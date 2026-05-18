from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import httpx
import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(name="mailaccess", help="MailAccess OSINT email intelligence CLI.")
# Use standard console for normal output, err_console for progress/errors when outputting JSON
console = Console()
err_console = Console(stderr=True)

CONFIG_FILE = Path.home() / ".mailaccess" / "config.json"


def get_backend_url() -> str:
    url = os.environ.get("MAILACCESS_URL")
    if url:
        return url.rstrip("/")
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
                url = data.get("url")
                if url:
                    return url.rstrip("/")
        except Exception:
            pass
    return "http://localhost:8000"


def set_backend_url(url: str) -> None:
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
        except Exception:
            pass
    data["url"] = url
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)


config_app = typer.Typer(name="config", help="Manage configuration")
app.add_typer(config_app)

@config_app.command(name="set-url")
def config_set_url(url: str = typer.Argument(..., help="Backend URL (e.g. http://localhost:8000)")) -> None:
    """Set the backend URL."""
    set_backend_url(url)
    console.print(f"[green]Backend URL set to:[/] {url}")


def get_risk_color(risk_level: str) -> str:
    risk_level = risk_level.lower()
    if risk_level == "low":
        return "green"
    elif risk_level == "medium":
        return "yellow"
    elif risk_level == "high":
        return "red"
    elif risk_level == "critical":
        return "bright_red"
    return "white"


def get_status_color(status: str) -> str:
    status = status.lower()
    if status in ("success", "complete"):
        return "green"
    elif status == "failed":
        return "red"
    elif status in ("pending", "running"):
        return "cyan"
    elif status == "partial":
        return "yellow"
    return "white"


async def _investigate(email: str, output_format: str, modules: str | None, timeout: int) -> None:
    base_url = get_backend_url()
    out = err_console if output_format == "json" else console
    
    payload = {"email": email}
    if modules:
        payload["modules"] = [m.strip() for m in modules.split(",") if m.strip()]

    async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as client:
        try:
            # 1. Start investigation
            resp = await client.post("/api/investigate", json=payload)
            resp.raise_for_status()
            data = resp.json()
            inv_id = data["id"]
        except httpx.ConnectError:
            out.print("[red]Error:[/] cannot connect to MailAccess server", style="bold red")
            raise typer.Exit(1)
        except httpx.HTTPStatusError as e:
            out.print(f"[red]Error starting investigation:[/] {e.response.text}", style="bold red")
            raise typer.Exit(1)
        except Exception as e:
            out.print(f"[red]Error:[/] {e}", style="bold red")
            raise typer.Exit(1)

        if output_format != "json":
            out.print(f"[bold cyan]Investigating:[/] {email} (ID: {inv_id})\n")

        # 2. Poll progress
        status = "pending"
        report_data: dict[str, Any] = {}
        
        # Build the live table generator
        def generate_progress_table(rep: dict[str, Any]) -> Table:
            table = Table(title="Module Progress", box=None)
            table.add_column("Module", style="cyan")
            table.add_column("Status", justify="right")
            
            runs = rep.get("module_runs", [])
            for run in runs:
                mod_name = run.get("module_name", "Unknown")
                mod_status = run.get("status", "unknown")
                color = get_status_color(mod_status)
                table.add_row(mod_name, f"[{color}]{mod_status.upper()}[/]")
            return table

        if output_format != "json":
            with Live(generate_progress_table({}), console=out, refresh_per_second=4) as live:
                while status not in ("complete", "failed"):
                    await asyncio.sleep(2)
                    try:
                        resp = await client.get(f"/api/report/{inv_id}")
                        resp.raise_for_status()
                        report_data = resp.json()
                        status = report_data.get("status", status)
                        live.update(generate_progress_table(report_data))
                    except Exception:
                        # Temporary errors during polling can be ignored
                        pass
        else:
            # Silent polling for json output
            while status not in ("complete", "failed"):
                await asyncio.sleep(2)
                try:
                    resp = await client.get(f"/api/report/{inv_id}")
                    resp.raise_for_status()
                    report_data = resp.json()
                    status = report_data.get("status", status)
                except Exception:
                    pass

        # 3. Final output
        if output_format == "json":
            console.print_json(json.dumps(report_data, indent=2))
            return

        out.print("\n[bold green]Investigation Complete[/]\n")

        # Summary Table
        summary_table = Table(title="Summary")
        summary_table.add_column("Exposure Score", justify="center")
        summary_table.add_column("Risk Level", justify="center")
        summary_table.add_column("Total Findings", justify="center")

        score = report_data.get("exposure_score")
        risk = report_data.get("risk_level", "unknown")
        findings_count = len(report_data.get("findings", []))

        score_str = str(score) if score is not None else "N/A"
        risk_color = get_risk_color(risk)
        
        summary_table.add_row(
            score_str,
            f"[{risk_color}]{risk.upper()}[/]",
            str(findings_count)
        )
        out.print(summary_table)
        out.print()

        # Findings Grouped by Module
        findings_by_module = report_data.get("findings_by_module", {})
        if not findings_by_module:
            out.print("[dim]No findings to display.[/]")
            return

        for module_name, findings in findings_by_module.items():
            content = ""
            for i, f in enumerate(findings, 1):
                # Try to format the finding nicely instead of pure json dumps
                finding_str = json.dumps(f, indent=2)
                content += f"[bold]{i}.[/] {finding_str}\n"
            
            panel = Panel(
                content.strip(),
                title=f"[cyan]{module_name}[/]",
                border_style="cyan"
            )
            out.print(panel)
            out.print()


@app.command()
def investigate(
    email: str = typer.Argument(..., help="Email address to investigate."),
    output: str = typer.Option(
        "table", "--format", "-f", help="Output format: table|json"
    ),
    modules: str = typer.Option(
        None, "--modules", "-m", help="Comma-separated list of modules to run."
    ),
    timeout: int = typer.Option(
        30, "--timeout", "-t", help="Timeout in seconds for API calls."
    ),
) -> None:
    """Run a full OSINT investigation against an email address."""
    asyncio.run(_investigate(email, output, modules, timeout))


@app.command()
def history(
    page: int = typer.Option(1, help="Page number"),
    page_size: int = typer.Option(20, help="Items per page"),
    timeout: int = typer.Option(10, help="Timeout in seconds")
) -> None:
    """List past investigations."""
    asyncio.run(_history(page, page_size, timeout))


async def _history(page: int, page_size: int, timeout: int) -> None:
    base_url = get_backend_url()
    async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as client:
        try:
            resp = await client.get("/api/investigations", params={"page": page, "page_size": page_size})
            resp.raise_for_status()
            data = resp.json()
        except httpx.ConnectError:
            console.print("[red]Error:[/] cannot connect to MailAccess server", style="bold red")
            raise typer.Exit(1)
        except Exception as e:
            console.print(f"[red]Error:[/] {e}", style="bold red")
            raise typer.Exit(1)

    table = Table(title=f"Past Investigations (Page {data['page']}/{data['pages']})")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Email")
    table.add_column("Status")
    table.add_column("Score", justify="right")
    table.add_column("Created At")

    for item in data.get("items", []):
        status = item.get("status", "unknown")
        color = get_status_color(status)
        score = item.get("exposure_score")
        score_str = str(score) if score is not None else "-"
        table.add_row(
            item.get("id"),
            item.get("email"),
            f"[{color}]{status}[/]",
            score_str,
            item.get("created_at")
        )
    
    console.print(table)


if __name__ == "__main__":
    app()
