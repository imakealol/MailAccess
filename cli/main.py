from __future__ import annotations

import asyncio
import contextlib
import json
import os
from pathlib import Path
from typing import Any, Optional

import httpx
import typer
from dotenv import load_dotenv, set_key, unset_key
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

# Auto-load ~/.mailaccess/.env before reading system env
_ENV_FILE = Path.home() / ".mailaccess" / ".env"
if _ENV_FILE.exists():
    load_dotenv(_ENV_FILE, override=False)

BANNER = """\
[bold red]
███╗   ███╗ █████╗ ██╗██╗      █████╗  ██████╗ ██████╗███████╗███████╗
████╗ ████║██╔══██╗██║██║     ██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝
██╔████╔██║███████║██║██║     ███████║██║     ██║     █████╗  ███████╗
██║╚██╔╝██║██╔══██║██║██║     ██╔══██║██║     ██║     ██╔══╝  ╚════██║
██║ ╚═╝ ██║██║  ██║██║███████╗██║  ██║╚██████╗╚██████╗███████╗███████║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝╚══════╝
[/bold red]
[dim]Open-source OSINT email intelligence tool[/dim]
[dim]v0.2.0 · pypi.org/project/mailaccess[/dim]"""

app = typer.Typer(name="mailaccess", help="MailAccess OSINT email intelligence CLI.")
console = Console()
err_console = Console(stderr=True)

CONFIG_FILE = Path.home() / ".mailaccess" / "config.json"
ENV_FILE = Path.home() / ".mailaccess" / ".env"

_API_KEYS: list[tuple[str, str, str]] = [
    ("HIBP_API_KEY",        "hibp",          "haveibeenpwned.com/API"),
    ("SERPAPI_KEY",         "google_dork",   "serpapi.com"),
    ("SHODAN_API_KEY",      "domain_intel",  "shodan.io"),
    ("EMAILREP_API_KEY",    "emailrep",      "emailrep.io"),
    ("HUNTER_IO_API_KEY",   "hunter_io",     "hunter.io"),
    ("SLACK_WEBHOOK_URL",   "notifications", "Slack app webhooks"),
    ("DISCORD_WEBHOOK_URL", "notifications", "Discord server webhooks"),
]

_EXPORT_FORMATS = {".json", ".csv", ".md", ".pdf", ".stix", ".mtgx"}

_HARDCODED_MODULES = [
    ("haveibeenpwned", "HIBP",      "HIBP_API_KEY",      "No", "Check email against known breach databases"),
    ("hunter_io",      "Hunter.io", "HUNTER_IO_API_KEY", "No", "Find associated domain email patterns"),
    ("emailrep",       "EmailRep",  "EMAILREP_API_KEY",  "No", "Email reputation and metadata lookup"),
    ("gravatar",       "Gravatar",  "—",                 "No", "Retrieve profile photo via Gravatar"),
    ("google_dork",    "Google",    "SERPAPI_KEY",        "No", "Run targeted dork queries via SerpAPI"),
    ("google_search",  "Google",    "—",                 "No", "General Google search for email mentions"),
    ("shodan",         "Shodan",    "SHODAN_API_KEY",    "No", "IP/domain intelligence via Shodan"),
    ("dns_lookup",     "DNS",       "—",                 "No", "DNS record enumeration for email domain"),
    ("whois_lookup",   "WHOIS",     "—",                 "No", "WHOIS registration data for email domain"),
    ("social_links",   "Multi",     "—",                 "No", "Check email on social platforms"),
    ("domain_intel",   "Multi",     "SHODAN_API_KEY",    "No", "Domain intelligence and infrastructure recon"),
]


# ── Global callback (banner) ──────────────────────────────────────────────────

@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the ASCII banner (for CI/scripting)"),
) -> None:
    if not no_banner:
        err_console.print(BANNER)
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


# ── Config ────────────────────────────────────────────────────────────────────

def get_backend_url() -> str:
    url = os.environ.get("MAILACCESS_URL")
    if url:
        return url.rstrip("/")
    if CONFIG_FILE.exists():
        with contextlib.suppress(Exception):
            with open(CONFIG_FILE) as f:
                data = json.load(f)
                url = data.get("url")
                if url:
                    return url.rstrip("/")
    return "http://localhost:8000"


def set_backend_url(url: str) -> None:
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {}
    if CONFIG_FILE.exists():
        with contextlib.suppress(Exception):
            with open(CONFIG_FILE) as f:
                data = json.load(f)
    data["url"] = url
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)


config_app = typer.Typer(name="config", help="Manage configuration")
app.add_typer(config_app)


@config_app.command(name="set-url")
def config_set_url(
    url: str = typer.Argument(..., help="Backend URL (e.g. http://localhost:8000)"),
) -> None:
    """Set the backend URL."""
    set_backend_url(url)
    console.print(f"[green]Backend URL set to:[/] {url}")


# ── Keys ──────────────────────────────────────────────────────────────────────

keys_app = typer.Typer(name="keys", help="Manage API keys stored in ~/.mailaccess/.env")
app.add_typer(keys_app)


@keys_app.command(name="list")
def keys_list() -> None:
    """Show all supported API keys and their current status."""
    table = Table(title="API Keys")
    table.add_column("Key Name", style="cyan")
    table.add_column("Required For")
    table.add_column("Service")
    table.add_column("Status", justify="center")

    for key_name, module, service in _API_KEYS:
        value = os.environ.get(key_name)
        status = "[green]SET[/green]" if value else "[red]NOT SET[/red]"
        table.add_row(key_name, module, service, status)

    console.print(table)


@keys_app.command(name="set")
def keys_set(
    key_name: str = typer.Argument(..., help="API key name (e.g. HIBP_API_KEY)"),
    value: str = typer.Argument(..., help="The key value to store"),
) -> None:
    """Save an API key to ~/.mailaccess/.env."""
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not ENV_FILE.exists():
        ENV_FILE.touch()
    set_key(str(ENV_FILE), key_name, value)
    console.print(f"[green]✓ {key_name} saved to ~/.mailaccess/.env[/green]")
    console.print("[dim]Restart MailAccess server for changes to take effect[/dim]")


@keys_app.command(name="unset")
def keys_unset(
    key_name: str = typer.Argument(..., help="API key name to remove"),
) -> None:
    """Remove an API key from ~/.mailaccess/.env."""
    if not ENV_FILE.exists():
        console.print("[yellow]~/.mailaccess/.env not found — nothing to remove.[/yellow]")
        return
    removed, _ = unset_key(str(ENV_FILE), key_name)
    if removed:
        console.print(f"[green]✓ {key_name} removed from ~/.mailaccess/.env[/green]")
    else:
        console.print(f"[yellow]{key_name} was not found in ~/.mailaccess/.env[/yellow]")


# ── Commands overview ─────────────────────────────────────────────────────────

@app.command(name="commands")
def commands_overview() -> None:
    """Show all available commands with descriptions."""
    content = (
        "  [cyan]investigate <email>[/cyan]   Run full OSINT on an email address\n"
        "  [cyan]history[/cyan]               View past investigations\n"
        "  [cyan]keys list[/cyan]             Show API key status\n"
        "  [cyan]keys set <k> <v>[/cyan]      Save an API key to ~/.mailaccess/.env\n"
        "  [cyan]keys unset <k>[/cyan]        Remove an API key\n"
        "  [cyan]config set-url <url>[/cyan]  Set backend server URL\n"
        "  [cyan]modules[/cyan]               List available investigation modules\n"
        "  [cyan]commands[/cyan]              Show this help panel"
    )
    console.print(Panel(content, title="MailAccess Commands", border_style="cyan"))


# ── Modules ───────────────────────────────────────────────────────────────────

@app.command(name="modules")
def modules_list(
    timeout: int = typer.Option(5, help="Timeout in seconds when contacting server"),
) -> None:
    """List all available investigation modules."""
    server_modules: list[str] | None = None
    with contextlib.suppress(Exception):
        resp = httpx.get(f"{get_backend_url()}/health", timeout=timeout)
        if resp.status_code == 200:
            server_modules = resp.json().get("modules_loaded")

    table = Table(title="Available Modules")
    table.add_column("Module", style="cyan")
    table.add_column("Platforms")
    table.add_column("Requires Key")
    table.add_column("Opt-in")
    table.add_column("Description")

    for name, platform, key_req, opt_in, desc in _HARDCODED_MODULES:
        label = name
        if server_modules is not None:
            label += " [green]●[/green]" if name in server_modules else " [dim]○[/dim]"
        table.add_row(label, platform, key_req, opt_in, desc)

    console.print(table)
    if server_modules is None:
        console.print("[dim]Could not reach server — showing hardcoded module list.[/dim]")


# ── Helpers ───────────────────────────────────────────────────────────────────

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


# ── Investigate ───────────────────────────────────────────────────────────────

async def _investigate(
    email: str,
    output_format: str,
    modules: str | None,
    timeout: int,
    output_file: str | None,
) -> None:
    base_url = get_backend_url()
    out = err_console if output_format == "json" else console

    payload: dict[str, Any] = {"email": email}
    if modules:
        payload["modules"] = [m.strip() for m in modules.split(",") if m.strip()]

    async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as client:
        try:
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

        status = "pending"
        report_data: dict[str, Any] = {}

        def generate_progress_table(rep: dict[str, Any]) -> Table:
            table = Table(title="Module Progress", box=None)
            table.add_column("Module", style="cyan")
            table.add_column("Status", justify="right")
            for run in rep.get("module_runs", []):
                mod_name = run.get("module_name", "Unknown")
                mod_status = run.get("status", "unknown")
                color = get_status_color(mod_status)
                table.add_row(mod_name, f"[{color}]{mod_status.upper()}[/]")
            return table

        if output_format != "json":
            with Live(generate_progress_table({}), console=out, refresh_per_second=4) as live:
                while status not in ("complete", "failed"):
                    await asyncio.sleep(2)
                    with contextlib.suppress(Exception):
                        resp = await client.get(f"/api/report/{inv_id}")
                        resp.raise_for_status()
                        report_data = resp.json()
                        status = report_data.get("status", status)
                        live.update(generate_progress_table(report_data))
        else:
            while status not in ("complete", "failed"):
                await asyncio.sleep(2)
                with contextlib.suppress(Exception):
                    resp = await client.get(f"/api/report/{inv_id}")
                    resp.raise_for_status()
                    report_data = resp.json()
                    status = report_data.get("status", status)

        # Export to file if requested
        if output_file:
            ext = Path(output_file).suffix.lower()
            if ext not in _EXPORT_FORMATS:
                out.print(f"[red]Unsupported extension:[/] {ext}. Supported: {', '.join(sorted(_EXPORT_FORMATS))}")
            else:
                fmt = ext.lstrip(".")
                try:
                    export_resp = await client.get(
                        f"/api/report/{inv_id}/export",
                        params={"format": fmt},
                    )
                    export_resp.raise_for_status()
                    Path(output_file).write_bytes(export_resp.content)
                    out.print(f"[green]✓ Report saved to {output_file}[/green]")
                except Exception as e:
                    out.print(f"[red]Failed to save report:[/] {e}")

        # Final stdout output
        if output_format == "json":
            console.print_json(json.dumps(report_data, indent=2))
            return

        out.print("\n[bold green]Investigation Complete[/]\n")

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
            str(findings_count),
        )
        out.print(summary_table)
        out.print()

        findings_by_module = report_data.get("findings_by_module", {})
        if not findings_by_module:
            out.print("[dim]No findings to display.[/]")
            return

        for module_name, findings in findings_by_module.items():
            content = ""
            for i, f in enumerate(findings, 1):
                finding_str = json.dumps(f, indent=2)
                content += f"[bold]{i}.[/] {finding_str}\n"
            out.print(Panel(content.strip(), title=f"[cyan]{module_name}[/]", border_style="cyan"))
            out.print()


@app.command()
def investigate(
    email: str = typer.Argument(..., help="Email address to investigate."),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table|json"
    ),
    modules: str = typer.Option(
        None, "--modules", "-m", help="Comma-separated list of modules to run."
    ),
    timeout: int = typer.Option(
        30, "--timeout", "-t", help="Timeout in seconds for API calls."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save report to file (.json .csv .md .pdf .stix .mtgx)"
    ),
) -> None:
    """Run a full OSINT investigation against an email address."""
    asyncio.run(_investigate(email, output_format, modules, timeout, output_file))


# ── History ───────────────────────────────────────────────────────────────────

@app.command()
def history(
    page: int = typer.Option(1, help="Page number"),
    page_size: int = typer.Option(20, help="Items per page"),
    timeout: int = typer.Option(10, help="Timeout in seconds"),
) -> None:
    """List past investigations."""
    asyncio.run(_history(page, page_size, timeout))


async def _history(page: int, page_size: int, timeout: int) -> None:
    base_url = get_backend_url()
    async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as client:
        try:
            resp = await client.get(
                "/api/investigations", params={"page": page, "page_size": page_size}
            )
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
            item.get("created_at"),
        )

    console.print(table)


if __name__ == "__main__":
    app()
