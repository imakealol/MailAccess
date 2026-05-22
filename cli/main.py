from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Force UTF-8 on stdout/stderr so Rich glyphs (✓, box-drawing, etc.) don't
# crash on legacy Windows code pages (cp1252).
if sys.platform == "win32":
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

import logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("mailaccess").setLevel(logging.WARNING)

import httpx
import websockets
import typer
from dotenv import load_dotenv, set_key, unset_key
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# Auto-load ~/.mailaccess/.env before reading system env
_ENV_FILE = Path.home() / ".mailaccess" / ".env"
if _ENV_FILE.exists():
    load_dotenv(_ENV_FILE, override=False)

from importlib.metadata import version as pkg_version
try:
    _VERSION = pkg_version("mailaccess")
except Exception:
    _VERSION = "dev"

BANNER = f"""\
[bold red]
███╗   ███╗ █████╗ ██╗██╗      █████╗  ██████╗ ██████╗███████╗███████╗███████╗
████╗ ████║██╔══██╗██║██║     ██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝
██╔████╔██║███████║██║██║     ███████║██║     ██║     █████╗  ███████╗███████╗
██║╚██╔╝██║██╔══██║██║██║     ██╔══██║██║     ██║     ██╔══╝  ╚════██║╚════██║
██║ ╚═╝ ██║██║  ██║██║███████╗██║  ██║╚██████╗╚██████╗███████╗███████║███████║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝
[/bold red]
[dim]Open-source OSINT email intelligence tool[/dim]
[dim]v{_VERSION} · pypi.org/project/mailaccess[/dim]"""

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
    import sys
    if sys.stderr.isatty() and not no_banner:
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


config_app = typer.Typer(name="config", help="Manage configuration", invoke_without_command=True, no_args_is_help=True)
app.add_typer(config_app)


@config_app.callback(invoke_without_command=True)
def config_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


@config_app.command(name="set-url")
def config_set_url(
    url: str = typer.Argument(..., help="Backend URL (e.g. http://localhost:8000)"),
) -> None:
    """Set the backend URL."""
    set_backend_url(url)
    console.print(f"[green]Backend URL set to:[/] {url}")


# ── Keys ──────────────────────────────────────────────────────────────────────

keys_app = typer.Typer(name="keys", help="Manage API keys stored in ~/.mailaccess/.env", invoke_without_command=True, no_args_is_help=True)
app.add_typer(keys_app)


@keys_app.callback(invoke_without_command=True)
def keys_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


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
        "  [cyan]serve[/cyan]                 Start the backend server locally\n"
        "  [cyan]history[/cyan]               View past investigations\n"
        "  [cyan]keys list[/cyan]             Show API key status\n"
        "  [cyan]keys set <k> <v>[/cyan]      Save an API key to ~/.mailaccess/.env\n"
        "  [cyan]keys unset <k>[/cyan]        Remove an API key\n"
        "  [cyan]config set-url <url>[/cyan]  Set backend server URL\n"
        "  [cyan]modules[/cyan]               List available investigation modules\n"
        "  [cyan]commands[/cyan]              Show this help panel"
    )
    console.print(Panel(content, title="MailAccess Commands", border_style="cyan"))


@app.command(name="serve")
def serve_command(
    host: str = typer.Option("127.0.0.1", "--host", help="Host IP to bind to"),
    port: int = typer.Option(8000, "--port", help="Port to bind to"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (dev mode)"),
) -> None:
    """Start the MailAccess backend server."""
    import asyncio
    import uvicorn
    from backend.db.database import init_db

    asyncio.run(init_db())

    err_console.print("[green]Starting MailAccess server...[/green]")
    err_console.print(f"[dim]Listening on http://{host}:{port}[/dim]")
    err_console.print("[dim]Press Ctrl+C to stop[/dim]")

    uvicorn.run(
        "backend.main:app",
        host=host,
        port=port,
        reload=reload
    )


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


def _normalize_module_name(name: str) -> str:
    return name.replace("_", " ").upper()


def _short_id(inv_id: str, length: int = 8) -> str:
    return inv_id[:length]


def _display_url(value: str, max_len: int = 50) -> str:
    cleaned = value.strip()
    for prefix in ("https://", "http://"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
            break
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    if len(cleaned) <= max_len:
        return cleaned
    return f"{cleaned[: max_len - 3]}..."


def _score_color(score: int | None) -> str:
    if score is None:
        return "white"
    if score <= 15:
        return "green"
    if score <= 35:
        return "yellow"
    if score <= 65:
        return "dark_orange"
    return "red"


def _extract_finding_line(finding: dict[str, Any], default_name: str) -> tuple[str, str]:
    platform = (
        finding.get("platform")
        or finding.get("service")
        or finding.get("source")
        or finding.get("site")
        or default_name
    )
    url_like = (
        finding.get("url")
        or finding.get("profile_url")
        or finding.get("link")
        or finding.get("domain")
        or finding.get("website")
        or ""
    )
    if not url_like:
        display_name = finding.get("display_name")
        username = finding.get("username")
        breach_name = finding.get("breach_name")
        severity = finding.get("severity")
        extra = next(
            (v for v in (display_name, username, breach_name, severity) if isinstance(v, str) and v.strip()),
            "",
        )
        url_like = extra
    return str(platform), _display_url(str(url_like)) if url_like else ""


def _format_duration(run: dict[str, Any]) -> str:
    duration = run.get("duration_seconds")
    if isinstance(duration, (int, float)):
        return f"{duration:.1f}s"
    started = run.get("started_at")
    finished = run.get("completed_at") or run.get("finished_at")
    if isinstance(started, str) and isinstance(finished, str):
        try:
            start_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(finished.replace("Z", "+00:00"))
            return f"{max((end_dt - start_dt).total_seconds(), 0):.1f}s"
        except ValueError:
            return "—"
    return "..."


# ── Investigate ───────────────────────────────────────────────────────────────

async def _investigate(
    email: str,
    output_format: str,
    modules: str | None,
    timeout: int,
    output_file: str | None,
    force: bool = False,
    show_collisions: bool = False,
) -> int:
    base_url = get_backend_url()
    out = err_console if output_format in ("json", "jsonl") else console

    payload: dict[str, Any] = {"email": email}
    if modules:
        payload["modules"] = [m.strip() for m in modules.split(",") if m.strip()]
    if force:
        payload["force"] = True

    try:
        async with httpx.AsyncClient() as check_client:
            await check_client.get(f"{base_url}/health", timeout=3.0)
    except Exception:
        err_console.print(f"[yellow]No backend found at {base_url}[/yellow]")
        err_console.print("[dim]Starting embedded server...[/dim]")
        
        import threading
        import uvicorn
        from backend.db.database import init_db
        await init_db()

        server_thread = threading.Thread(
            target=uvicorn.run,
            args=("backend.main:app",),
            kwargs={"host": "127.0.0.1", "port": 8000, "log_level": "error"},
            daemon=True
        )
        server_thread.start()
        
        server_ready = False
        for _ in range(30):
            await asyncio.sleep(0.5)
            err_console.print(".", end="", style="dim")
            try:
                async with httpx.AsyncClient() as check_client:
                    resp = await check_client.get(f"{base_url}/health", timeout=1.0)
                    if resp.status_code == 200:
                        server_ready = True
                        break
            except Exception:
                pass
        err_console.print()
        if not server_ready:
            err_console.print("[red]Error:[/] Server failed to start within 15 seconds")
            return 3
        err_console.print("[dim]Server started. Will stop when investigation completes.[/dim]")

    async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as client:
        err_console.print(f"[dim]Backend: {base_url}[/dim]")
        try:
            resp = await client.post("/api/investigate", json=payload)
            resp.raise_for_status()
            data = resp.json()
            inv_id = data["id"]
            cached = bool(data.get("cached"))
        except httpx.ConnectError:
            out.print("[red]Error:[/] cannot connect to MailAccess server", style="bold red")
            return 3
        except httpx.HTTPStatusError as e:
            out.print(f"[red]Error starting investigation:[/] {e.response.text}", style="bold red")
            return 3
        except Exception as e:
            out.print(f"[red]Error:[/] {e}", style="bold red")
            return 3

        if output_format == "jsonl":
            sys.stdout.write(json.dumps({"type": "start", "email": email, "id": inv_id}) + "\n")
            sys.stdout.flush()

        if output_format not in ("json", "jsonl"):
            started_time = datetime.now().strftime("%H:%M:%S")
            header = Text()
            header.append("🔍  ", style="bold")
            header.append(email, style="bold cyan")
            header.append("\n")
            header.append(
                f"ID: {_short_id(inv_id)} · Started: {started_time}",
                style="dim",
            )
            out.print(Rule(style="dim"))
            out.print(header)
            out.print(Rule(style="dim"))

        if cached and output_format not in ("json", "jsonl"):
            try:
                created_dt = datetime.fromisoformat(data["created_at"])
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
                age_min = int(
                    (datetime.now(timezone.utc) - created_dt).total_seconds() // 60
                )
                out.print(
                    f"[dim]Using recent result from {age_min} minute{'s' if age_min != 1 else ''} ago "
                    f"(pass --force to re-run)[/dim]\n"
                )
            except Exception:
                out.print("[dim]Using recent cached result (pass --force to re-run)[/dim]\n")

        status = "complete" if cached else "pending"
        report_data: dict[str, Any] = {}

        def _get_score(rep: dict[str, Any]) -> int | float | None:
            score = rep.get("exposure_score")
            if score is None:
                summary = rep.get("summary")
                if isinstance(summary, dict):
                    score = summary.get("exposure_score")
            if isinstance(score, (int, float)):
                return score
            return None

        def _get_risk(rep: dict[str, Any]) -> str:
            risk = rep.get("risk_level")
            if risk is None:
                summary = rep.get("summary")
                if isinstance(summary, dict):
                    risk = summary.get("risk_level")
            return str(risk) if risk is not None else "unknown"

        _progress_table = Table(title="Module Progress", box=None)

        def update_progress_table(rep: dict[str, Any]) -> Table:
            _progress_table.columns.clear()
            _progress_table.add_column("Module", style="cyan")
            _progress_table.add_column("Status", justify="right")
            _progress_table.add_column("Time", justify="right", style="dim")
            for run in rep.get("module_runs", []):
                mod_name = run.get("module_name", "Unknown")
                mod_status = run.get("status", "unknown")
                color = get_status_color(mod_status)
                duration = _format_duration(run)
                _progress_table.add_row(mod_name, f"[{color}]{mod_status.upper()}[/]", duration)
            return _progress_table

        def render_summary(rep: dict[str, Any]) -> None:
            score = _get_score(rep)
            risk = _get_risk(rep)
            findings_count = len(rep.get("findings", []))
            
            module_runs = rep.get("module_runs", [])
            total_modules = len(module_runs)
            skipped_count = sum(1 for r in module_runs if str(r.get("status", "")).lower() == "skipped")
            ran_modules = total_modules - skipped_count
            
            score_val = str(score) if score is not None else "N/A"
            if score is not None:
                score_val = f"{score}/100"
            score_str = f"{score_val} ({ran_modules}/{total_modules} modules)"
            
            risk_color = get_risk_color(risk)
            score_color = _score_color(score if isinstance(score, int) else None)
            summary = (
                f" [bold]Score:[/] [{score_color}]{score_str}[/]  │  "
                f"[bold]Risk:[/] [{risk_color}]{risk.upper()}[/]  │  "
                f"[bold]Hits:[/] {findings_count} "
            )
            out.print(Panel(summary, border_style=score_color))
            if skipped_count > 3:
                out.print(f"[dim]{skipped_count} modules skipped — set API keys to improve coverage. Run: mailaccess keys list[/dim]")
            out.print()

        def render_findings(rep: dict[str, Any]) -> None:
            findings_by_module = rep.get("findings_by_module", {})
            if findings_by_module:
                for module_name, findings in findings_by_module.items():
                    out.print(Rule(f"{_normalize_module_name(module_name)}  ({len(findings)} hits)", style="cyan"))
                    for finding in findings:
                        if not isinstance(finding, dict):
                            continue
                        confidence = str(finding.get("confidence", "")).lower()
                        severity = str(finding.get("severity", "")).lower()
                        symbol = "✓"
                        style = "green"
                        if confidence == "low":
                            symbol = "~"
                            style = "dim"
                        if severity == "critical":
                            symbol = "⚠"
                            style = "red"
                        platform, detail = _extract_finding_line(finding, module_name)
                        meta = finding.get("metadata", {})
                        if "common_variations" in meta:
                            detail = "→ " + ", ".join(meta["common_variations"])

                        if module_name in ("account_discovery", "user_scanner") or str(finding.get("source", "")) in ("account_discovery", "user_scanner"):
                            platform = platform.title()
                            detail_text = "[dim][email registration confirmed][/dim]"
                        elif module_name == "dns_lookup":
                            pt = str(finding.get("platform", ""))
                            if pt == "dns_mx" and meta.get("mx_provider"):
                                detail_text = f"MX: {meta.get('mx_provider')}"
                            elif pt == "dns_spf" and meta.get("spf_record"):
                                detail_text = f"SPF: {str(meta.get('spf_record'))[:40]}"
                            elif pt == "dns_dmarc" and meta.get("dmarc_policy"):
                                detail_text = f"DMARC: {meta.get('dmarc_policy')}"
                            elif pt == "dns_a" and meta.get("ip_address"):
                                detail_text = f"A: {meta.get('ip_address')}"
                            elif pt == "dns_ns" and meta.get("nameservers"):
                                ns = meta.get("nameservers")
                                ns_val = ns[0] if isinstance(ns, list) and ns else ns
                                detail_text = f"NS: {ns_val}"
                            elif pt == "dns_dkim" and meta.get("selector"):
                                detail_text = f"DKIM: selector={meta.get('selector')}"
                            else:
                                detail_text = "record found"
                        else:
                            detail_text = detail if detail else "account found"
                        
                        platform_label = f"{platform[:20]:<20}"
                        out.print(f"  [{style}]{symbol}[/{style}] {platform_label} {detail_text}")
                        metadata = []
                        for key in ("display_name", "username", "breach_name", "severity"):
                            value = finding.get(key)
                            if value:
                                metadata.append(f"{key}: {value}")
                        if confidence == "low":
                            metadata.append("low confidence")
                        if metadata:
                            out.print(f"    [dim][{' · '.join(metadata)}][/dim]")
                    out.print()
            else:
                out.print("[dim]No findings to display.[/]")

        def render_skipped(rep: dict[str, Any]) -> None:
            module_runs = rep.get("module_runs", [])
            skipped_runs = [r for r in module_runs if str(r.get("status", "")).lower() == "skipped"]
            
            groups = {
                "BREACH SOURCES": ["hibp", "haveibeenpwned", "breachdirectory", "hudson_rock"],
                "RECON MODULES": ["dns_lookup", "whois_lookup", "domain_intel", "google_dork", "shodan", "hunter_io"],
                "OPTIONAL MODULES": ["ghunt", "user_scanner", "account_discovery", "whatsmyname", "username_pivot", "permutation_discovery", "phone_intel"]
            }
            
            key_hints = {
                "hibp": "set HIBP_API_KEY",
                "haveibeenpwned": "set HIBP_API_KEY",
                "google_dork": "set SERPAPI_KEY",
                "shodan": "set SHODAN_API_KEY",
                "domain_intel": "set SHODAN_API_KEY",
                "hunter_io": "set HUNTER_IO_API_KEY",
                "emailrep": "set EMAILREP_API_KEY",
                "ghunt": "run mailaccess keys set GHUNT_CREDS_PATH /path/to/creds"
            }

            for group_name, mods in groups.items():
                group_skipped = [r for r in skipped_runs if r.get("module_name", "unknown") in mods]
                if group_skipped:
                    out.print(Rule(group_name, style="dim"))
                    for run in group_skipped:
                        m_name = run.get("module_name", "unknown")
                        errors = run.get("errors") or []
                        hint = str(errors[0]) if errors else key_hints.get(m_name, "see docs")
                        if "api key" in str(run.get("error", "")).lower() or "api key" in hint.lower():
                            hint = key_hints.get(m_name, "missing api key")
                        if m_name == "whois_lookup" and "free provider" in hint.lower():
                            hint = "free email provider"
                        if len(hint) > 50:
                            hint = hint[:47] + "..."
                        out.print(f"  [dim]— {_normalize_module_name(m_name)}: skipped ({hint})[/dim]")
                    out.print()

            other_skipped = [r for r in skipped_runs if not any(r.get("module_name", "unknown") in g for g in groups.values())]
            if other_skipped:
                out.print(Rule("OTHER MODULES", style="dim"))
                for run in other_skipped:
                    m_name = run.get("module_name", "unknown")
                    errors = run.get("errors") or []
                    hint = str(errors[0]) if errors else key_hints.get(m_name, "see docs")
                    if "api key" in str(run.get("error", "")).lower() or "api key" in hint.lower():
                        hint = key_hints.get(m_name, "missing api key")
                    if m_name == "whois_lookup" and "free provider" in hint.lower():
                        hint = "free email provider"
                    if len(hint) > 50:
                        hint = hint[:47] + "..."
                    out.print(f"  [dim]— {_normalize_module_name(m_name)}: skipped ({hint})[/dim]")
                out.print()

            out.print("[dim]Legend: ✓ confirmed  ~ low confidence  — skipped[/dim]")
            out.print(f"[dim]💾 Save report: mailaccess investigate {email} -o report.pdf[/dim]")

        if cached:
            try:
                resp = await client.get(f"/api/report/{inv_id}", timeout=30)
                resp.raise_for_status()
                report_data = resp.json()
                status = report_data.get("status", status)
            except Exception:
                # Fallback to normal polling if immediate report fetch fails.
                status = "pending"

        _MAX_POLL_ATTEMPTS = 60  # 60 × 2 s = 120 s hard timeout

        if output_format not in ("json", "jsonl") and not cached:
            ws_base = base_url.replace("https://", "wss://").replace("http://", "ws://")
            ws_url = f"{ws_base}/ws/investigate/{inv_id}"
            err_console.print(f"[dim]Connecting: {ws_url}[/dim]")
            _ws_modules: dict[str, dict[str, Any]] = {}
            _live = None
            if output_format != "jsonl":
                _live = Live(_progress_table, console=out, refresh_per_second=4)
                _live.start()
                _live.update(update_progress_table({}))
            try:
                try:
                    async with websockets.connect(ws_url, open_timeout=10) as ws:
                        _deadline = asyncio.get_running_loop().time() + 360
                        while True:
                            remaining = _deadline - asyncio.get_running_loop().time()
                            if remaining <= 0:
                                err_console.print("[yellow]WS deadline reached (360 s), falling back to polling[/yellow]")
                                break
                            try:
                                raw = await asyncio.wait_for(ws.recv(), timeout=min(remaining, 150))
                            except asyncio.TimeoutError:
                                err_console.print("[yellow]WS receive timed out (150 s), falling back to polling[/yellow]")
                                break
                            event = json.loads(raw)
                            ev_type = event.get("type")
                            if ev_type == "module_start":
                                mod = event.get("module", "unknown")
                                _ws_modules[mod] = {"module_name": mod, "status": "running", "started_at": event.get("timestamp")}
                            elif ev_type in ("module_result", "module_error"):
                                mod = event.get("module", "unknown")
                                if mod not in _ws_modules:
                                    _ws_modules[mod] = {"module_name": mod}
                                _ws_modules[mod]["status"] = event.get("status", "complete")
                                _ws_modules[mod]["completed_at"] = datetime.now(timezone.utc).isoformat()
                                if output_format == "jsonl" and event.get("findings"):
                                    for f in event["findings"]:
                                        if not isinstance(f, dict): continue
                                        finding_obj = {
                                            "email": email,
                                            "investigation_id": inv_id,
                                            "module": mod,
                                            "platform": str(f.get("platform") or f.get("service") or f.get("source") or f.get("site") or mod),
                                            "profile_url": str(f.get("url") or f.get("profile_url") or f.get("link") or ""),
                                            "confidence": f.get("confidence", "unknown"),
                                            "severity": f.get("severity", "info"),
                                            "metadata": {k: v for k, v in f.items() if k not in ("platform", "service", "source", "site", "url", "profile_url", "link", "confidence", "severity")},
                                            "timestamp": datetime.now(timezone.utc).isoformat()
                                        }
                                        sys.stdout.write(json.dumps(finding_obj) + "\n")
                                    sys.stdout.flush()
                            elif ev_type == "investigation_complete":
                                status = "complete"
                            if _ws_modules and _live:
                                _live.update(update_progress_table({"module_runs": list(_ws_modules.values())}))
                            if status == "complete":
                                with contextlib.suppress(Exception):
                                    resp = await client.get(f"/api/report/{inv_id}", timeout=30)
                                    resp.raise_for_status()
                                    report_data = resp.json()
                                break
                except Exception as _ws_exc:
                    err_console.print(f"[yellow]WS unavailable, falling back to polling ({_ws_exc})[/yellow]")
                    err_console.print(f"[dim]Tried: {ws_url}[/dim]")
                    err_console.print("[dim]Is the backend running?[/dim]")
                if status not in ("complete", "failed"):
                    _attempts = 0
                    while status not in ("complete", "failed"):
                        if _attempts >= _MAX_POLL_ATTEMPTS:
                            err_console.print("[red]Timed out waiting for investigation to complete (120 s)[/red]")
                            return 3
                        await asyncio.sleep(2)
                        _attempts += 1
                        with contextlib.suppress(Exception):
                            resp = await client.get(f"/api/report/{inv_id}")
                            resp.raise_for_status()
                            report_data = resp.json()
                            status = report_data.get("status", status)
                            if _live:
                                _live.update(update_progress_table(report_data))
            finally:
                if _live:
                    _live.stop()
        else:
            _attempts = 0
            while status not in ("complete", "failed"):
                if _attempts >= _MAX_POLL_ATTEMPTS:
                    err_console.print("[red]Timed out waiting for investigation to complete (120 s)[/red]")
                    return 3
                await asyncio.sleep(2)
                _attempts += 1
                with contextlib.suppress(Exception):
                    resp = await client.get(f"/api/report/{inv_id}")
                    resp.raise_for_status()
                    report_data = resp.json()
                    status = report_data.get("status", status)

        if output_format not in ("json", "jsonl") and cached:
            module_runs = report_data.get("module_runs", [])
            statuses = [
                f"{run.get('module_name', 'unknown')}:{str(run.get('status', 'unknown')).upper()}"
                for run in module_runs
            ]
            if statuses:
                out.print(f"[dim]Modules: {', '.join(statuses)}[/dim]")

        if not report_data:
            try:
                resp = await client.get(f"/api/report/{inv_id}", timeout=30)
                resp.raise_for_status()
                report_data = resp.json()
            except Exception as _e:
                out.print(f"[red]Error:[/] Could not fetch report: {_e}")
                return 3
        if not report_data:
            out.print("[red]Error:[/] Report is empty — investigation may have failed.")
            return 3

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

        # Determine exit code
        findings_count = len(report_data.get("findings", []))
        breaches_found = False
        for f in report_data.get("findings", []):
            if isinstance(f, dict):
                src = str(f.get("source", "")).lower()
                plat = str(f.get("platform", "")).lower()
                mod = str(f.get("module_name", "")).lower()
                if "hibp" in (src, plat, mod) or "breachdirectory" in (src, plat, mod) or "hudson_rock" in (src, plat, mod) or "haveibeenpwned" in (src, plat, mod):
                    breaches_found = True
                    break
        
        exit_code = 0
        if breaches_found:
            exit_code = 2
        elif findings_count > 0:
            exit_code = 1

        if output_format == "jsonl":
            if cached:
                # If cached, WS didn't stream, so stream from report now
                for mod, findings in report_data.get("findings_by_module", {}).items():
                    for f in findings:
                        if not isinstance(f, dict): continue
                        finding_obj = {
                            "email": email,
                            "investigation_id": inv_id,
                            "module": mod,
                            "platform": str(f.get("platform") or f.get("service") or f.get("source") or f.get("site") or mod),
                            "profile_url": str(f.get("url") or f.get("profile_url") or f.get("link") or ""),
                            "confidence": f.get("confidence", "unknown"),
                            "severity": f.get("severity", "info"),
                            "metadata": {k: v for k, v in f.items() if k not in ("platform", "service", "source", "site", "url", "profile_url", "link", "confidence", "severity")},
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                        sys.stdout.write(json.dumps(finding_obj) + "\n")
            score = _get_score(report_data)
            risk = _get_risk(report_data)
            sys.stdout.write(json.dumps({
                "type": "complete",
                "email": email,
                "score": score,
                "risk": risk,
                "total_findings": findings_count
            }) + "\n")
            sys.stdout.flush()
            return exit_code

        if output_format == "json":
            console.print_json(json.dumps(report_data, indent=2))
            return exit_code

        async def render_clusters_output() -> None:
            try:
                resp = await client.get(f"/api/report/{inv_id}/clusters", timeout=10)
                resp.raise_for_status()
                data = resp.json()
                clusters = data.get("clusters", [])
                if not clusters:
                    return
            except Exception as e:
                out.print(f"[red]Error rendering clusters:[/] {e}")
                import traceback
                out.print(f"[dim]{traceback.format_exc()}[/dim]")
                return
                
            out.print(Rule("IDENTITY ANALYSIS", style="bold blue"))
            out.print()
            
            for i, cluster in enumerate(clusters, 1):
                conf = cluster.get("confidence", 0.0)
                label = cluster.get("label", "unknown")
                reasoning = cluster.get("reasoning", [])
                findings = cluster.get("findings", [])
                is_col = cluster.get("is_collision", False)
                
                out.print(f"  [bold]IDENTITY {i}[/] — {label}  [dim][confidence: {conf:.2f}][/dim]")
                for reason in reasoning:
                    out.print(f"    [dim]\"{reason}\"[/dim]")
                out.print()
                
                if is_col and not show_collisions:
                    out.print(f"    [dim]~ {len(findings)} platforms with bare username match[/dim]")
                    out.print("      [dim](use --show-collisions to expand)[/dim]")
                    out.print()
                    continue
                    
                shown = 0
                for finding in findings:
                    item = finding.get("data", finding)
                    mod_name = finding.get("module_name", "unknown")
                    platform, detail = _extract_finding_line(item, mod_name)
                    
                    detail_text = detail
                    if mod_name in ("account_discovery", "user_scanner") or str(item.get("source", "")) in ("account_discovery", "user_scanner"):
                        platform = platform.title()
                        detail_text = "[email registration confirmed]"
                        
                    p_label = f"{platform[:16]:<16}"
                    out.print(f"    [green]✓[/green] {p_label} [dim]{detail_text}[/dim]")
                    shown += 1
                    if not is_col and shown >= 5 and len(findings) > 5:
                        out.print(f"    [dim]+ {len(findings) - 5} more accounts[/dim]")
                        break
                out.print()
            out.print()

        out.print("\n[bold green]Investigation Complete[/]\n")
        render_summary(report_data)
        await render_clusters_output()
        out.print(Rule("Full Results", style="bold"))
        render_findings(report_data)
        render_skipped(report_data)

    return exit_code


@app.command()
def investigate(
    email: str = typer.Argument(..., help="Email address to investigate."),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table|json|jsonl"
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
    force: bool = typer.Option(
        False, "--force", help="Bypass recent-result cache and re-run all modules."
    ),
    show_collisions: bool = typer.Option(
        False, "--show-collisions", help="Expands collision clusters in output."
    ),
) -> None:
    """Run a full OSINT investigation against an email address.
    Exit codes: 0=clean 1=findings 2=breaches 3=error"""
    if email == "-":
        emails = [l.strip() for l in sys.stdin if l.strip() and not l.startswith("#")]
    else:
        emails = [email]

    max_code = 0
    for i, target_email in enumerate(emails):
        if i > 0 and output_format not in ("json", "jsonl"):
            err_console.print("━" * 80)
        code = asyncio.run(_investigate(target_email, output_format, modules, timeout, output_file, force, show_collisions))
        if code > max_code:
            max_code = code

    sys.exit(max_code)


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
