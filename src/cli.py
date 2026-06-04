"""
Click CLI for the asset monitoring tool.

Entry point commands:
  scan         — run enumeration + verification modules
  report       — print a tabulated terminal report
  export       — write a JSON or HTML report to a file
  add          — add a domain / subdomain / website to monitoring
  daemon       — start the APScheduler loop
  reset-admin  — reset (or create) the admin dashboard user
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.table import Table

from src.config import AppConfig, load_config
from src.database import (
    ChangeEvent,
    DatabaseManager,
    Domain,
    Subdomain,
)

console = Console()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_SEVERITY_STYLE: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}


def _setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _parse_since(since: Optional[str]) -> Optional[datetime]:
    """Parse a duration string like ``24h`` or ``7d`` to a UTC cutoff datetime."""
    if not since:
        return None
    since = since.strip().lower()
    try:
        if since.endswith("h"):
            return datetime.now(tz=timezone.utc) - timedelta(hours=int(since[:-1]))
        if since.endswith("d"):
            return datetime.now(tz=timezone.utc) - timedelta(days=int(since[:-1]))
        if since.endswith("m"):
            return datetime.now(tz=timezone.utc) - timedelta(minutes=int(since[:-1]))
    except ValueError:
        pass
    raise click.BadParameter(
        f"Cannot parse --since value '{since}'. Use formats like 24h, 7d, 30m."
    )


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@click.group()
@click.option(
    "--config",
    default="config.yaml",
    show_default=True,
    help="Path to the YAML configuration file.",
)
@click.option(
    "--db",
    default="data/assetmonitor.db",
    show_default=True,
    help="Path to the SQLite database file.",
)
@click.option(
    "--log-level",
    default="INFO",
    show_default=True,
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    help="Logging verbosity.",
)
@click.pass_context
def cli(ctx: click.Context, config: str, db: str, log_level: str) -> None:
    """AssetMonitor — continuous security asset monitoring tool."""
    _setup_logging(log_level)
    ctx.ensure_object(dict)

    try:
        app_config: AppConfig = load_config(config)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Config error:[/bold red] {exc}")
        console.print(
            "Copy [cyan]config.yaml.example[/cyan] to [cyan]config.yaml[/cyan] and edit it."
        )
        sys.exit(1)

    db_manager = DatabaseManager(db)

    # Apply any DB-stored config overrides on top of the YAML config
    db_manager.apply_settings_to_config(app_config)

    ctx.obj["config"] = app_config
    ctx.obj["db"] = db_manager


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--module",
    type=click.Choice(
        ["all", "subdomains", "websites", "known-subdomains", "ports"], case_sensitive=False
    ),
    default="all",
    show_default=True,
    help="Which scan module(s) to run.",
)
@click.option("--domain", default=None, help="Limit scan to a single domain.")
@click.pass_context
def scan(ctx: click.Context, module: str, domain: Optional[str]) -> None:
    """Run enumeration and verification scan modules."""

    async def _run() -> None:
        config: AppConfig = ctx.obj["config"]
        db: DatabaseManager = ctx.obj["db"]

        from src.notifications.manager import NotificationManager
        from src.scheduler import SchedManager

        notif_mgr = NotificationManager(config, db)
        sched = SchedManager(config, db, notif_mgr)

        if domain:
            # Ensure the domain exists in DB
            db.add_domain(domain)

        console.print(f"[bold cyan]Running scan module=[/bold cyan][bold]{module}[/bold]", end="")
        if domain:
            console.print(f" [dim]for domain=[/dim][bold]{domain}[/bold]")
        else:
            console.print()

        if module in ("all", "subdomains", "known-subdomains", "websites"):
            await sched.run_full_scan()
        elif module == "ports":
            from src.scanning.manager import PortScanManager
            psm = PortScanManager(config, db)
            events = await psm.scan_all()
            console.print(f"[bold green]Port scan complete.[/bold green] {len(events)} change event(s).")
            return
        else:
            console.print(f"[red]Unknown module: {module}[/red]")
            sys.exit(1)

        console.print("[bold green]Scan complete.[/bold green]")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@cli.command(name="report")
@click.option(
    "--type",
    "report_type",
    type=click.Choice(["subdomains", "changes", "events"], case_sensitive=False),
    default="changes",
    show_default=True,
    help="Type of report to display.",
)
@click.option("--status", default=None, help="Filter by status (e.g. alive, dead).")
@click.option(
    "--severity",
    default=None,
    help="Filter by minimum severity (CRITICAL/HIGH/MEDIUM/LOW/INFO).",
)
@click.option(
    "--since",
    default=None,
    help="Show events since this duration ago (e.g. 24h, 7d).",
)
@click.option("--domain", default=None, help="Limit to a specific domain.")
@click.pass_context
def report(
    ctx: click.Context,
    report_type: str,
    status: Optional[str],
    severity: Optional[str],
    since: Optional[str],
    domain: Optional[str],
) -> None:
    """Print a tabulated report to the terminal."""
    db: DatabaseManager = ctx.obj["db"]
    cutoff = _parse_since(since)

    if report_type == "subdomains":
        _report_subdomains(db, status=status, domain=domain)
    elif report_type in ("changes", "events"):
        _report_events(db, severity=severity, cutoff=cutoff, domain=domain)
    else:
        console.print(f"[red]Unknown report type: {report_type}[/red]")
        sys.exit(1)


def _report_subdomains(
    db: DatabaseManager,
    status: Optional[str] = None,
    domain: Optional[str] = None,
) -> None:
    from sqlalchemy import select as _select

    with db.get_session() as session:
        q = _select(Subdomain)
        if status:
            q = q.where(Subdomain.status == status.lower())
        if domain:
            dom_obj = session.scalar(
                _select(Domain).where(Domain.domain == domain)
            )
            if dom_obj:
                q = q.where(Subdomain.domain_id == dom_obj.id)
            else:
                console.print(f"[yellow]Domain not found in DB: {domain}[/yellow]")
        rows: List[Subdomain] = list(session.scalars(q.order_by(Subdomain.fqdn)).all())

    table = Table(title="Subdomains", show_lines=False, border_style="dim")
    table.add_column("FQDN", style="cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("HTTP", justify="right")
    table.add_column("Classification")
    table.add_column("Technologies")
    table.add_column("First Seen")

    for sub in rows:
        status_style = "green" if sub.status == "alive" else "dim"
        tech_list = sub.technologies or []
        tech_names = [
            t.get("name", str(t)) if isinstance(t, dict) else str(t)
            for t in tech_list
        ]
        techs = ", ".join(tech_names[:3])
        if len(tech_names) > 3:
            techs += f" +{len(tech_names) - 3}"
        table.add_row(
            sub.fqdn,
            f"[{status_style}]{sub.status}[/{status_style}]",
            str(sub.http_status or "—"),
            sub.classification or "—",
            techs or "—",
            (sub.first_seen.strftime("%Y-%m-%d") if sub.first_seen else "—"),
        )

    console.print(table)
    console.print(f"[dim]Total: {len(rows)} subdomain(s)[/dim]")


def _report_events(
    db: DatabaseManager,
    severity: Optional[str] = None,
    cutoff: Optional[datetime] = None,
    domain: Optional[str] = None,
) -> None:
    from sqlalchemy import select as _select

    with db.get_session() as session:
        q = _select(ChangeEvent).order_by(ChangeEvent.detected_at.desc())
        if severity:
            min_level = _SEVERITY_ORDER.get(severity.upper(), 99)
            q_results: List[ChangeEvent] = list(session.scalars(q).all())
            rows = [
                ev
                for ev in q_results
                if _SEVERITY_ORDER.get(ev.severity.upper(), 99) <= min_level
            ]
        else:
            rows = list(session.scalars(q).all())

    if cutoff:
        rows = [
            ev
            for ev in rows
            if ev.detected_at
            and (
                ev.detected_at.replace(tzinfo=timezone.utc)
                if ev.detected_at.tzinfo is None
                else ev.detected_at
            )
            >= cutoff
        ]

    if domain:
        rows = [
            ev
            for ev in rows
            if ev.target == domain or ev.target.endswith(f".{domain}")
        ]

    table = Table(title="Change Events", show_lines=False, border_style="dim")
    table.add_column("Sev", no_wrap=True)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Target", no_wrap=True)
    table.add_column("Description")
    table.add_column("Detected At", no_wrap=True)
    table.add_column("Alerted", justify="center")

    for ev in rows:
        sev = ev.severity.upper()
        sev_style = _SEVERITY_STYLE.get(sev, "")
        alerted_str = "[green]✓[/green]" if ev.alerted else "[dim]—[/dim]"
        table.add_row(
            f"[{sev_style}]{sev}[/{sev_style}]",
            ev.event_type,
            ev.target,
            ev.description[:80] + ("…" if len(ev.description) > 80 else ""),
            (
                ev.detected_at.strftime("%Y-%m-%d %H:%M")
                if ev.detected_at
                else "—"
            ),
            alerted_str,
        )

    console.print(table)
    console.print(f"[dim]Total: {len(rows)} event(s)[/dim]")


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


@cli.command(name="export")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "html"], case_sensitive=False),
    default="json",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    "output",
    default=None,
    help="Output file path (defaults: report.json / report.html).",
)
@click.option("--domain", default=None, help="Limit export to a specific domain.")
@click.pass_context
def export(
    ctx: click.Context,
    fmt: str,
    output: Optional[str],
    domain: Optional[str],
) -> None:
    """Export monitoring data to a JSON or HTML file."""

    async def _run() -> None:
        db: DatabaseManager = ctx.obj["db"]
        out = output or (f"report.{fmt}")

        console.print(
            f"Exporting [bold]{fmt.upper()}[/bold] report to [cyan]{out}[/cyan]..."
        )

        if fmt == "json":
            from src.reporting.json_export import export_json

            await export_json(db, out, domain=domain)
        else:
            from src.reporting.html_report import generate_report

            await generate_report(db, out, domain=domain)

        console.print(f"[bold green]Report written:[/bold green] {out}")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# add
# ---------------------------------------------------------------------------


@cli.command(name="add")
@click.argument(
    "resource_type",
    type=click.Choice(["domain", "subdomain", "website"], case_sensitive=False),
)
@click.argument("value")
@click.pass_context
def add(ctx: click.Context, resource_type: str, value: str) -> None:
    """Add a domain, subdomain, or website URL to monitoring.

    \b
    Examples:
      assetmonitor.py add domain example.com
      assetmonitor.py add subdomain admin.example.com
      assetmonitor.py add website https://example.com
    """
    db: DatabaseManager = ctx.obj["db"]
    resource_type = resource_type.lower()

    if resource_type == "domain":
        dom = db.add_domain(value)
        console.print(
            f"[green]Domain added:[/green] [cyan]{dom.domain}[/cyan] (id={dom.id})"
        )

    elif resource_type == "subdomain":
        # Infer parent domain from FQDN
        parts = value.split(".")
        root = ".".join(parts[-2:]) if len(parts) >= 2 else value
        parent = db.get_domain(root)
        if parent is None:
            parent = db.add_domain(root)
            console.print(f"[dim]Auto-created parent domain: {root}[/dim]")

        sub, is_new = db.upsert_subdomain(
            fqdn=value,
            domain_id=parent.id,
            discovery_technique="manual",
        )
        verb = "added" if is_new else "already exists"
        console.print(
            f"[green]Subdomain {verb}:[/green] [cyan]{sub.fqdn}[/cyan] (id={sub.id})"
        )

        _append_to_file("data/subdomains.txt", value)

    elif resource_type == "website":
        _append_to_file("data/websites.txt", value)
        console.print(f"[green]Website added to monitoring:[/green] [cyan]{value}[/cyan]")

    else:
        console.print(f"[red]Unknown resource type: {resource_type}[/red]")
        sys.exit(1)


def _append_to_file(path: str, value: str) -> None:
    """Append a value to a text file if it isn't already present."""
    import os

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    existing: List[str] = []
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            existing = [ln.strip() for ln in fh if not ln.strip().startswith("#")]
    if value not in existing:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{value}\n")


# ---------------------------------------------------------------------------
# reset-admin
# ---------------------------------------------------------------------------


@cli.command(name="reset-admin")
@click.option(
    "--password",
    default=None,
    help="New admin password. If omitted a random one is generated and printed.",
)
@click.pass_context
def reset_admin(ctx: click.Context, password: Optional[str]) -> None:
    """Reset (or create) the admin user with a new password.

    \b
    Usage inside Docker:
      docker-compose exec assetmonitor python assetmonitor.py reset-admin
      docker-compose exec assetmonitor python assetmonitor.py reset-admin --password mysecret
    """
    import secrets as _secrets
    import bcrypt as _bcrypt

    db: DatabaseManager = ctx.obj["db"]

    if password:
        new_pwd = password
        generated = False
    else:
        new_pwd = _secrets.token_urlsafe(12)
        generated = True

    password_hash = "bcrypt:" + _bcrypt.hashpw(new_pwd.encode(), _bcrypt.gensalt()).decode()
    db.set_user("admin", password_hash, "admin")

    if generated:
        console.print(
            "[bold yellow]┌─ ADMIN PASSWORD RESET ────────────────────────────────────────────┐[/bold yellow]"
        )
        console.print(
            "[bold yellow]│  Username:[/bold yellow] [bold cyan]admin[/bold cyan]"
        )
        console.print(
            f"[bold yellow]│  Password:[/bold yellow] [bold cyan]{new_pwd}[/bold cyan]"
        )
        console.print(
            "[bold yellow]└──────────────────────────────────────────────────────────────────┘[/bold yellow]"
        )
    else:
        console.print("[bold green]Admin password updated.[/bold green]")


# ---------------------------------------------------------------------------
# daemon
# ---------------------------------------------------------------------------


@cli.command(name="daemon")
@click.pass_context
def daemon(ctx: click.Context) -> None:
    """Start the APScheduler daemon loop.

    Runs the full scan on the interval configured in config.yaml
    (``scan.interval_minutes``).  Handles SIGTERM / SIGINT for graceful
    shutdown.
    """
    config: AppConfig = ctx.obj["config"]
    db: DatabaseManager = ctx.obj["db"]

    from src.notifications.manager import NotificationManager
    from src.scheduler import SchedManager

    # Ensure at least one login exists; print generated password on first run
    temp_pwd = db.ensure_default_admin()
    if temp_pwd:
        console.print(
            "[bold yellow]┌─ DEFAULT ADMIN CREDENTIALS ──────────────────────────────────────┐[/bold yellow]"
        )
        console.print(
            "[bold yellow]│  Username:[/bold yellow] [bold cyan]admin[/bold cyan]"
        )
        console.print(
            f"[bold yellow]│  Password:[/bold yellow] [bold cyan]{temp_pwd}[/bold cyan]"
        )
        console.print(
            "[bold yellow]│  Also saved to: data/initial_credentials.txt                     │[/bold yellow]"
        )
        console.print(
            "[bold yellow]│  Change via Settings → Users after first login.                  │[/bold yellow]"
        )
        console.print(
            "[bold yellow]└──────────────────────────────────────────────────────────────────┘[/bold yellow]"
        )
        logger.info("Default admin user created — credentials saved to data/initial_credentials.txt")

        # Write to mounted volume so user can read from host without docker logs
        _creds_path = "data/initial_credentials.txt"
        try:
            os.makedirs("data", exist_ok=True)
            with open(_creds_path, "w", encoding="utf-8") as _f:
                _f.write("AssetMonitor — Initial Admin Credentials\n")
                _f.write("=" * 42 + "\n")
                _f.write(f"Username : admin\n")
                _f.write(f"Password : {temp_pwd}\n")
                _f.write("\n")
                _f.write("Change this password immediately via Settings → Users.\n")
                _f.write("Delete this file after your first login.\n")
        except Exception as _e:
            logger.warning("Could not write credentials file: %s", _e)

    notif_mgr = NotificationManager(config, db)
    sched = SchedManager(config, db, notif_mgr)

    console.print(
        f"[bold cyan]AssetMonitor daemon starting[/bold cyan] "
        f"(interval={config.scan.interval_minutes}m)"
    )

    # Start the web dashboard if enabled
    if config.web.enabled:
        from src.web.server import start_web_server
        start_web_server(db, config, host=config.web.host, port=config.web.port, sched_manager=sched)
        console.print(
            f"[bold cyan]Dashboard:[/bold cyan] http://{config.web.host}:{config.web.port}"
        )

    # Run an immediate scan on startup, then let the scheduler take over.
    asyncio.run(sched.run_full_scan())

    sched.start()

    # Graceful shutdown on SIGTERM / SIGINT
    def _shutdown(signum: int, frame: Any) -> None:
        console.print("\n[yellow]Received shutdown signal — stopping scheduler…[/yellow]")
        sched.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    console.print("[dim]Daemon running. Press Ctrl+C to stop.[/dim]")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        _shutdown(signal.SIGINT, None)
