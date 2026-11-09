# src/webpent/shared/console.py
"""webpent.shared.console

Centralised Rich-based terminal UI components for the WebPent Framework V3.

This module provides a single :data:`console` instance and helper
functions for rendering professional, minimalist output:

  * :func:`render_phase` — phase-transition panels (e.g. "Recon Started")
  * :func:`render_findings_table` — colour-coded findings table
  * :func:`render_summary` — engagement completion summary panel
  * :func:`render_error` — error panel (red border)
  * :func:`configure_logging` — RichHandler-based logging setup

Design philosophy:
    Enterprise-grade security tool aesthetic. No neon green, no ASCII
    skulls, no excessive emojis. Minimalist, high-contrast, optimised
    for rapid readability in both light and dark terminals.

Colour scheme (severity):
    Critical → bold red
    High     → red
    Medium   → yellow
    Low      → cyan
    Info     → blue
"""

from __future__ import annotations

import json as _json
import logging
import os
import time as _time
from collections.abc import Sequence

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn
from rich.table import Table
from rich.text import Text

# Single shared Console instance. ``stderr=True`` so that normal
# informational output (panels, tables) goes to stdout while logs go
# to stderr — this keeps pipelines like ``webpent ... | grep FINDING``
# clean.
console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Severity colour mapping
# ---------------------------------------------------------------------------
_SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "blue",
}


def _severity_style(severity: str) -> str:
    """Return the Rich style string for a severity value."""
    return _SEVERITY_STYLES.get(str(severity).lower(), "white")


# ---------------------------------------------------------------------------
# Phase transition panel
# ---------------------------------------------------------------------------
# Minimalist phase labels — no emojis, no exclamation marks. The panel
# border uses a muted blue to distinguish phase markers from log output
# without being visually loud.
_PHASE_BORDER = "steel_blue"


def print_phase_start(phase_name: str, description: str | None = None) -> None:
    """Print a compact, color-coded phase start event."""
    detail = description or "phase started"
    console.print(
        f"[bold steel_blue][START][/bold steel_blue] "
        f"[bold white]{phase_name}[/bold white] [dim]{detail}[/dim]"
    )


def print_phase_end(phase_name: str, duration: float, status: str = "success") -> None:
    """Print a color-coded phase completion event with duration."""
    normalized = str(status).strip().lower()
    style = {"success": "green", "warning": "yellow", "error": "red"}.get(
        normalized, "cyan"
    )
    console.print(
        f"[{style}][{normalized.upper()}][/{style}] "
        f"[bold white]{phase_name}[/bold white] "
        f"[dim]{max(0.0, float(duration)):.2f}s[/dim]"
    )


def create_progress() -> Progress:
    """Create a reusable Rich progress bar for long-running operations."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeRemainingColumn(),
        console=console,
    )


def render_phase(phase_name: str, detail: str | None = None) -> None:
    """Render a phase-transition panel.

    Args:
        phase_name: Human-readable phase label (e.g. "Reconnaissance").
        detail: Optional one-line detail shown beneath the phase name.
    """
    body = f"[bold white]{phase_name}[/bold white]"
    if detail:
        body += f"\n[dim]{detail}[/dim]"
    panel = Panel(
        body,
        border_style=_PHASE_BORDER,
        padding=(0, 2),
        expand=False,
    )
    console.print(panel)


# ---------------------------------------------------------------------------
# Findings table
# ---------------------------------------------------------------------------
def render_findings_table(findings: Sequence, title: str = "Findings") -> None:
    """Render a colour-coded findings table.

    Args:
        findings: Sequence of :class:`~webpent.models.findings.Finding`
            objects (or dicts with ``id``, ``severity``, ``title``,
            ``url`` keys).
        title: Table title.
    """
    table = Table(
        title=title,
        title_style="bold white",
        border_style="grey50",
        header_style="bold cyan",
        show_lines=False,
        expand=False,
    )

    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("ID", style="dim", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Title", min_width=30, max_width=60, no_wrap=False)
    table.add_column("URL", min_width=30, max_width=50, no_wrap=False)

    for idx, finding in enumerate(findings, start=1):
        # Support both Finding objects and dicts.
        if hasattr(finding, "severity"):
            sev = str(finding.severity)
            title_text = finding.title
            url = finding.url
            fid = str(finding.id)[:8]
        else:
            sev = str(finding.get("severity", "info"))
            title_text = finding.get("title", "")
            url = finding.get("url", "")
            fid = str(finding.get("id", ""))[:8]

        sev_text = Text(sev.upper(), style=_severity_style(sev))

        table.add_row(
            str(idx),
            fid,
            sev_text,
            title_text,
            url,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Summary panel
# ---------------------------------------------------------------------------
def render_summary(
    thread_id: str,
    findings_count: int,
    saved_count: int,
    report_path: str,
    db_path: str,
) -> None:
    """Render the engagement completion summary panel.

    Uses a green border to signal success without being garish.
    """
    content = (
        f"[bold green]Engagement Completed[/bold green]\n\n"
        f"  [dim]Thread ID[/dim]          {thread_id}\n"
        f"  [dim]Findings[/dim]           {saved_count}/{findings_count} persisted\n"
        f"  [dim]Report[/dim]             {report_path}\n"
        f"  [dim]Database[/dim]           {db_path}"
    )
    panel = Panel(
        content,
        border_style="green",
        padding=(1, 2),
        expand=False,
    )
    console.print(panel)


# ---------------------------------------------------------------------------
# Error panel
# ---------------------------------------------------------------------------
def render_error(message: str, detail: str | None = None) -> None:
    """Render an error panel with a red border.

    Args:
        message: Primary error message.
        detail: Optional secondary detail (e.g. "Run with --debug").
    """
    body = f"[bold red]{message}[/bold red]"
    if detail:
        body += f"\n[dim]{detail}[/dim]"
    panel = Panel(
        body,
        border_style="red",
        padding=(0, 2),
        expand=False,
    )
    err_console.print(panel)


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
class JsonLogFormatter(logging.Formatter):
    """Structured one-line-per-event JSON formatter (Track 3.5, 0.26.0).

    ``docker-compose.yml`` has declared ``WEBPENT_LOG_FORMAT=json`` for the
    production profile since the hardening pass, but nothing consumed the
    variable — dead config. This formatter makes it real: one JSON object
    per log event (``ts``, ``level``, ``logger``, ``message``) so log
    shippers can ingest operator runs without regex scraping.

    Secret-safety is unchanged by construction: the formatter renders the
    SAME message text the existing redaction layers already sanitize
    before any ``logger.*`` call; it adds only envelope fields. No new
    data source is introduced.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": _time.strftime(
                "%Y-%m-%dT%H:%M:%S", _time.gmtime(record.created)
            )
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return _json.dumps(payload, ensure_ascii=False)


def configure_logging(debug: bool = False) -> None:
    """Configure root logging with :class:`rich.logging.RichHandler`.

    In standard mode (``debug=False``):
      * Timestamps are omitted (the terminal already shows them via
        the shell).
      * The logger name (module path) is omitted to prioritise message
        clarity.
      * Only the level and message are shown, colour-coded by level.

    In debug mode (``debug=True``):
      * Full timestamp is shown.
      * Logger name is shown for tracing.
      * Level is DEBUG.

    Args:
        debug: If ``True``, enable DEBUG-level logging with full
            metadata. Defaults to ``False`` (INFO, clean output).

    Environment:
        WEBPENT_LOG_FORMAT: ``json`` switches the root handler to the
            structured :class:`JsonLogFormatter` (Track 3.5, 0.26.0 —
            makes the long-dead docker-compose declaration real). Any
            other value keeps the Rich console handler.
    """
    level = logging.DEBUG if debug else logging.INFO

    # Structured mode (Track 3.5): opt-in via WEBPENT_LOG_FORMAT=json.
    if os.environ.get("WEBPENT_LOG_FORMAT", "").strip().lower() == "json":
        root = logging.getLogger()
        root.handlers.clear()
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(JsonLogFormatter())
        root.addHandler(stream_handler)
        root.setLevel(level)
        return

    # RichHandler keyword arguments. In standard mode we suppress
    # timestamps and the logger name (show_level=False keeps the
    # coloured level tag but drops the redundant "INFO" text — we
    # keep show_level=True because the colour-coding is useful).
    if debug:
        handler_kwargs = {
            "show_time": True,
            "show_path": True,
            "show_level": True,
            "rich_tracebacks": True,
            "tracebacks_show_locals": False,
            "markup": True,
        }
    else:
        handler_kwargs = {
            "show_time": False,
            "show_path": False,
            "show_level": True,
            "rich_tracebacks": True,
            "tracebacks_show_locals": False,
            "markup": True,
        }

    handler = RichHandler(
        console=err_console,
        **handler_kwargs,
    )

    # Clear any existing handlers (from previous calls or basicConfig).
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Suppress noisy third-party loggers regardless of mode.
    for noisy in (
        "httpx",
        "httpcore",
        "openai",
        "anthropic",
        "urllib3",
        "chromadb",
        "sentence_transformers",
        "playwright",
    ):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Info / warning helpers (non-logging)
# ---------------------------------------------------------------------------
def print_info(message: str) -> None:
    """Print a dim informational line (not a log — goes to stdout)."""
    console.print(f"[dim]{message}[/dim]")


def print_success(message: str) -> None:
    """Print a green success line."""
    console.print(f"[green]{message}[/green]")
