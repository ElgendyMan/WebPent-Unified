# viewer.py
"""Simple CLI viewer for the WebPent findings database.

Lists every persisted finding ordered by severity (critical first) in a
colour-coded Rich table.

Usage:
    python viewer.py [--db ./webpent.db] [--json]
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()
err_console = Console(stderr=True)


# Severity ordering — critical first, info last.
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
_DEFAULT_SEVERITY_RANK = 99

# Severity → Rich style mapping (matches cli/main.py).
_SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "blue",
}


def _severity_style(severity: str) -> str:
    return _SEVERITY_STYLES.get(str(severity).lower(), "white")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webpent-viewer",
        description="View WebPent findings from the SQLite database.",
    )
    parser.add_argument(
        "--db",
        default="./webpent.db",
        help="Path to the SQLite database (default: ./webpent.db).",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit findings as a JSON array instead of a table.",
    )
    return parser


def _fetch_findings(db_path: Path) -> list[dict[str, object]]:
    """Load all findings from ``db_path``, ordered by severity.

    The connection is opened explicitly and closed in a ``finally`` block.
    The ``with sqlite3.connect(...) as conn:`` idiom is deliberately
    avoided — per the ``sqlite3`` documentation that context manager
    manages *transactions* (commit/rollback), not the connection
    lifecycle, so it would leak file descriptors until garbage collection.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, title, severity, url, tool_name, "
            "cvss_score, business_impact "
            "FROM findings ORDER BY created_at ASC"
        )
        rows = [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

    rows.sort(
        key=lambda r: (
            _SEVERITY_ORDER.get(
                str(r.get("severity", "")).lower(), _DEFAULT_SEVERITY_RANK
            ),
            str(r.get("title", "")),
        )
    )
    return rows


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    return text[: max(width - 3, 0)] + "..."


def _render_table(rows: Sequence[dict[str, object]]) -> None:
    """Print findings as a colour-coded Rich table."""
    table = Table(
        title="WebPent Findings",
        title_style="bold white",
        border_style="grey50",
        header_style="bold cyan",
        show_lines=False,
        expand=False,
    )

    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Severity", width=10)
    table.add_column("Tool", width=12)
    table.add_column("CVSS", width=20)
    table.add_column("Title", min_width=25, max_width=45, no_wrap=False)
    table.add_column("URL", min_width=25, max_width=45, no_wrap=False)

    for idx, row in enumerate(rows, start=1):
        sev = str(row.get("severity", "info"))
        sev_text = Text(sev.upper(), style=_severity_style(sev))
        tool = str(row.get("tool_name", ""))
        cvss = str(row.get("cvss_score") or "—")
        title = _truncate(str(row.get("title", "")), 45)
        url = str(row.get("url", ""))

        table.add_row(str(idx), sev_text, tool, cvss, title, url)

    console.print(table)

    # Summary panel
    total = len(rows)
    by_sev: dict[str, int] = {}
    for r in rows:
        s = str(r.get("severity", "info")).lower()
        by_sev[s] = by_sev.get(s, 0) + 1

    summary_parts = [f"Total: {total}"]
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in by_sev:
            summary_parts.append(f"{sev.capitalize()}: {by_sev[sev]}")

    console.print(
        Panel(
            "  ".join(summary_parts),
            border_style="steel_blue",
            padding=(0, 2),
            expand=False,
        )
    )


def _render_json(rows: Sequence[dict[str, object]]) -> None:
    console.print_json(json.dumps(list(rows), default=str))


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    db_path = Path(args.db)
    if not db_path.exists():
        err_console.print(
            f"[red]Error:[/red] Database not found at {db_path}",
            style="red",
        )
        return 1

    try:
        rows = _fetch_findings(db_path)
    except sqlite3.OperationalError as exc:
        err_console.print(
            f"[red]Error reading database:[/red] {exc}\n"
            "[dim]Hint: run an engagement first to initialise the schema.[/dim]",
        )
        return 1

    if not rows:
        console.print("[dim]No findings in the database.[/dim]")
        return 0

    if args.as_json:
        _render_json(rows)
    else:
        _render_table(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
