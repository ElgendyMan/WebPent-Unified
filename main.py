# main.py
"""Root-level entry point for the WebPent Framework V4.5.

This file delegates to the unified Typer CLI at ``webpent.cli``, which
includes the mandatory Playwright pre-flight health check. The legacy
``webpent.cli.main`` module has been removed to prevent bypass risks.

Usage:
    python main.py scan --url https://example.com
    python main.py scan --url https://example.com --creds admin:password
    python main.py preflight
"""

from __future__ import annotations

from webpent.cli import app

if __name__ == "__main__":
    app()
