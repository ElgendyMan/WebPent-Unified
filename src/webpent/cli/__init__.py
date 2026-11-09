"""
WebPent CLI — OPTIONAL LAYER
Requires: langgraph, typer, rich
Core engine: webpent.goed_v1, webpent.cqa_v2, webpent.models, webpent.smart

The actual Typer command surface lives in ``webpent.cli.commands`` (restored
from the pre-GOED v61 line during the canonical merge — see
RECONCILIATION_REPORT.md). This file keeps the thin OPTIONAL_LAYER
availability-probe convention used by every other top-level package
(api/, graph/, agents/, shared/, state/, workers/), and additionally
re-exports ``app``/``main`` so the ``webpent = "webpent.cli:main"`` console
script entry point in pyproject.toml keeps working when the optional
dependency (langgraph) is installed.
"""

OPTIONAL_LAYER = "cli"
try:
    import langgraph  # noqa: F401

    LAYER_AVAILABLE = True
    LAYER_STATUS = "Optional dependencies available"
except ImportError:
    LAYER_AVAILABLE = False
    LAYER_STATUS = "langgraph not installed — CLI layer unavailable"

__all__ = ["OPTIONAL_LAYER", "LAYER_AVAILABLE", "LAYER_STATUS"]

if LAYER_AVAILABLE:
    try:
        from webpent.cli.commands import (  # noqa: F401
            app,
            main,
        )

        __all__ += ["app", "main"]
    except ImportError as _exc:  # pragma: no cover - defensive, mirrors LAYER_AVAILABLE gate
        LAYER_AVAILABLE = False
        LAYER_STATUS = f"CLI commands module failed to import: {_exc}"
