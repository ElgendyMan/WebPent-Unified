"""The Verdict Protocol Tool (Pre-Verdict Sprint, Phase 1).

A meta-tool: it leads the operator through the 47-entry Verdict
Protocol (15 protocol days, the 30-day watch window and the final
verdict) without adding a single feature to the webpent core. The
operator runs webpent; this tool records what happened, verifies the
checklists and computes the verdict.
"""

from __future__ import annotations

__version__ = "1.0.0"

from verdict_tool.protocol import TOTAL_DAYS, Check, Day, get_day  # noqa: E402
from verdict_tool.tracking import VerdictState, Workspace, new_state  # noqa: E402

__all__ = ["Check", "Day", "TOTAL_DAYS", "VerdictState", "Workspace",
           "get_day", "new_state"]
