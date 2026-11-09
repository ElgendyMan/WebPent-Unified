# src/webpent/reporting/__init__.py
"""Engagement reporting (v78, release package).

Pure, machine-derived rendering of an existing hunt report payload
(``AutonomousHuntState.to_report_json()``) into deliverable Markdown or
self-contained HTML. Nothing here computes new claims about the target;
sections that are absent from the payload are skipped, and every
non_claim the payload carries is carried through verbatim.
"""

from __future__ import annotations

from webpent.reporting.engagement_report import build_engagement_report

__all__ = ["build_engagement_report"]
