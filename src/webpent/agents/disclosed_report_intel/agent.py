"""LangGraph node for optional local disclosed-report intelligence."""

from __future__ import annotations

import re
from typing import Any

from langchain_core.messages import AIMessage

from webpent.shared.disclosed_report_intel import build_advisories, ingest_disclosed_reports
from webpent.state.state import PentestState

_URL_RE = re.compile(r"https?://[^\s'\"<>]+")


def _collect_endpoint_context(value: Any, *, limit: int = 200) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    def visit(item: Any) -> None:
        if len(found) >= limit:
            return
        if isinstance(item, str):
            for candidate in _URL_RE.findall(item):
                clean = candidate.rstrip(".,);]")
                if clean not in seen:
                    seen.add(clean)
                    found.append(clean)
                    if len(found) >= limit:
                        return
        elif isinstance(item, dict):
            for key, child in item.items():
                if (
                    str(key).lower() in {"url", "endpoint", "request_url", "route"}
                    and isinstance(child, str)
                    and child not in seen
                ):
                    seen.add(child)
                    found.append(child)
                visit(child)
                if len(found) >= limit:
                    return
        elif isinstance(item, (list, tuple, set)):
            for child in item:
                visit(child)
                if len(found) >= limit:
                    return

    visit(value)
    return found[:limit]


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def disclosed_report_intel_node(state: PentestState) -> dict[str, Any]:
    """Build advisory leads from operator-supplied local report records.

    The node is intentionally a no-op with an explicit gap when no corpus is
    configured. It does not fetch external report sites and never mutates
    Finding confidence.
    """
    corpus = state.get("disclosed_report_corpus") or []
    target = state.get("target")
    target_url = str(getattr(target, "url", "") or "")
    records = ingest_disclosed_reports(corpus)
    advisories, gaps = build_advisories(
        target_url,
        _collect_endpoint_context(state.get("crawled_data") or {}),
        records,
    )
    return {
        "disclosed_report_advisories": advisories,
        "advisory_coverage_gaps": gaps,
        "messages": [
            AIMessage(
                content=(
                    f"Disclosed-report intelligence: indexed {len(records)} local records, "
                    f"generated {len(advisories)} advisory leads; no finding was auto-confirmed."
                )
            )
        ],
        "current_phase": "disclosed_report_intel",
    }
