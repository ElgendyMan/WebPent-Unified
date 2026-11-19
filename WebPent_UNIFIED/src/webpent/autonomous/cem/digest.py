"""CEM Operator Interface — the daily digest (v83, U-CEM-11).

One bounded, redacted Markdown report plus its JSON twin summarizing a
day of CEM: what was observed, what changed, which campaigns ran, which
findings regressed, what the budget looks like, and which scope alerts
fired. Every section is capped, every string passes ``redact``, and any
component that is missing or corrupt contributes an empty section instead
of an exception. The digest is a report: it instructs nothing.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

MAX_LISTED_ITEMS = 10
MAX_MARKDOWN_CHARS = 20_000


def _fmt_ts(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OSError, OverflowError):
        return "unknown"


def _section(changes: Any, limit: int = MAX_LISTED_ITEMS) -> list[str]:
    lines: list[str] = []
    if not isinstance(changes, (list, tuple)):
        return lines
    for change in list(changes)[:limit]:
        if not isinstance(change, dict):
            continue
        item = redact(str(change.get("item") or ""))[:100]
        classification = redact(str(change.get("classification") or ""))[:20]
        kind = redact(str(change.get("kind") or ""))[:20]
        lines.append(f"- `{kind}` {item} ({classification})")
    return lines


def build_digest(
    *,
    now: float,
    cem_state: Any = None,
    cycle_reports: Any = None,
    scheduler_status: Any = None,
    reactor_active: Any = None,
    regression_status: Any = None,
    regressed: Any = None,
    wake_history: Any = None,
    lessons: Any = None,
    seasonal_targets: Any = None,
    drift_alerts: Any = None,
) -> dict[str, Any]:
    """Build the bounded daily digest: ``{"markdown": str, "json": {...}}``."""
    state = cem_state if isinstance(cem_state, dict) else {}
    reports = [r for r in (cycle_reports or []) if isinstance(r, dict)]
    sched = scheduler_status if isinstance(scheduler_status, dict) else {}
    regr = regression_status if isinstance(regression_status, dict) else {}
    alerts = [a for a in (drift_alerts or []) if isinstance(a, dict)]

    changes_total = sum(int(r.get("change_count") or 0) for r in reports)
    spend_total = sum(int(r.get("spend") or 0) for r in reports)

    payload: dict[str, Any] = {
        "generated_at": _fmt_ts(now),
        "cycle_count": int(state.get("cycle_count") or 0),
        "targets": len(state.get("targets") or {}),
        "cycles_today": len(reports),
        "changes_total": changes_total,
        "spend_today": spend_total,
        "scheduler": sched,
        "active_campaigns": len(reactor_active or []),
        "regressions": len(regressed or []),
        "regression_status": regr,
        "wake_count": len(wake_history or []),
        "lessons_count": len(lessons or []),
        "seasonal_watchlist": [
            redact(str(t))[:120] for t in (seasonal_targets or [])[:MAX_LISTED_ITEMS]
        ],
        "scope_alerts": [
            {
                "kind": redact(str(a.get("kind") or ""))[:40],
                "host": redact(str(a.get("host") or ""))[:120],
                "severity": redact(str(a.get("severity") or ""))[:10],
                "note": redact(str(a.get("note") or ""))[:160],
            }
            for a in alerts[:MAX_LISTED_ITEMS]
        ],
        "advisory": True,
    }

    md: list[str] = []
    md.append(f"# تقرير CEM اليومي — {payload['generated_at']}")
    md.append("")
    md.append(
        f"الدورات: {payload['cycle_count']} · الأهداف: {payload['targets']} · "
        f"تغيّرات ملاحظة: {changes_total} · إنفاق اليوم: {spend_total} طلب"
    )
    md.append("")
    md.append("## الجدولة والحدود")
    md.append(
        f"- Kill switch: {'مُفعّل' if sched.get('kill_switch') else 'غير مُفعّل'}"
        + (f" — {redact(str(sched.get('kill_reason') or ''))[:120]}"
           if sched.get("kill_reason") else "")
    )
    md.append(
        f"- ساعات النشاط: {redact(str(sched.get('active_hours') or 'unknown'))[:40]} · "
        f"الإنفاق: {sched.get('spent_today', 0)}/{sched.get('daily_cap', '?')}"
    )
    md.append("")
    md.append("## التغيّرات الأخيرة")
    recent_lines: list[str] = []
    for report in reports[-3:]:
        report_changes = report.get("changes")
        if isinstance(report_changes, dict):
            recent_lines.extend(_section(report_changes.get("changes")))
        else:
            recent_lines.extend(_section([]))
    for decision in _decisions_of(reports):
        recent_lines.extend(_section((decision.get("diff") or {}).get("changes")))
    if recent_lines:
        md.extend(recent_lines[:MAX_LISTED_ITEMS])
    else:
        md.append("- لا تغيّرات تستحق الذكر.")
    md.append("")
    md.append("## الحملات والانحدارات")
    md.append(f"- حملات نشطة: {payload['active_campaigns']} · استدعاءات: {payload['wake_count']}")
    md.append(f"- انحدارات: {payload['regressions']} · حالة المراقبة: {regr or 'لا شيء'}")
    md.append("")
    md.append("## تنبيهات النطاق")
    if payload["scope_alerts"]:
        for alert in payload["scope_alerts"]:
            md.append(f"- {alert['kind']}: {alert['host']} ({alert['severity']}) — {alert['note']}")
    else:
        md.append("- لا تنبيهات نطاق.")
    md.append("")
    md.append("## الذاكرة الطولية")
    md.append(
        f"- دروس حية: {payload['lessons_count']} · "
        f"قائمة المراقبة الموسمية: {', '.join(payload['seasonal_watchlist']) or 'فارغة'}"
    )
    md.append("")
    md.append("_advisory بالكامل: هذا التقرير لا يرقّي دليلًا ولا يأمر بتنفيذ._")

    markdown = "\n".join(md)[:MAX_MARKDOWN_CHARS]
    payload["markdown"] = markdown
    return payload


def _decisions_of(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    decisions: list[dict[str, Any]] = []
    for report in reports:
        for observed in report.get("observed") or []:
            if isinstance(observed, dict):
                decisions.append(observed)
    return decisions[:MAX_LISTED_ITEMS]


def write_digest(digest: dict[str, Any], *, directory: Any) -> dict[str, str]:
    """Write digest.md and digest.json atomically into the directory."""
    written: dict[str, str] = {}
    try:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        for name, text in (
            ("digest.json", json.dumps(digest, indent=2, ensure_ascii=False)),
            ("digest.md", str(digest.get("markdown") or "")),
        ):
            fd, tmp_name = tempfile.mkstemp(dir=str(directory))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(text)
                os.replace(tmp_name, directory / name)
                written[name] = str(directory / name)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
    except (OSError, TypeError, ValueError) as exc:
        _LOG.warning("digest write failed (fail-soft): %s", exc)
    return written


__all__ = ["build_digest", "write_digest"]
