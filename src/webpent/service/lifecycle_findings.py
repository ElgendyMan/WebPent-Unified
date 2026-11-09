"""Lifecycle-notification Finding builder (r6c, UM-DR-26).

The promoted-alert webhook needs an actionable notification object, and the
M1-B/E-1 provenance contract requires every ``Tool-Confirmed`` writer to be a
consciously-registered module that stamps its confirming gate.  This builder
is that registered writer (see
``tests/test_m1b_tool_confirmed_writers.py::APPROVED_TOOL_CONFIRMED_WRITERS``):

- a PROMOTED lifecycle event carries ``confidence_level="Tool-Confirmed"``
  with evidence naming ``tool_confirmed_by="webpent.lifecycle"`` (the
  promotion-guard stamp) — so ``push_to_webhook``'s actionable-confidence
  filter lets the alert through (the old always-``Pending`` shape silently
  dead-ended every promoted webhook);
- a REFUTED event stays ``Pending`` (not actionable, notification only).

``service/cost_alerts.py`` deliberately keeps NO ``Tool-Confirmed`` literal
(the M1b source-level ban) and calls this builder instead.
"""
from __future__ import annotations

import uuid
from typing import Any, Mapping

from webpent.models.findings import Finding


def build_lifecycle_finding(
    *,
    campaign_id: str,
    finding_id: str,
    status: str,
    severity: str,
    title: str,
    vuln_class: str,
    route: str,
    finding_url: str,
    cvss_score: str | None,
    payload: Mapping[str, Any],
) -> Finding:
    """Build the lifecycle NOTIFICATION Finding for one finding event."""
    promoted = str(status or "") == "promoted"
    evidence: dict[str, Any] = {
        "lifecycle_status": str(status or ""),
        "notification_only": True,
    }
    if promoted:
        # The promotion gate's own stamp (M1-B/E-1): this notification IS the
        # promotion guard's decision record, so the Tool-Confirmed literal is
        # honest — the gate is named, not claimed.
        evidence["tool_confirmed_by"] = "webpent.lifecycle"
    return Finding(
        id=uuid.uuid5(uuid.NAMESPACE_URL, f"webpent:{campaign_id}:{finding_id}"),
        title=title or f"WebPent {vuln_class} finding",
        severity=severity,
        description=f"Lifecycle notification for {vuln_class} finding {finding_id}.",
        tool_name="webpent.lifecycle",
        url=finding_url,
        confidence_level="Tool-Confirmed" if promoted else "Pending",
        cvss_score=cvss_score,
        vuln_class=vuln_class,
        campaign_id=campaign_id,
        route=route if route != "/" else None,
        evidence=evidence,
    )


__all__ = ["build_lifecycle_finding"]
