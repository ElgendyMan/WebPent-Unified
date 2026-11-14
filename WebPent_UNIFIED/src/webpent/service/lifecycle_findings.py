"""Lifecycle-notification Finding builder (r6c, UM-DR-26; corrected UM-DR-35).

The promoted-alert webhook needs an actionable notification object. The
UM-DR-35 corrective closure removed the historical ``Tool-Confirmed``
literal from this builder: a lifecycle ``status`` string is NOT confirmation
authority evidence, and minting a notification Finding as Tool-Confirmed
from it was exactly the bypass class the universal CausalGuard boundary
forbids. The notification is now honest about what it is — a promotion
NOTIFICATION mirroring a decision already made by the real authority chain
elsewhere, kept actionable for the webhook through the ``Needs Human
Review`` level (accepted by the webhook actionable set) plus explicit
promotion-mirroring evidence.

- a PROMOTED lifecycle event carries ``confidence_level="Needs Human
  Review"`` with evidence naming ``lifecycle_promotion_mirrored=True`` and
  ``promotion_decided_by`` pointing at the real authority chain;
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
        # UM-DR-35 corrective closure: mirror, never re-mint. The promotion
        # decision was made by the real authority chain (CausalGuard →
        # ProofBundle → Replay → central promotion); this notification only
        # records that it happened and explicitly disclaims confirmation
        # authority. The historical Tool-Confirmed literal minted from a
        # lifecycle status string was removed (universal boundary rule).
        evidence["lifecycle_promotion_mirrored"] = True
        evidence["promotion_decided_by"] = (
            "causal_guard_authority_chain (mirrored; notification has no "
            "confirmation authority)"
        )
    return Finding(
        id=uuid.uuid5(uuid.NAMESPACE_URL, f"webpent:{campaign_id}:{finding_id}"),
        title=title or f"WebPent {vuln_class} finding",
        severity=severity,
        description=f"Lifecycle notification for {vuln_class} finding {finding_id}.",
        tool_name="webpent.lifecycle",
        url=finding_url,
        confidence_level="Needs Human Review" if promoted else "Pending",
        cvss_score=cvss_score,
        vuln_class=vuln_class,
        campaign_id=campaign_id,
        route=route if route != "/" else None,
        evidence=evidence,
    )


__all__ = ["build_lifecycle_finding"]
