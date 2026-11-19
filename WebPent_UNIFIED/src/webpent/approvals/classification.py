"""webpent.approvals.classification — M9 (Part 4 §11): Tier 0–3 risk
classification by ACTUAL action behavior.

Part 4 §11: "approval classification and binding completing
authorization — never replacing it" and "Tier 0–3 risk classification
by ACTUAL action behavior".

Classification inputs are the action's OBSERVED behavior — the HTTP
method, the action family, the capability name, whether an identity's
session material is used, whether state mutates, whether data leaves
the engagement boundary — never the action's self-description. The
mapping is deterministic and reason-carrying:

* **TIER_0** — read-only, in-scope, no identity material: no approval
  needed (the authorization layer alone governs).
* **TIER_1** — active but bounded: in-scope state interaction
  (form submit, browser action) with the engagement's own identities.
* **TIER_2** — high impact: destructive methods, file upload, or
  budget above the standard band.
* **TIER_3** — exceptional: credential/session material use beyond
  the engagement's declared identities, cross-tenant interactions,
  data export, or anything the authorization layer flagged
  human-review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

__all__ = [
    "ApprovalTier",
    "TierClassification",
    "classify_action",
]

_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_DESTRUCTIVE_METHODS = frozenset({"DELETE"})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH"})
_EXPORT_FAMILIES = frozenset({"export", "report_export", "data_export"})
_CREDENTIAL_SIGNALS = ("credential", "password", "session", "token", "secret")


class ApprovalTier(str, Enum):
    TIER_0 = "tier_0"
    TIER_1 = "tier_1"
    TIER_2 = "tier_2"
    TIER_3 = "tier_3"


@dataclass(frozen=True)
class TierClassification:
    """The deterministic tier verdict for one action, with its reasons."""

    tier: ApprovalTier
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def approval_required(self) -> bool:
        return self.tier != ApprovalTier.TIER_0

    def as_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value,
            "approval_required": self.approval_required,
            "reasons": list(self.reasons),
        }


def classify_action(
    *,
    method: str = "GET",
    action_family: str = "http_read",
    capability: str = "",
    identity_ref: str = "anonymous",
    uses_engagement_identity: bool = False,
    uses_foreign_identity: bool = False,
    cross_tenant: bool = False,
    estimated_cost: float = 1.0,
    standard_budget_band: float = 10.0,
    authorization_flagged_human_review: bool = False,
) -> TierClassification:
    """Classify by ACTUAL behavior; every reason names the signal."""
    reasons: list[str] = []
    method = str(method or "GET").upper()
    family = str(action_family or "http_read").lower()
    capability_l = str(capability or "").lower()

    tier = ApprovalTier.TIER_0
    if method in _READ_METHODS and family in {"http_read", "browser_read", "recon"}:
        reasons.append(f"read_only_method:{method}")
    if method in _MUTATING_METHODS or family in {"form_submit", "browser_action", "workflow"}:
        tier = ApprovalTier.TIER_1
        reasons.append(f"active_behavior:{method or family}")
    if method in _DESTRUCTIVE_METHODS or family in {"file_upload", "oob"}:
        tier = ApprovalTier.TIER_2
        reasons.append(f"high_impact_behavior:{method or family}")
    if estimated_cost > standard_budget_band:
        tier = ApprovalTier.TIER_2
        reasons.append(f"budget_above_standard_band:{estimated_cost}>{standard_budget_band}")
    if family in _EXPORT_FAMILIES or "export" in capability_l:
        tier = ApprovalTier.TIER_3
        reasons.append("data_leaves_engagement_boundary")
    if uses_foreign_identity or cross_tenant:
        tier = ApprovalTier.TIER_3
        reasons.append("cross_identity_or_tenant_interaction")
    if authorization_flagged_human_review:
        tier = ApprovalTier.TIER_3
        reasons.append("authorization_layer_flagged_human_review")
    if uses_engagement_identity and tier == ApprovalTier.TIER_0:
        tier = ApprovalTier.TIER_1
        reasons.append("engagement_identity_in_use")

    _ = identity_ref  # the identity NAME is not a behavior signal; the
    # boolean behavior flags above are — recorded for clarity.
    return TierClassification(tier=tier, reasons=tuple(reasons))


def classification_from_request(request: Mapping[str, Any] | Any) -> TierClassification:
    """Convenience: classify an ActionRequest-like object."""

    def get(key: str, default: Any = None) -> Any:
        if isinstance(request, Mapping):
            return request.get(key, default)
        return getattr(request, key, default)

    return classify_action(
        method=str(get("method", "GET")),
        action_family=str(get("action_family", "http_read")),
        capability=str(get("capability", "") or ""),
        identity_ref=str(get("identity_ref", "anonymous")),
        uses_engagement_identity=bool(get("identity_ref", "anonymous") != "anonymous"),
        uses_foreign_identity=bool(get("uses_foreign_identity", False)),
        cross_tenant=bool(get("cross_tenant", False)),
        estimated_cost=float(get("estimated_cost", 1.0) or 1.0),
        authorization_flagged_human_review=bool(
            get("authorization_flagged_human_review", False)
        ),
    )
