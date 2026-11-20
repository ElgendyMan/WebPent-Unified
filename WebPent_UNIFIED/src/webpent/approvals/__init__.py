"""webpent.approvals — M9 (Part 4 §11): HITL approval gates.

Tier 0–3 classification by ACTUAL action behavior; approval bound to
the full tuple (engagement, manifest, action, target, identity, tier,
preview, budget, approver, expiry); material change voids; CLI-prompt-
first channels (notifications can never grant); timeout/deny/cancel/
emergency-stop; append-only audit trail. Approvals COMPLETE
authorization — never replace it (a policy denial still wins).
"""
from webpent.approvals.binding import (
    ApprovalBinding,
    ApprovalGate,
    ApprovalLedger,
    ChannelOutcome,
    cli_prompt_channel,
    fingerprint_action,
)
from webpent.approvals.classification import (
    ApprovalTier,
    TierClassification,
    classify_action,
    classification_from_request,
)

__all__ = [
    "ApprovalBinding",
    "ApprovalGate",
    "ApprovalLedger",
    "ApprovalTier",
    "ChannelOutcome",
    "TierClassification",
    "classify_action",
    "classification_from_request",
    "cli_prompt_channel",
    "fingerprint_action",
]
