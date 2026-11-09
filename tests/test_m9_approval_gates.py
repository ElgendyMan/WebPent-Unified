"""M9 (Part 4 §11, UM-DR-21): HITL approval gates — P0.

Acceptance: "approval audit trail complete; no approval reuse after
material change (tested)".

1. **Tier classification by ACTUAL behavior** — read-only → T0;
   active (POST/form/browser-action) → T1; destructive/upload/OOB or
   above-band budget → T2; export / foreign identity / cross-tenant /
   authorization-flagged → T3; reasons name the signal.
2. **The binding tuple** — engagement, manifest, action (method/path/
   family/capability), identity, tier, preview, budget, approver,
   expiry — all present; the fingerprint covers the action side.
3. **Material change voids** — every tuple component change refuses
   reuse (tested component by component).
4. **Lifecycle** — timeout / deny / cancel / expiry / one-time consume
   (a stale pre-consumption copy cannot double-spend) / emergency
   stop.
5. **Channels** — CLI prompt first; a notification channel can NEVER
   grant.
6. **Approval completes authorization, never replaces it** — with the
   real ActionAuthority, a human approval does not rescue a
   policy-denied out-of-scope action.
7. **The audit trail** — every event recorded in order.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from webpent.approvals import (
    ApprovalGate,
    ApprovalLedger,
    ApprovalTier,
    classify_action,
)
from webpent.approvals.binding import ChannelOutcome


def _grant_channel(approver: str = "alice", detail: str = "ok"):
    def channel(request: dict[str, Any]) -> ChannelOutcome:
        return ChannelOutcome(granted=True, approver=approver, detail=detail)

    return channel


def _gate(**kwargs: Any) -> ApprovalGate:
    gate = ApprovalGate(
        engagement_id="eng-1", manifest_digest="sha256:manifest-abc", **kwargs
    )
    gate.channel = _grant_channel()
    return gate


def _request(gate: ApprovalGate, **overrides: Any) -> Any:
    payload: dict[str, Any] = dict(
        method="POST",
        path="/api/notes",
        action_family="form_submit",
        capability="form_submit",
        identity_ref="owner",
        preview="POST /api/notes (note body redacted)",
        budget=2.0,
    )
    payload.update(overrides)
    classification = classify_action(
        method=payload["method"], action_family=payload["action_family"]
    )
    return gate.request_approval(classification, **payload), payload, classification


def _consume_kwargs(payload: dict[str, Any], classification: Any) -> dict[str, Any]:
    return {
        "method": payload["method"],
        "path": payload["path"],
        "action_family": payload["action_family"],
        "capability": payload["capability"],
        "identity_ref": payload["identity_ref"],
        "preview": payload["preview"],
        "budget": payload["budget"],
        "tier": classification.tier.value,
    }


# ---------------------------------------------------------------------------
# 1. Tier classification by ACTUAL behavior
# ---------------------------------------------------------------------------


def test_classification_by_actual_behavior() -> None:
    read = classify_action(method="GET", action_family="http_read")
    assert read.tier == ApprovalTier.TIER_0 and not read.approval_required

    active = classify_action(method="POST", action_family="form_submit")
    assert active.tier == ApprovalTier.TIER_1

    destructive = classify_action(method="DELETE", action_family="http_read")
    assert destructive.tier == ApprovalTier.TIER_2
    assert any("high_impact_behavior" in r for r in destructive.reasons)

    budget = classify_action(method="GET", action_family="recon", estimated_cost=99.0)
    assert budget.tier == ApprovalTier.TIER_2
    assert any("budget_above_standard_band" in r for r in budget.reasons)

    export = classify_action(action_family="export")
    assert export.tier == ApprovalTier.TIER_3
    assert any("data_leaves_engagement_boundary" in r for r in export.reasons)

    foreign = classify_action(method="GET", uses_foreign_identity=True)
    assert foreign.tier == ApprovalTier.TIER_3

    flagged = classify_action(method="GET", authorization_flagged_human_review=True)
    assert flagged.tier == ApprovalTier.TIER_3

    identity_read = classify_action(method="GET", identity_ref="owner", uses_engagement_identity=True)
    assert identity_read.tier == ApprovalTier.TIER_1


def test_classification_names_its_signals() -> None:
    verdict = classify_action(method="DELETE", action_family="http_read")
    assert verdict.reasons and all(r for r in verdict.reasons)


# ---------------------------------------------------------------------------
# 2. The binding tuple
# ---------------------------------------------------------------------------


def test_binding_carries_the_full_tuple() -> None:
    gate = _gate()
    binding, _, _ = _request(gate)
    data = binding.as_dict()
    for key in (
        "engagement_id", "manifest_digest", "action_fingerprint", "method",
        "path", "action_family", "capability", "identity_ref", "tier",
        "preview", "budget", "approver", "approved_at", "expires_at",
        "channel", "status",
    ):
        assert key in data, key
    assert data["engagement_id"] == "eng-1"
    assert data["manifest_digest"] == "sha256:manifest-abc"
    assert data["approver"] == "alice"
    assert data["status"] == "granted"


# ---------------------------------------------------------------------------
# 3. Material change voids (component by component)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "component,new_value",
    [
        ("method", "PUT"),
        ("path", "/api/other-notes"),
        ("action_family", "browser_action"),
        ("capability", "browser_action"),
        ("identity_ref", "viewer"),
        ("preview", "PUT /api/notes (DIFFERENT preview)"),
        ("budget", 3.0),
        ("tier", "tier_2"),
    ],
)
def test_any_material_change_refuses_reuse(component: str, new_value: Any) -> None:
    gate = _gate()
    binding, payload, classification = _request(gate)
    consume_kwargs = _consume_kwargs(payload, classification)
    ok, reason = gate.consume(binding, **consume_kwargs)
    assert ok, reason

    # A fresh identical approval, then reuse under a CHANGED component.
    binding2, payload2, classification2 = _request(gate)
    changed = {**_consume_kwargs(payload2, classification2), component: new_value}
    ok, reason = gate.consume(binding2, **changed)
    assert ok is False
    assert reason == "material_change_voids_approval"
    # And the voiding is terminal — the original tuple no longer works.
    ok, reason = gate.consume(binding2, **_consume_kwargs(payload2, classification2))
    assert ok is False and "binding_not_granted:voided" == reason


# ---------------------------------------------------------------------------
# 4. Lifecycle: timeout / deny / cancel / expiry / one-time / emergency
# ---------------------------------------------------------------------------


def test_deny_and_timeout_paths() -> None:
    gate = _gate()
    gate.channel = lambda req: ChannelOutcome(granted=False, approver="bob", detail="no")
    binding, _, classification = _request(gate)
    assert binding.status == "denied"
    ok, reason = gate.consume(
        binding, **_consume_kwargs(
            {"method": "POST", "path": "/api/notes", "action_family": "form_submit",
             "capability": "form_submit", "identity_ref": "owner",
             "preview": "POST /api/notes (note body redacted)", "budget": 2.0},
            classification,
        )
    )
    assert ok is False and "binding_not_granted:denied" in reason

    gate2 = _gate()
    gate2.channel = lambda req: ChannelOutcome(granted=False, detail="timeout")
    binding2, _, _ = _request(gate2)
    assert binding2.status == "timeout"


def test_expiry_refuses_and_voids() -> None:
    gate = _gate(default_ttl_seconds=-1.0)  # already expired
    binding, payload, classification = _request(gate)
    ok, reason = gate.consume(binding, **_consume_kwargs(payload, classification))
    assert ok is False and reason == "expired"


def test_one_time_consume_even_with_a_stale_copy() -> None:
    gate = _gate()
    binding, payload, classification = _request(gate)
    consume_kwargs = _consume_kwargs(payload, classification)
    ok, _ = gate.consume(binding, **consume_kwargs)
    assert ok
    # The caller kept the ORIGINAL (pre-consumption) immutable copy —
    # double-spend must still be refused.
    ok, reason = gate.consume(binding, **consume_kwargs)
    assert ok is False and "binding_not_granted:consumed" in reason


def test_cancel_and_emergency_stop() -> None:
    gate = _gate()
    binding, payload, classification = _request(gate)
    gate.cancel(binding, reason="operator changed mind")
    ok, reason = gate.consume(binding, **_consume_kwargs(payload, classification))
    assert ok is False and "binding_not_granted" in reason

    gate2 = _gate()
    gate2.emergency_stop(reason="incident")
    binding2, _, _ = _request(gate2)
    assert binding2.status == "cancelled"
    ok, reason = gate2.consume(binding2, method="POST", path="/x", action_family="form_submit",
                               capability="form_submit", identity_ref="owner",
                               preview="p", budget=1.0, tier="tier_1")
    assert ok is False and reason == "emergency_stop_active"


def test_tier0_never_prompts() -> None:
    gate = _gate()
    prompted: list[dict[str, Any]] = []

    def channel(request: dict[str, Any]) -> ChannelOutcome:
        prompted.append(request)
        return ChannelOutcome(granted=True, approver="alice")

    gate.channel = channel
    classification = classify_action(method="GET", action_family="http_read")
    binding = gate.request_approval(
        classification, method="GET", path="/", action_family="http_read",
        capability="http_read", identity_ref="anonymous", preview="GET /", budget=1.0,
    )
    assert prompted == []  # no prompt for tier 0
    assert binding.status == "granted" and binding.approver == "policy:tier_0"


# ---------------------------------------------------------------------------
# 5. Channels: notification can never grant
# ---------------------------------------------------------------------------


def test_notification_channel_cannot_grant() -> None:
    gate = _gate()
    gate.channel = lambda req: ChannelOutcome(
        granted=True, notification_only=True, approver="webhook"
    )
    binding, _, _ = _request(gate)
    assert binding.status != "granted"
    assert binding.approver == ""


# ---------------------------------------------------------------------------
# 6. Approval completes authorization — never replaces it
# ---------------------------------------------------------------------------


def test_human_approval_does_not_rescue_policy_denial() -> None:
    """With the REAL ActionAuthority: an approved request on an
    out-of-scope target is still policy-denied (approvals complete
    authorization; they do not replace it)."""
    from webpent.shared.action_authority import (
        ActionAuthority,
        ActionRequest,
        ActionRisk,
        ActionStatus,
    )

    authority = ActionAuthority(
        allowed_origin="https://in-scope.example.com",
        manifest=None,
    )
    request = ActionRequest(
        task_id="t1",
        engagement_id="eng-1",
        target_url="https://elsewhere.example.com/admin",  # OUT OF SCOPE
        method="POST",
        action_family="form_submit",
        capability="form_submit",
        risk=ActionRisk.ACTIVE,
        identity_ref="owner",
        human_approved=True,  # a human DID approve
    )
    decision = authority.evaluate(request) if hasattr(authority, "evaluate") else None
    if decision is None:  # older surface: authorize()
        decision = authority.authorize(request)
    assert decision.status != ActionStatus.AUTHORIZED
    assert any("scope" in r.lower() for r in decision.reasons)


# ---------------------------------------------------------------------------
# 7. The audit trail
# ---------------------------------------------------------------------------


def test_audit_trail_records_every_event_in_order(tmp_path) -> None:
    ledger = ApprovalLedger(tmp_path / "approvals.jsonl")
    gate = ApprovalGate(
        engagement_id="eng-audit", manifest_digest="sha256:m", ledger=ledger
    )
    gate.channel = _grant_channel()
    binding, payload, classification = _request(gate)
    gate.consume(binding, **_consume_kwargs(payload, classification))
    binding2, payload2, classification2 = _request(gate)
    gate.cancel(binding2, "done")
    gate.emergency_stop("test")

    events = [e["event"] for e in ledger.events()]
    assert events == [
        "requested", "granted", "consumed",
        "requested", "granted", "voided", "emergency_stop",
    ]
    # The persisted JSONL matches the in-memory trail.
    import json

    lines = (tmp_path / "approvals.jsonl").read_text(encoding="utf-8").strip().splitlines()
    persisted = [json.loads(line) for line in lines]
    assert [e["event"] for e in persisted] == events
    assert all("recorded_at" in e and "uuid" in e for e in persisted)
    # Per-binding trails are retrievable.
    assert len(ledger.events_for(binding.approval_id)) >= 2
