"""UM-DR-37 §10 — component influence: enabled vs ablated, decision must
change.

Three NEW in-process influence checks (identity binding, evidence-gated
failure policy, family-profile reasoning gates) plus the verified
INFLUENCE_REGISTRY that maps every mission component to the existing
suite that demonstrates its influence. A component that executes but
has no measurable influence must never be described as an effective
intelligence capability — the registry makes each claim point at real
evidence.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from webpent.research.failure_taxonomy import (
    CausalAttribution,
    FailureLedger,
    FailureStage,
    LearningEvent,
    apply_failure_policy,
)
from webpent.research.family_profiles import (
    FAMILY_PROFILES,
    families_for_entity,
)
from webpent.shared.bac_identity_tester import (
    IdentityProfile,
    assess_access_control,
    sanitise_probe_result,
)

ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# 1. Identity graph influence: the SAME probe evidence yields a
#    candidate differential only when the identity/ownership binding is
#    recorded (the RC-3/RC-4 influence in-process).
# ---------------------------------------------------------------------------

def _probe_rows() -> list[dict]:
    return [
        sanitise_probe_result(
            profile=IdentityProfile(name="alice", role="user"),
            url="http://lab.local/orders/1001", status_code=200,
            content_length=42),
        sanitise_probe_result(
            profile=IdentityProfile(name="bob", role="user"),
            url="http://lab.local/orders/1001", status_code=200,
            content_length=42),
        sanitise_probe_result(
            profile=IdentityProfile(name="anonymous", role="anonymous"),
            url="http://lab.local/orders/1001", status_code=403,
            content_length=0),
    ]


def test_identity_binding_changes_the_assessment_outcome() -> None:
    """Component: identity graph. Identical observations, the only
    difference is the recorded owner binding — the assessment outcome
    changes from review-only to a verified differential candidate."""
    without_owner = assess_access_control(_probe_rows())
    with_owner = assess_access_control(_probe_rows(), owner_identity="alice")
    assert without_owner["status"] in {"needs_review", "coverage_gap"}
    assert with_owner["status"] == "confirmed"
    assert with_owner["candidate_result"] is True
    assert with_owner["confidence_level"] == \
        "Identity-Differential-Verified"


# ---------------------------------------------------------------------------
# 2. Feedback/learning influence: a CONFIRMED failure event changes the
#    next candidate selection (suspected failures must not).
# ---------------------------------------------------------------------------

def test_confirmed_failure_event_changes_next_selection() -> None:
    candidates = [("e-ac-1", "access_control"), ("e-ssrf-1", "ssrf")]
    clean = apply_failure_policy(candidates, FailureLedger())
    assert clean[0] == candidates  # nothing deferred without a failure

    ledger = FailureLedger()
    ledger.record(LearningEvent(
        stage=FailureStage.IDENTITY_RESOLUTION,
        reason_code="identity_profiles_dropped",
        causal_attribution=CausalAttribution.CONFIRMED,
        diagnosis_confidence=0.95, trace_ref="umdr37_graph_trace_before"))
    kept, deferred = apply_failure_policy(candidates, ledger)
    assert kept == [("e-ssrf-1", "ssrf")]          # selection CHANGED
    assert deferred[0]["experiment_id"] == "e-ac-1"
    assert deferred[0]["corrective_action"].startswith(
        "repair the identity model")


# ---------------------------------------------------------------------------
# 3. Multi-family reasoning influence: the family profiles gate which
#    families may even reason about an entity — the reasoning surface
#    changes with the appmodel's entity kinds.
# ---------------------------------------------------------------------------

def test_family_profiles_gate_reasoning_by_entity() -> None:
    identity_only = families_for_entity("identity")
    endpoint_only = families_for_entity("endpoint")
    assert "broken_access_control" in identity_only
    assert "injection" not in identity_only          # needs endpoints
    assert set(endpoint_only) >= {
        "broken_access_control", "injection",
        "cross_site_scripting", "server_side_request_forgery",
        "security_misconfiguration", "sensitive_information_disclosure"}
    # SSRF requires a workflow/fetch context, not just any endpoint
    assert "server_side_request_forgery" in families_for_entity("workflow")


# ---------------------------------------------------------------------------
# The verified influence registry — every component points at the real
# evidence (existing suite or artifact) that demonstrates its influence.
# ---------------------------------------------------------------------------

INFLUENCE_REGISTRY = {
    "appmodel": {
        "demonstrates": "ownership research hints change hypothesis "
                        "priority and AVI experiment selection order",
        "evidence": "tests/test_umdr36_appmodel_influence.py",
    },
    "identity_graph": {
        "demonstrates": "identity/ownership binding flips the "
                        "assessment outcome (in-process above)",
        "evidence": "tests/test_umdr37_component_influence.py + "
                    "tests/test_v11_bac_identity.py",
    },
    "knowledge_graph": {
        "demonstrates": "appmodel -> attack-graph projection feeds "
                        "hypothesis generation surfaces",
        "evidence": "tests/test_m3_appmodel.py + "
                    "tests/test_umdr36_appmodel_influence.py",
    },
    "hypothesis_ranking": {
        "demonstrates": "appmodel hint boost reorders the hypothesis "
                        "pool (bounded +0.10)",
        "evidence": "tests/test_umdr36_appmodel_influence.py",
    },
    "information_gain": {
        "demonstrates": "evidence/repetition/state-record terms change "
                        "selector scores and flip selections",
        "evidence": "tests/test_umdr37_learning_ablation.py",
    },
    "feedback_learning": {
        "demonstrates": "full loop: evidence channels reorder execution "
                        "under an identical budget (ground truth "
                        "reached only in evidence-carrying arms)",
        "evidence": "docs/UMDR37_FULL_LOOP_LEARNING.json + "
                    "tests/test_umdr31_campaign_e2e_ablation.py",
    },
    "stateful_discovery": {
        "demonstrates": "session/state continuity across experiments "
                        "changes what later experiments can reach",
        "evidence": "tests/test_umdr28_campaign_stateful_e2e.py",
    },
    "multi_family": {
        "demonstrates": "per-family evidence channels reorder execution "
                        "and change which families' cases confirm first",
        "evidence": "tests/test_umdr31_campaign_e2e_ablation.py "
                    "(4-arm matrix)",
    },
}


@pytest.mark.parametrize("component", sorted(INFLUENCE_REGISTRY))
def test_every_component_influence_is_evidenced(component: str) -> None:
    entry = INFLUENCE_REGISTRY[component]
    assert entry["demonstrates"], component
    for token in entry["evidence"].replace(",", " ").split():
        if "/" not in token:
            continue  # prose notes, not paths
        candidate = ROOT / token
        assert candidate.exists(), f"{component}: missing evidence {token}"


def test_registry_covers_all_eight_components() -> None:
    assert set(INFLUENCE_REGISTRY) == {
        "appmodel", "identity_graph", "knowledge_graph",
        "hypothesis_ranking", "information_gain", "feedback_learning",
        "stateful_discovery", "multi_family",
    }
