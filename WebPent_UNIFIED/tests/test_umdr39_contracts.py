"""UM-DR-39 — discovery-intelligence contract tests.

Pins the bounded RC-1/2/3 implementation:

* RC-1: the discovery funnel counts the replay/promotion shapes the
  production verifier and the AVI merge actually write (the vocabulary
  mismatch that made every campaign report zero);
* RC-2: the ``authorization_observations`` channel is DECLARED on
  PentestState with an additive reducer, the promotion-boundary
  projection writes evidence-backed observations (CausalGuard context
  only — absent values stay None, never invented), AND the channel
  survives checkpoint redaction (the "authorization" name-fragment
  blanking that erased the persisted channel in every prior run);
* RC-3: hypothesis preconditions are load-bearing — a hypothesis with
  declared-but-unsatisfied preconditions DEFERs with the named reason;
  hypotheses without preconditions keep today's semantics.
"""
from __future__ import annotations

import sys
import uuid
from typing import Any

import pytest

REPO = __file__.rsplit("/tests/", 1)[0]
sys.path.insert(0, f"{REPO}/src")
sys.path.insert(0, f"{REPO}/scripts")

from webpent.production import discovery_funnel  # noqa: E402
from webpent.production.authorization_observations import (  # noqa: E402
    build_authorization_observation,
)
from webpent.state.reducers import merge_lists  # noqa: E402
from webpent.state.state import PentestState  # noqa: E402


def _finding(evidence: dict[str, Any], **overrides) -> dict[str, Any]:
    base = {
        "id": str(uuid.uuid4()),
        "vuln_class": "auth_bypass",
        "confidence_level": "Tool-Confirmed",
        "url": "http://lab.test/api/invoices/INV-B-777",
        "evidence": evidence,
    }
    base.update(overrides)
    return base


def _chain_evidence(**replay_shape) -> dict[str, Any]:
    """Evidence carrying the COMPLETE confirmed chain in a given
    replay-vocabulary shape."""
    ev: dict[str, Any] = {
        "causal_guard": {"verdict": "CONFIRMED"},
        "proof_bundle": {"bundle_id": "b-1"},
    }
    ev.update(replay_shape)
    return ev


# ---------------------------------------------------------------------------
# RC-1 — the funnel counts the producer shapes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("replay_shape", [
    # the shape the verifier writes (verifier.py:506-508)
    {"replay_metadata": {"replay_verified": True}},
    # the shape the verifier's promotion guard writes (:533-539)
    {"promotion_guard": {"replay_verified": True}},
    # the shape the AVI merge writes (builder.py:1986)
    {"avi_replay_verified": True},
    # the legacy synthetic shape stays readable (back-compat)
    {"replay_verified": True},
    {"replay": {"verified": True}},
])
def test_funnel_counts_every_production_replay_shape(
        replay_shape: dict) -> None:
    finding = _finding(_chain_evidence(**replay_shape))
    (_awaiting, _guard, _bundle, replay, promoted, confirmed) = (
        discovery_funnel._confirmation_chain_counts([finding]))
    assert replay == 1
    assert promoted == 1
    assert confirmed == 1


def test_funnel_avi_promotion_decision_counts() -> None:
    finding = _finding(_chain_evidence(
        avi_replay_verified=True,
        avi_promotion={"decision": "PROMOTED"}))
    (_a, _g, _b, _r, promoted, confirmed) = (
        discovery_funnel._confirmation_chain_counts([finding]))
    assert promoted == 1
    assert confirmed == 1


def test_funnel_unverified_replay_still_not_confirmed() -> None:
    """The vocabulary fix never inflates: without a TRUE replay shape
    the chain stays incomplete."""
    finding = _finding({"causal_guard": {"verdict": "CONFIRMED"},
                        "proof_bundle": {"bundle_id": "b-1"},
                        "replay_metadata": {"replay_verified": False}})
    (_a, _g, _b, replay, promoted, confirmed) = (
        discovery_funnel._confirmation_chain_counts([finding]))
    assert replay == 0
    assert promoted == 0
    assert confirmed == 0


# ---------------------------------------------------------------------------
# RC-2 — the declared channel + the evidence-backed projection
# ---------------------------------------------------------------------------

def test_authorization_observations_channel_is_declared() -> None:
    """The key was previously ABSENT from PentestState — LangGraph
    silently drops undeclared keys, so no producer could ever reach
    the funnel."""
    assert "authorization_observations" in PentestState.__annotations__
    annotation = PentestState.__annotations__[
        "authorization_observations"]
    assert "merge_lists" in str(annotation)


def test_merge_lists_reducer_is_additive() -> None:
    assert merge_lists([{"a": 1}], [{"b": 2}]) == [{"a": 1}, {"b": 2}]


def _guard_diff() -> dict[str, Any]:
    return {"authorization_differential": {
        "actor_id": "User_A",
        "resource_id": "INV-B-777",
        "resource_owner": "User_B",
        "verdict": "CONFIRMED",
    }}


def test_projection_extracts_guard_context() -> None:
    finding = _finding({"causal_guard": {
        "verdict": "CONFIRMED", **_guard_diff()}})
    obs = build_authorization_observation(finding, "validator")
    assert obs is not None
    assert obs["actor_id"] == "User_A"
    assert obs["resource_owner"] == "User_B"
    assert obs["guard_verdict"] == "CONFIRMED"
    assert obs["source_node"] == "validator"
    assert obs["ownership_basis"] == (
        "CausalGuard authorization_differential context")


def test_projection_avi_context_is_used_when_present() -> None:
    finding = _finding({"causal_guard": {"verdict": "CONFIRMED"},
                        "avi_actor_id": "User_A",
                        "avi_resource_id": "INV-B-777"})
    obs = build_authorization_observation(finding, "access_control")
    assert obs is not None
    assert obs["actor_id"] == "User_A"
    assert obs["resource_id"] == "INV-B-777"
    assert obs["resource_owner"] is None  # absent -> None, never invented


def test_projection_skips_non_confirmed_findings() -> None:
    finding = _finding(_chain_evidence(replay_verified=True),
                       confidence_level="Pending")
    assert build_authorization_observation(finding, "validator") is None


def test_projection_absent_guard_leaves_nulls() -> None:
    finding = _finding({"unrelated": "evidence"})
    obs = build_authorization_observation(finding, "validator")
    assert obs is not None
    assert obs["actor_id"] is None
    assert obs["resource_owner"] is None
    assert obs["ownership_basis"] is None


def test_authorization_observations_survive_checkpoint_redaction() -> None:
    """Root cause, layer 3: the checkpoint redactor's generic
    "authorization" fragment (written for HTTP auth headers) blanked
    the ENTIRE channel at every checkpoint write — the observations
    existed in the live state and silently vanished from every
    persisted final state. The exemption preserves the channel while
    field-wise redaction still strips sensitive-keyed entries."""
    from webpent.graph.checkpoints import _redact_channel

    obs = [{"finding_id": "f1", "actor_id": "User_A",
            "resource_owner": "User_B",
            "observed_at_utc": "2026-11-17T00:00:00+00:00"}]
    assert _redact_channel("authorization_observations", obs) == obs
    poisoned = [{"finding_id": "f1", "cookie": "sess-123"}]
    out = _redact_channel("authorization_observations", poisoned)
    assert out == [{"finding_id": "f1"}]


def test_funnel_reads_real_observations_from_state() -> None:
    """End-to-end: a state carrying the projected observations makes
    the funnel's authorization_observations stage non-zero (previously
    zero forever) and the confirmed chain visible from the SAME state."""
    finding = _finding({"causal_guard": {
        "verdict": "CONFIRMED", **_guard_diff()},
        "proof_bundle": {"bundle_id": "b-1"},
        "replay_metadata": {"replay_verified": True}})
    obs = build_authorization_observation(finding, "validator")
    assert obs is not None
    state: dict[str, Any] = {
        "authorization_observations": [obs],
        "hypotheses": [],
        "findings": [finding],
    }
    funnel = discovery_funnel.build_discovery_funnel(state)
    stages = funnel["stages"]
    assert stages["authorization_observations"] == 1
    assert stages["confirmed_findings"] == 1


# ---------------------------------------------------------------------------
# RC-3 — preconditions are load-bearing
# ---------------------------------------------------------------------------

def _hypothesis(**overrides) -> Any:
    from webpent.models.hypothesis import Hypothesis

    base: dict[str, Any] = {
        "id": uuid.uuid4(),
        "statement": "The invoice endpoint returns other tenants' "
                     "objects when requested by a foreign principal.",
        "target_url": "http://lab.test/api/invoices/INV-B-777",
        "vuln_class": "idor",
        "origin": "heuristic",
        "status": "unexplored",
        "confidence_score": 0.95,
    }
    base.update(overrides)
    return Hypothesis(**base)


def test_preconditions_block_promotion_when_unsatisfied() -> None:
    from webpent.shared.prioritization import recommend_action

    h = _hypothesis(
        preconditions=["authenticated session with role X",
                       "endpoint accepts POST"])
    action, _score, rule = recommend_action(h, state={})
    assert action.value.lower() == "defer"
    assert "preconditions unverified" in rule
    assert "authenticated session with role X" in rule


def test_preconditions_satisfied_restores_normal_path() -> None:
    from webpent.shared.prioritization import recommend_action

    h = _hypothesis(
        preconditions=["authenticated session with role X"],
        preconditions_satisfied=True)
    action, _score, rule = recommend_action(h, state={})
    assert "preconditions unverified" not in rule


def test_hypothesis_without_preconditions_unchanged() -> None:
    """Zero current-behavior change: the production generator emits no
    preconditions, so today's promotions are untouched."""
    from webpent.shared.prioritization import recommend_action

    h = _hypothesis()
    _action, _score, rule = recommend_action(h, state={})
    assert "preconditions unverified" not in rule


def test_preconditions_satisfied_field_is_additive_optional() -> None:
    """Legacy constructors stay valid: the field defaults to None."""
    h = _hypothesis()
    assert h.preconditions_satisfied is None
    assert h.preconditions == []
