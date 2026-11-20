"""UM-DR-43 Workstream B — identity-aware hypothesis intelligence.

Pins the directive §13 contract:
  1. genuine duplicates (same security context, harmless representation
     deltas) MERGE;
  2. security-distinct hypotheses (user/tenant/object/session/auth
     strength/absence) NEVER merge, with explainable differing fields;
  3. fingerprints are stable and deterministic;
  4. every merge/keep decision carries a reason (explainability);
  5. the dedup report is bounded (no hypothesis explosion).
"""
from __future__ import annotations

from webpent.egaie.identity_scope import (
    IdentityContext,
    compare_identity_scope,
    deduplicate_hypotheses,
    from_params,
    identity_scope_key,
)
from webpent.egaie.schemas import HypothesisRecord, HypothesisStatus

_BASE_PARAMS = {
    "method": "POST",
    "actor": "user-a",
    "role": "buyer",
    "tenant": "acme",
    "object_id": "order-1001",
    "auth_strength": "mfa",
    # harmless representation noise that MUST be ignored:
    "idempotency_key": "egaie-abc123",
    "request_id": "req-9",
    "nonce": "n-1",
    "timestamp": "2026-11-20T00:00:00Z",
}


def _ctx(**overrides: object) -> IdentityContext:
    return from_params({**_BASE_PARAMS, **overrides})


def test_representation_only_changes_never_split():
    """Genuine duplicates: different param order + extra tokens +
    different method case all produce the SAME fingerprint."""
    a = from_params(_BASE_PARAMS)
    b = from_params({
        "nonce": "n-2", "request_id": "req-77", "ts": "9999",
        "correlation_id": "c-9", "method": "post",  # case-insensitive
        "actor": "user-a", "role": "buyer", "tenant": "acme",
        "object_id": "order-1001", "auth_strength": "mfa",
    })
    assert identity_scope_key(a) == identity_scope_key(b)
    decision = compare_identity_scope(a, b)
    assert decision.merge is True
    assert "identity scopes identical" in decision.reason


def test_actor_distinction_keeps_hypotheses_separate():
    decision = compare_identity_scope(_ctx(), _ctx(actor="user-b"))
    assert decision.merge is False
    assert decision.verdict == "keep_separate"
    assert decision.differing_fields == ("actor",)
    assert "actor" in decision.reason


def test_tenant_object_session_auth_distinctions():
    for changed in (
        {"tenant": "globex"},
        {"object_id": "order-1002"},
        {"session": "sess-1"},
        {"auth_strength": "password-only"},
        {"role": "admin"},
    ):
        decision = compare_identity_scope(_ctx(), _ctx(**changed))
        assert decision.merge is False, changed
        assert decision.differing_fields, changed


def test_absence_of_actor_is_itself_a_distinction():
    """Unauthenticated (no known principal) vs authenticated contexts
    must never merge — absence contributes to the fingerprint."""
    anonymous = from_params({
        "method": "GET", "tenant": "acme", "object_id": "order-1001"})
    authenticated = from_params({
        "method": "GET", "tenant": "acme", "object_id": "order-1001",
        "actor": "user-a"})
    assert compare_identity_scope(
        anonymous, authenticated).merge is False


def test_fingerprints_stable_and_deterministic():
    kwargs = dict(_BASE_PARAMS)
    assert (identity_scope_key(from_params(kwargs))
            == identity_scope_key(from_params(dict(reversed(
                list(kwargs.items()))))))
    # direct construction is stable too
    direct = IdentityContext(
        actor="user-a", tenant="acme", method="get",
        preconditions=("b", "a"))
    assert identity_scope_key(direct) == identity_scope_key(IdentityContext(
        actor="user-a", tenant="acme", method="GET",
        preconditions=("a", "b")))


def test_genuine_duplicates_merge_in_dedup():
    """Directive regression case 1: two records that differ only by
    harmless representation details merge into one, deterministically."""
    records = [
        HypothesisRecord(
            hypothesis_id="h-b", family="WORKFLOW_IDENTITY",
            statement="second intake",
            status=HypothesisStatus.PROPOSED),
        HypothesisRecord(
            hypothesis_id="h-a", family="WORKFLOW_IDENTITY",
            statement="first intake",
            status=HypothesisStatus.SUPPORTED),
    ]
    contexts = {"h-a": _ctx(), "h-b": _ctx(nonce="other")}
    report = deduplicate_hypotheses(records, contexts)
    assert report.merged_into == {"h-b": "h-a"}  # smallest id kept
    assert report.kept == ("h-a",)
    assert report.groups == 1


def test_security_distinct_hypotheses_remain_separate():
    """Directive regression case 2: same endpoint+family, different
    principal and object — MUST stay separate, explainably."""
    records = [
        HypothesisRecord(
            hypothesis_id="h-1", family="WORKFLOW_IDENTITY",
            statement="user-a on order-1001"),
        HypothesisRecord(
            hypothesis_id="h-2", family="WORKFLOW_IDENTITY",
            statement="user-b on order-1002"),
    ]
    contexts = {
        "h-1": _ctx(),
        "h-2": _ctx(actor="user-b", object_id="order-1002"),
    }
    report = deduplicate_hypotheses(records, contexts)
    assert report.merged_into == {}
    assert sorted(report.kept) == ["h-1", "h-2"]
    assert report.groups == 2
    separate = report.to_dict()["kept_separate"]
    assert separate and separate[0]["differing_fields"] == [
        "actor", "object_id"]
    assert "security contexts differ" in separate[0]["reason"]


def test_unknown_context_is_never_merged():
    """Absence of identity evidence is not evidence of equality."""
    records = [
        HypothesisRecord(
            hypothesis_id="h-1", family="PRICE_INTEGRITY",
            statement="contexted"),
        HypothesisRecord(
            hypothesis_id="h-2", family="PRICE_INTEGRITY",
            statement="no context available"),
    ]
    report = deduplicate_hypotheses(records, {"h-1": _ctx()})
    assert report.merged_into == {}
    assert report.groups == 2


def test_different_families_never_merge_even_with_same_scope():
    records = [
        HypothesisRecord(
            hypothesis_id="h-1", family="PRICE_INTEGRITY",
            statement="price"),
        HypothesisRecord(
            hypothesis_id="h-2", family="WORKFLOW_IDENTITY",
            statement="workflow"),
    ]
    contexts = {"h-1": _ctx(), "h-2": _ctx()}
    report = deduplicate_hypotheses(records, contexts)
    assert report.merged_into == {}
    assert report.groups == 2


def test_dedup_report_bounded():
    records = [
        HypothesisRecord(
            hypothesis_id=f"h-{i}", family="WORKFLOW_IDENTITY",
            statement=f"distinct actor {i}")
        for i in range(60)
    ]
    contexts = {f"h-{i}": _ctx(actor=f"user-{i}") for i in range(60)}
    report = deduplicate_hypotheses(records, contexts)
    assert len(report.kept_separate) <= 50
    assert report.groups == 60
    assert report.to_dict()["merged_count"] == 0


def test_precondition_order_does_not_split():
    a = _ctx(preconditions=("stage-1-complete", "stage-2-open"))
    b = _ctx(preconditions=("stage-2-open", "stage-1-complete"))
    assert compare_identity_scope(a, b).merge is True
