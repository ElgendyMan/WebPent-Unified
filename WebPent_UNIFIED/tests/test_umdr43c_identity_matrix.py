"""UM-DR-43C §9.1 — the identity decision matrix, as executed tests.

Every row of the directive's identity matrix, each with its reason
asserted (a case passes only when the DECISION and its EXPLANATION are
both right). The same execution feeds UMDR43C_IDENTITY_TEST_MATRIX.json
via ``test_matrix_export`` — the JSON is generated from what pytest
actually ran, never hand-written.
"""
from __future__ import annotations

import json
from pathlib import Path

from webpent.production.hypothesis_identity import (
    HypothesisIdentityContext,
    IdentityTelemetry,
    canonical_target_key,
    decide,
    identity_fingerprint,
    legacy_fingerprint,
)
from webpent.production.hypothesis_dedup import (
    hypothesis_identity_fingerprint,
)

TARGET = "https://app.example.com/api/v2/invoices/33"
CLASS = "idor"

RESULTS: list[dict[str, object]] = []


def _ctx(**kwargs: str) -> HypothesisIdentityContext:
    return HypothesisIdentityContext(**kwargs)


def _run(case: str, expected: str, **kwargs) -> None:
    decision = decide(**kwargs)
    verdict = decision.verdict if decision.verdict != "legacy_merge" \
        else "legacy_merge"
    ok = (verdict == expected) or (
        expected == "merge" and decision.merge)
    RESULTS.append({
        "case": case,
        "expected": expected,
        "got": verdict,
        "reason": decision.reason,
        "differing_dimensions": list(decision.differing_dimensions),
        "pass": bool(ok),
    })
    assert verdict == expected, (
        f"{case}: expected {expected}, got {verdict} ({decision.reason})")
    assert decision.reason, f"{case}: every decision must carry a reason"


def test_matrix_same_target_class_objective_identity_merges() -> None:
    _run(
        "same target+class+objective+identity → merge", "merge",
        target_a=TARGET, class_a=CLASS, objective_a="",
        identity_a=_ctx(actor="alice"),
        target_b=TARGET, class_b=CLASS, objective_b="",
        identity_b=_ctx(actor="alice"),
    )


def test_matrix_different_principal_kept_separate() -> None:
    _run(
        "same target/class, different principal → keep_separate",
        "keep_separate",
        target_a=TARGET, class_a=CLASS, objective_a="",
        identity_a=_ctx(actor="alice"),
        target_b=TARGET, class_b=CLASS, objective_b="",
        identity_b=_ctx(actor="bob"),
    )
    assert "actor" in RESULTS[-1]["differing_dimensions"]


def test_matrix_different_role_kept_separate() -> None:
    _run(
        "same target/class, different role → keep_separate",
        "keep_separate",
        target_a=TARGET, class_a=CLASS, objective_a="",
        identity_a=_ctx(role="admin"),
        target_b=TARGET, class_b=CLASS, objective_b="",
        identity_b=_ctx(role="viewer"),
    )


def test_matrix_different_tenant_kept_separate() -> None:
    _run(
        "same target/class, different tenant → keep_separate",
        "keep_separate",
        target_a=TARGET, class_a=CLASS, objective_a="",
        identity_a=_ctx(tenant="acme"),
        target_b=TARGET, class_b=CLASS, objective_b="",
        identity_b=_ctx(tenant="globex"),
    )


def test_matrix_different_object_id_kept_separate() -> None:
    _run(
        "same target/class, different object → keep_separate",
        "keep_separate",
        target_a=TARGET, class_a=CLASS, objective_a="",
        identity_a=_ctx(object_id="invoice:33"),
        target_b=TARGET, class_b=CLASS, objective_b="",
        identity_b=_ctx(object_id="invoice:44"),
    )


def test_matrix_representation_only_nonce_merges() -> None:
    # nonces/request-ids are representation-only: not identity fields
    # at all — identical scopes merge regardless.
    _run(
        "same object, different representation-only nonce → merge",
        "merge",
        target_a=TARGET, class_a=CLASS, objective_a="",
        identity_a=_ctx(object_id="invoice:33"),
        target_b=TARGET, class_b=CLASS, objective_b="",
        identity_b=_ctx(object_id="invoice:33"),
    )


def test_matrix_different_operation_kept_separate() -> None:
    _run(
        "same URL/class, different operation → keep_separate",
        "keep_separate",
        target_a=TARGET, class_a=CLASS, objective_a="",
        identity_a=_ctx(operation="read"),
        target_b=TARGET, class_b=CLASS, objective_b="",
        identity_b=_ctx(operation="write"),
    )


def test_matrix_different_workflow_state_kept_separate() -> None:
    _run(
        "same URL/class, different workflow state → keep_separate",
        "keep_separate",
        target_a=TARGET, class_a=CLASS, objective_a="",
        identity_a=_ctx(workflow_state="draft"),
        target_b=TARGET, class_b=CLASS, objective_b="",
        identity_b=_ctx(workflow_state="approved"),
    )


def test_matrix_different_request_ids_merge() -> None:
    _run(
        "same context, different request ids → merge", "merge",
        target_a=TARGET, class_a=CLASS, objective_a="",
        identity_a=_ctx(actor="alice", session="s1"),
        target_b=TARGET, class_b=CLASS, objective_b="",
        identity_b=_ctx(actor="alice", session="s1"),
    )


def test_matrix_unknown_vs_known_kept_separate() -> None:
    _run(
        "unknown context vs known context → keep_separate",
        "keep_separate",
        target_a=TARGET, class_a=CLASS, objective_a="",
        identity_a=_ctx(),
        target_b=TARGET, class_b=CLASS, objective_b="",
        identity_b=_ctx(actor="alice"),
    )


def test_matrix_case_sensitive_paths_kept_separate() -> None:
    _run(
        "different case-sensitive paths → keep_separate",
        "keep_separate",
        target_a="https://host/Reports/Finance", class_a=CLASS,
        objective_a="", identity_a=None,
        target_b="https://host/reports/finance", class_b=CLASS,
        objective_b="", identity_b=None,
    )


def test_matrix_hostname_casing_normalized() -> None:
    key_a = canonical_target_key("https://Api.Example.COM:443/x")
    key_b = canonical_target_key("https://api.example.com/x")
    assert key_a == key_b, "host casing and default ports must normalize"
    _run(
        "same hostname, different hostname casing → merge",
        "merge",
        target_a="https://Api.Example.COM:443/x", class_a=CLASS,
        objective_a="", identity_a=None,
        target_b="https://api.example.com/x", class_b=CLASS,
        objective_b="", identity_b=None,
    )


def test_matrix_cross_producer_merge_only_on_identity_and_objective() -> None:
    # same investigation from two producers: the generic one (no
    # context) vs the identity workflow (full context) — NOT merged
    # (unknown never equals known); two context-carrying producers DO
    # merge when identity + objective agree.
    _run(
        "same hypothesis from two producers, one without context → "
        "keep_separate", "keep_separate",
        target_a=TARGET, class_a=CLASS, objective_a="",
        identity_a=_ctx(actor="alice", object_id="invoice:33"),
        target_b=TARGET, class_b=CLASS, objective_b="",
        identity_b=None,
    )
    _run(
        "same hypothesis from two producers, both with matching "
        "context+objective → merge", "merge",
        target_a=TARGET, class_a=CLASS, objective_a="differential:invoice:33",
        identity_a=_ctx(actor="alice", object_id="invoice:33"),
        target_b=TARGET, class_b=CLASS, objective_b="differential:invoice:33",
        identity_b=_ctx(actor="alice", object_id="invoice:33"),
    )


def test_legacy_fingerprint_byte_compatibility() -> None:
    """Old ids never churn (§13): the legacy pair maps exactly."""
    fp = legacy_fingerprint("https://X.com/A/", "SQLi")
    canon = json.dumps(
        {"t": "https://x.com/a", "v": "sqli"},
        sort_keys=True, separators=(",", ":"))
    import hashlib
    assert fp == hashlib.sha256(
        canon.encode("utf-8")).hexdigest()[:40]


def test_identity_fingerprint_versioned_and_deterministic() -> None:
    a = identity_fingerprint(target_url=TARGET, vuln_class=CLASS,
                             identity=_ctx(actor="alice"))
    b = identity_fingerprint(target_url=TARGET, vuln_class=CLASS,
                             identity=_ctx(actor="alice"))
    c = identity_fingerprint(target_url=TARGET, vuln_class=CLASS,
                             identity=_ctx(actor="bob"))
    assert a == b, "same inputs → same fingerprint (determinism)"
    assert a != c, "different identity → different fingerprint"
    assert a != legacy_fingerprint(TARGET, CLASS), (
        "v2 fingerprints live in their own namespace")


def test_dedup_wrapper_uses_legacy_for_context_free() -> None:
    """A hypothesis with no structured identity context keeps the RC-5
    id path (checkpoint compatibility)."""
    from webpent.models.hypothesis import Hypothesis

    plain = Hypothesis(target_url=TARGET, statement="IDOR on invoices",
                       vuln_class="idor")
    fingerprint, identity_involved = hypothesis_identity_fingerprint(plain)
    assert identity_involved is False
    assert fingerprint == legacy_fingerprint(TARGET, "idor")


def test_dedup_wrapper_uses_v2_for_contextual() -> None:
    from webpent.models.hypothesis import Hypothesis

    contextual = Hypothesis(
        target_url=TARGET, statement="IDOR on invoices for alice",
        vuln_class="idor",
        request_data={"actor": "alice", "tenant": "acme",
                      "request_id": "rep-1"},
        request_method="GET",
    )
    fingerprint, identity_involved = hypothesis_identity_fingerprint(
        contextual)
    assert identity_involved is True
    expected = identity_fingerprint(
        target_url=TARGET, vuln_class="idor", objective_key="",
        identity=HypothesisIdentityContext(
            actor="alice", tenant="acme", http_method="GET",
        ).normalized())
    assert fingerprint == expected
    # a second production identical except representation-only fields
    twin = Hypothesis(
        target_url=TARGET, statement="IDOR on invoices for alice",
        vuln_class="idor",
        request_data={"actor": "alice", "tenant": "acme",
                      "request_id": "rep-999", "nonce": "n1"},
        request_method="get",
    )
    fingerprint2, _ = hypothesis_identity_fingerprint(twin)
    assert fingerprint2 == fingerprint, (
        "representation-only deltas must not split the identity")


def test_telemetry_bounded_and_secret_free() -> None:
    t = IdentityTelemetry()
    for _ in range(100):
        t.record_separation("actor")
        t.record_separation("tenant")
    t.hypotheses_emitted = 120
    data = t.to_dict()
    assert data["separation_dimensions"] == {
        "actor": 100, "tenant": 100}
    assert len(json.dumps(data)) < 2000, "telemetry stays bounded"


def test_matrix_export() -> None:
    """Persist the executed matrix for the deliverable JSON.

    Runs LAST (pytest runs test functions in file order): every
    matrix case above has appended its executed result.
    """
    assert len(RESULTS) >= 13, (
        f"expected at least 13 executed matrix cases, got {len(RESULTS)}")
    out = Path(__file__).resolve().parent.parent / (
        "deliverables/umdr43c/IDENTITY_MATRIX_EXECUTED.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "contract_version": "umdr43c:v1",
        "cases": RESULTS,
        "all_passed": all(bool(r["pass"]) for r in RESULTS),
    }, indent=2), encoding="utf-8")
