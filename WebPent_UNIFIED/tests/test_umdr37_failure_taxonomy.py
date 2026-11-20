"""UM-DR-37 §7 — structured failure taxonomy tests."""

from __future__ import annotations

import pytest

from webpent.research.failure_taxonomy import (
    CausalAttribution,
    FailureLedger,
    FailureStage,
    LearningEvent,
    REASON_CODES,
    apply_failure_policy,
)


def test_all_sixteen_stages_exist() -> None:
    assert len(FailureStage) == 16
    assert FailureStage.SURFACE_DISCOVERY.value == "surface_discovery"
    assert FailureStage.PROMOTION.value == "promotion"


def test_reason_codes_carry_stage_and_corrective_action() -> None:
    for code, spec in REASON_CODES.items():
        assert spec["stage"] in {stage.value for stage in FailureStage}
        assert spec["corrective_action"].strip(), code
    # the four UM-DR-37 root causes are first-class codes
    for code in ("json_manifest_unparsed", "identifier_gate_too_strict",
                 "identity_profiles_dropped",
                 "guard_inconclusive_insufficient_auth_context"):
        assert code in REASON_CODES


def test_event_requires_a_registered_reason_code() -> None:
    with pytest.raises(ValueError, match="unregistered reason code"):
        LearningEvent(
            stage=FailureStage.SURFACE_DISCOVERY,
            reason_code="llm_invented_this",
            causal_attribution=CausalAttribution.UNKNOWN,
            diagnosis_confidence=0.1,
        )


def test_event_carries_the_full_structured_record() -> None:
    event = LearningEvent(
        stage=FailureStage.IDENTITY_RESOLUTION,
        reason_code="identity_profiles_dropped",
        causal_attribution=CausalAttribution.CONFIRMED,
        diagnosis_confidence=0.95,
        entity_ids=("identity:user-b",),
        hypothesis_id="h-1",
        trace_ref="umdr37_graph_trace_before.json#stages",
        supporting_evidence=("captured kwargs lack identity_profiles",),
    )
    dump = event.to_dict()
    assert dump["corrective_action"].startswith("repair the identity")
    assert dump["causal_attribution"] == "confirmed"
    assert dump["trace_ref"].endswith("#stages")
    assert 0.0 <= dump["diagnosis_confidence"] <= 1.0


def test_confirmed_failure_defers_only_the_blocked_family() -> None:
    ledger = FailureLedger()
    ledger.record(LearningEvent(
        stage=FailureStage.IDENTITY_RESOLUTION,
        reason_code="identity_profiles_dropped",
        causal_attribution=CausalAttribution.CONFIRMED,
        diagnosis_confidence=0.95,
        trace_ref="trace:1",
    ))
    candidates = [
        ("e-ac-1", "access_control"),
        ("e-ssrf-1", "ssrf"),
        ("e-ac-2", "access_control"),
    ]
    kept, deferred = apply_failure_policy(candidates, ledger)
    assert kept == [("e-ssrf-1", "ssrf")]
    assert [d["experiment_id"] for d in deferred] == ["e-ac-1", "e-ac-2"]
    assert deferred[0]["reason_code"] == "identity_profiles_dropped"
    assert deferred[0]["corrective_action"].startswith(
        "repair the identity model")


def test_suspected_failure_never_influences_the_decision() -> None:
    """Mission §7: a failure influences the next decision ONLY when the
    evidence justifies it — suspected attribution or low diagnosis
    confidence records the event without steering anything."""
    ledger = FailureLedger()
    ledger.record(LearningEvent(
        stage=FailureStage.IDENTITY_RESOLUTION,
        reason_code="identity_profiles_dropped",
        causal_attribution=CausalAttribution.SUSPECTED,
        diagnosis_confidence=0.95,
    ))
    candidates = [("e-ac-1", "access_control"), ("e-ssrf-1", "ssrf")]
    kept, deferred = apply_failure_policy(candidates, ledger)
    assert kept == candidates
    assert deferred == []

    low_confidence = FailureLedger()
    low_confidence.record(LearningEvent(
        stage=FailureStage.IDENTITY_RESOLUTION,
        reason_code="identity_profiles_dropped",
        causal_attribution=CausalAttribution.CONFIRMED,
        diagnosis_confidence=0.4,
    ))
    kept, deferred = apply_failure_policy(candidates, low_confidence)
    assert kept == candidates
    assert deferred == []


def test_inconclusive_event_directs_a_followup_not_a_refutation() -> None:
    event = LearningEvent(
        stage=FailureStage.SECURITY_ORACLE,
        reason_code="experiment_inconclusive",
        causal_attribution=CausalAttribution.CONFIRMED,
        diagnosis_confidence=0.8,
        hypothesis_id="h-9",
    )
    assert event.corrective_action.startswith(
        "generate a more discriminating follow-up")
    # and it blocks no family (it is guidance, not a gate)
    ledger = FailureLedger()
    ledger.record(event)
    assert ledger.blocking_family() is None


def test_ledger_bounded_and_counted() -> None:
    ledger = FailureLedger(max_events=10)
    for index in range(14):
        ledger.record(LearningEvent(
            stage=FailureStage.OBSERVATION_PARSING,
            reason_code="observation_unparseable",
            causal_attribution=CausalAttribution.UNKNOWN,
            diagnosis_confidence=0.1,
            trace_ref=f"trace:{index}",
        ))
    assert len(ledger.events) <= 10
    dump = ledger.to_dict()
    assert dump["attribution_counts"]["unknown"] == len(ledger.events)
    assert dump["influencing_events"] == 0
