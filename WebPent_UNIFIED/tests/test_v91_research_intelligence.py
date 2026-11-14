from webpent.shared.research_intelligence import (
    ActionClass,
    GapStatus,
    InformationAction,
    KnowledgeGapEngine,
    NegativeEvidence,
    NegativeEvidenceLedger,
    PositiveEvidence,
    ResearchSession,
    SmartNextBestActionEngine,
)


def test_missing_ownership_fact_creates_owner_and_denial_actions():
    engine = KnowledgeGapEngine()
    gaps = engine.derive(
        {
            "crawled_data": {"urls": ["http://127.0.0.1:8000/user_profile/1"]},
            "relational_evidence": [],
            "authorization_matrix": {},
        }
    )

    assert gaps
    gap = engine.choose(gaps)
    assert gap is not None
    assert gap.kind.value == "ownership"
    assert {action.action_class for action in gap.candidate_actions} == {
        ActionClass.IDENTITY_ACQUISITION,
        ActionClass.NEGATIVE_CONTROL,
    }

    resolved = engine.resolve(
        gap,
        supporting_evidence=["owner_context_acquired"],
        contradicting_evidence=["foreign_identity_denied"],
    )
    assert resolved.status == GapStatus.RESOLVED
    assert "owner_context_acquired" in resolved.supporting_evidence
    assert "foreign_identity_denied" in resolved.contradicting_evidence


def test_smart_nba_penalizes_repeated_action_without_new_evidence():
    action = InformationAction(
        action_id="action:owner",
        action_class=ActionClass.IDENTITY_ACQUISITION,
        objective="acquire owner context",
        target_ref="http://127.0.0.1:8000/user_profile/1",
        expected_information_gain=0.9,
        cost=1.0,
    )
    engine = SmartNextBestActionEngine()
    first = engine.score(action, likelihood=0.8, impact=0.8, evidence_potential=0.9)
    repeated = engine.score(
        action,
        likelihood=0.8,
        impact=0.8,
        evidence_potential=0.9,
        attempted_fingerprints=[action.fingerprint()],
    )
    justified = engine.score(
        action,
        likelihood=0.8,
        impact=0.8,
        evidence_potential=0.9,
        attempted_fingerprints=[action.fingerprint()],
        new_evidence=True,
    )

    assert first.score > repeated.score
    assert justified.score == first.score
    assert "duplicate_without_new_evidence_penalty" in repeated.reasons


def test_research_session_records_negative_knowledge_without_raw_secret():
    session = ResearchSession.from_state(
        {"engagement_id": "engagement-a", "client_id": "client-a", "thread_id": "thread-a"}
    )
    action = InformationAction(
        action_id="action:denial",
        action_class=ActionClass.NEGATIVE_CONTROL,
        objective="foreign denial baseline",
        target_ref="http://127.0.0.1:8000/user_profile/1?token=secret-value",
        expected_information_gain=0.7,
    )
    ranked = SmartNextBestActionEngine().score(action)
    session.record_action(ranked, outcome="executed")
    evidence = NegativeEvidence(
        evidence_id="negative:1",
        hypothesis_id="hypothesis:idor",
        action_fingerprint=action.fingerprint(),
        identity_context="foreign",
        tenant_context="tenant-a",
        method="GET",
        workflow_state="baseline",
        reason="foreign identity received 403",
        confidence=0.9,
    )
    session.record_negative(evidence)
    payload = session.as_dict()

    assert payload["engagement_id"] == "engagement-a"
    assert payload["client_id"] == "client-a"
    assert "secret-value" not in str(payload)
    assert "negative:1" in payload["contradicting_evidence"]
    assert payload["next_best_actions"][0]["outcome"] == "executed"


def test_negative_evidence_ledger_enforces_scope_and_explicit_transfer():
    ledger = NegativeEvidenceLedger()
    base = NegativeEvidence(
        evidence_id="negative:scoped",
        hypothesis_id="hypothesis:idor",
        action_fingerprint="action:foreign",
        identity_context="foreign",
        tenant_context="tenant-a",
        method="GET",
        workflow_state="foreign-control",
        reason="foreign identity was denied",
        confidence=0.9,
        client_id="client-a",
        engagement_id="engagement-a",
        reusable_if=("same_client_cross_engagement",),
    )
    assert ledger.record(base) is True
    assert len(
        ledger.reusable_for(
            action_fingerprint="action:foreign",
            client_id="client-a",
            engagement_id="engagement-b",
        )
    ) == 1
    assert ledger.reusable_for(
        action_fingerprint="action:foreign",
        client_id="client-b",
        engagement_id="engagement-b",
    ) == []

    no_transfer = NegativeEvidence(
        **{**base.__dict__, "evidence_id": "negative:no-transfer", "reusable_if": ()}
    )
    isolated = NegativeEvidenceLedger()
    assert isolated.record(no_transfer) is True
    assert isolated.reusable_for(
        action_fingerprint="action:foreign",
        client_id="client-a",
        engagement_id="engagement-b",
    ) == []


def test_research_session_keeps_positive_and_negative_memory_separate():
    session = ResearchSession.from_state(
        {"engagement_id": "engagement-a", "client_id": "client-a"}
    )
    positive = PositiveEvidence(
        evidence_id="positive:1",
        hypothesis_id="hypothesis:idor",
        action_fingerprint="action:owner",
        identity_context="owner",
        tenant_context="tenant-a",
        method="GET",
        workflow_state="owner-baseline",
        reason="owner resource returned a stable object reference",
        confidence=0.8,
    )
    negative = NegativeEvidence(
        evidence_id="negative:1",
        hypothesis_id="hypothesis:idor",
        action_fingerprint="action:foreign",
        identity_context="foreign",
        tenant_context="tenant-a",
        method="GET",
        workflow_state="foreign-control",
        reason="foreign identity was denied",
        confidence=0.9,
    )

    session.record_positive(positive)
    session.record_negative(negative)
    payload = session.as_dict()

    assert payload["supporting_evidence"] == ["positive:1"]
    assert payload["promising_paths"] == ["action:owner"]
    assert payload["contradicting_evidence"] == ["negative:1"]
    assert payload["failed_paths"] == ["action:foreign"]
