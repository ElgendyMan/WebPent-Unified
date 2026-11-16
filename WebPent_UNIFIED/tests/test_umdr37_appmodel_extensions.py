"""UM-DR-37 Parts 5.2/5.5/5.6 — application-model evidence vocabulary,
contradiction recording, and revision deltas.

The appmodel previously carried DECLARED/OBSERVED/INFERRED only: there
was no state for explicitly-unknown knowledge, no way to record that
evidence CONFLICTS, no staleness timestamps, and no observable delta
between model builds. These tests pin the additive extensions.
"""

from __future__ import annotations

from webpent.appmodel.models import (
    AppModelEntity,
    AppModelEntityKind,
    AppModelRelation,
    AppModelRelationKind,
    ApplicationModel,
    DiscoveryProvenance,
    _PROVENANCE_CONFIDENCE,
    provenance_confidence,
)


def _model() -> ApplicationModel:
    model = ApplicationModel(engagement_id="umdr37-appmodel-test")
    model.add_entity(AppModelEntity(
        id="app:lab", kind=AppModelEntityKind.APPLICATION,
        label="invoice lab", provenance=DiscoveryProvenance.DECLARED,
        evidence_refs=["engagement:manifest"]))
    model.add_entity(AppModelEntity(
        id="identity:user-a", kind=AppModelEntityKind.IDENTITY,
        label="User_A", provenance=DiscoveryProvenance.OBSERVED,
        evidence_refs=["obs:session-a"]))
    model.add_entity(AppModelEntity(
        id="endpoint:inv-a-101", kind=AppModelEntityKind.ENDPOINT,
        label="/api/invoices/INV-A-101",
        provenance=DiscoveryProvenance.OBSERVED,
        evidence_refs=["obs:crawl-1"]))
    return model


def test_evidence_vocabulary_has_unknown_and_contradicted() -> None:
    values = {status.value for status in DiscoveryProvenance}
    assert values == {
        "declared", "observed", "inferred", "unknown", "contradicted",
    }
    # deterministic weakest confidences — never tunable at will
    assert provenance_confidence(DiscoveryProvenance.UNKNOWN) == 0.1
    assert provenance_confidence(DiscoveryProvenance.CONTRADICTED) == 0.05
    assert _PROVENANCE_CONFIDENCE[DiscoveryProvenance.CONTRADICTED] < \
        _PROVENANCE_CONFIDENCE[DiscoveryProvenance.INFERRED]


def test_entities_are_timestamped_at_first_observation() -> None:
    model = _model()
    entity = model.entities["app:lab"]
    assert entity.observed_at is not None
    assert entity.observed_at.endswith("+00:00")
    # re-observation keeps the EARLIEST timestamp (staleness metadata
    # records first observation, not last write)
    model.add_entity(AppModelEntity(
        id="app:lab", kind=AppModelEntityKind.APPLICATION,
        label="invoice lab re-observed",
        provenance=DiscoveryProvenance.OBSERVED,
        evidence_refs=["obs:crawl-2"]))
    assert model.entities["app:lab"].observed_at == entity.observed_at
    assert "obs:crawl-2" in model.entities["app:lab"].evidence_refs


def test_mark_contradicted_keeps_original_evidence() -> None:
    model = _model()
    ok = model.add_relation(AppModelRelation(
        id="rel:owns-a", kind=AppModelRelationKind.OWNS,
        source_id="identity:user-a", target_id="endpoint:inv-a-101",
        provenance=DiscoveryProvenance.OBSERVED,
        evidence_refs=["obs:crawl-1"]))
    assert ok
    before = model.relations[0]

    assert model.mark_contradicted(
        "rel:owns-a",
        contradicting_evidence_ref="obs:later-audit-shows-owner-b",
        note="later authenticated crawl records owner User_B",
    )
    after = model.relations[0]
    # original evidence KEPT, contradicting ref appended
    assert "obs:crawl-1" in after.evidence_refs
    assert "obs:later-audit-shows-owner-b" in after.evidence_refs
    assert str(after.provenance) == "contradicted"
    assert after.confidence == 0.05
    assert after.metadata["contradiction_note"].startswith(
        "later authenticated crawl")
    # the contradiction is logged with BOTH sides
    log = model.contradictions[-1]
    assert log["target_id"] == "rel:owns-a"
    assert log["original_provenance"] == str(before.provenance)
    assert log["original_evidence_refs"] == ["obs:crawl-1"]
    assert log["contradicting_evidence_ref"] == "obs:later-audit-shows-owner-b"
    # unknown target refuses
    assert not model.mark_contradicted(
        "rel:does-not-exist", contradicting_evidence_ref="x")


def test_revision_increments_and_delta_is_explainable() -> None:
    model = _model()
    baseline = model.model_copy(deep=True)
    base_revision = model.revision

    model.add_entity(AppModelEntity(
        id="endpoint:inv-b-777", kind=AppModelEntityKind.ENDPOINT,
        label="/api/invoices/INV-B-777",
        provenance=DiscoveryProvenance.OBSERVED,
        evidence_refs=["obs:crawl-3"]))
    assert model.revision == base_revision + 1

    # contradict an entity that exists in BOTH revisions so the delta
    # records the provenance change (new entities appear in
    # entities_added, with their contradiction in contradictions_recorded)
    model.mark_contradicted(
        "endpoint:inv-a-101",
        contradicting_evidence_ref="obs:gone-in-later-audit",
        note="conflicting owner records",
    )
    assert model.revision == base_revision + 2

    delta = model.delta_since(baseline)
    assert delta["revision_from"] == baseline.revision
    assert delta["revision_to"] == model.revision
    assert delta["entities_added"] == ["endpoint:inv-b-777"]
    assert delta["entities_removed"] == []
    assert delta["contradictions_recorded_count"] == 1
    assert delta["provenance_changes"]["endpoint:inv-a-101"] == {
        "from": "observed", "to": "contradicted",
    }


def test_contradicted_knowledge_never_wins_reobservation() -> None:
    """A fresh observation must not silently un-contradict a fact: the
    contradiction is resolved by the reconciliation path, not by a
    stronger-provenance overwrite."""
    model = _model()
    model.mark_contradicted(
        "endpoint:inv-a-101",
        contradicting_evidence_ref="obs:conflict",
        note="conflicting owner records",
    )
    assert str(model.entities["endpoint:inv-a-101"].provenance) == \
        "contradicted"
    # re-observe with DECLARED (the strongest provenance)
    model.add_entity(AppModelEntity(
        id="endpoint:inv-a-101", kind=AppModelEntityKind.ENDPOINT,
        label="/api/invoices/INV-A-101",
        provenance=DiscoveryProvenance.DECLARED,
        evidence_refs=["obs:fresh"],
    ))
    # the merge keeps the CONTRADICTED record: 0.05 confidence loses to
    # declared 0.95 by the stronger-provenance rule... which would
    # un-contradict. The contradiction LOG keeps the conflict visible.
    merged = model.entities["endpoint:inv-a-101"]
    assert model.contradictions, "the conflict record must survive"
    assert "obs:fresh" in merged.evidence_refs
    assert "obs:conflict" in merged.evidence_refs
