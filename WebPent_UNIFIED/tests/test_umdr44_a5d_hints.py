"""UM-DR-44 A5d — hints carry their derivation revision (RED on 6f3dc7c).

``build_appmodel_research_hints`` emits hints carrying subject +
evidence_refs but NO model_revision — a hint derived before newer
observations is indistinguishable from current truth.

Contract (4 tests): every hint carries model_revision equal to the
model's revision at derivation time; ownership-hint locators resolve to
REAL entities (endpoint_id + owner_identity_ids + evidence refs from
those entities); staleness is detectable (derive → observe → the old
hint's revision is now smaller than the model's); advisory_only stays
True and the hint set stays bounded at 128.
"""

from __future__ import annotations

from webpent.appmodel.builder import build_appmodel_research_hints
from webpent.appmodel.models import (
    ApplicationModel,
    AppModelEntity,
    AppModelEntityKind,
    AppModelRelation,
    AppModelRelationKind,
    DiscoveryProvenance,
)


def _model_with_ownership() -> ApplicationModel:
    m = ApplicationModel()
    m.add_entity(AppModelEntity(
        id="ep-1", kind=AppModelEntityKind.ENDPOINT,
        label="endpoint:ep-1", provenance=DiscoveryProvenance.OBSERVED,
        evidence_refs=["ev-ep"], metadata={"path": "/orders"}))
    m.add_entity(AppModelEntity(
        id="id-owner", kind=AppModelEntityKind.IDENTITY,
        label="identity:id-owner", provenance=DiscoveryProvenance.OBSERVED,
        evidence_refs=["ev-id"]))
    m.add_relation(AppModelRelation(
        id="rel-own", kind=AppModelRelationKind.OWNS,
        source_id="id-owner", target_id="ep-1",
        evidence_refs=["ev-own"]))
    return m


class TestHintRevision:
    def test_every_hint_carries_model_revision(self) -> None:
        """RED on the base: hints have no model_revision key at all."""
        model = _model_with_ownership()
        hints = build_appmodel_research_hints(model)
        assert hints, "fixture must produce at least one hint"
        for hint_id, hint in hints.items():
            assert hint.get("model_revision") == model.revision, (
                f"{hint_id}: hint must record the model revision it was "
                f"derived from (model is at {model.revision})"
            )

    def test_ownership_hint_locators_resolve(self) -> None:
        model = _model_with_ownership()
        hints = build_appmodel_research_hints(model)
        ownership = [
            h for h in hints.values()
            if h.get("kind") == "object_ownership_boundary"]
        assert ownership, "fixture must produce an ownership hint"
        subject = ownership[0]["subject"]
        assert subject["endpoint_id"] in model.entities
        for owner_id in subject["owner_identity_ids"]:
            assert owner_id in model.entities
        # evidence refs trace to the entities' own recorded refs
        endpoint_refs = set(model.entities[subject["endpoint_id"]].ref_list())
        assert set(ownership[0]["evidence_refs"]) <= endpoint_refs

    def test_staleness_is_detectable(self) -> None:
        """Derive a hint, then apply a newer observation — the OLD
        hint's revision must be recognizable as smaller than the
        model's current revision."""
        model = _model_with_ownership()
        hints_at_derivation = build_appmodel_research_hints(model)
        revision_at_derivation = model.revision
        # a newer observation moves the model forward
        model.apply_observation(
            {"url": "https://api.example.com/orders/99",
             "method": "GET", "evidence_ref": "req-new"})
        assert model.revision > revision_at_derivation
        for hint in hints_at_derivation.values():
            assert hint["model_revision"] < model.revision, (
                "a hint derived before newer observations must be "
                "recognizable as stale (model_revision < model.revision)"
            )

    def test_advisory_and_bounded_unchanged(self) -> None:
        model = _model_with_ownership()
        hints = build_appmodel_research_hints(model)
        for hint in hints.values():
            assert hint.get("advisory_only") is True
            assert hint.get("source") == "appmodel"
        # the 128 bound is structural — a model with many facts cannot
        # exceed it
        from webpent.appmodel.builder import _MAX_HINTS
        assert len(hints) <= _MAX_HINTS
        big = _model_with_ownership()
        for i in range(400):
            big.add_entity(AppModelEntity(
                id=f"ep-many-{i}", kind=AppModelEntityKind.ENDPOINT,
                label=f"endpoint:ep-many-{i}"[:160],
                provenance=DiscoveryProvenance.OBSERVED,
                evidence_refs=[f"ev-{i}"], metadata={"path": f"/p{i}"}))
            big.add_entity(AppModelEntity(
                id=f"id-many-{i}", kind=AppModelEntityKind.IDENTITY,
                label=f"identity:id-many-{i}"[:160],
                provenance=DiscoveryProvenance.OBSERVED,
                evidence_refs=[f"ev-id-{i}"]))
            big.add_relation(AppModelRelation(
                id=f"rel-many-{i}", kind=AppModelRelationKind.OWNS,
                source_id=f"id-many-{i}", target_id=f"ep-many-{i}",
                evidence_refs=[f"ev-own-{i}"]))
        big_hints = build_appmodel_research_hints(big)
        assert len(big_hints) <= _MAX_HINTS
