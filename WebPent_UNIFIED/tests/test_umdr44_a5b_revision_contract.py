"""UM-DR-44 A5b — merge increments revision (RED on 6f3dc7c).

The contract comment above ``revision`` (models.py ~177-180) says
literally "every add/contradiction increments it" — but ``add_entity``'s
merge path (re-observation) does NOT increment.  ``delta_since`` is
therefore blind to evidence accumulation on existing entities.

Contract tests (11): merge increments revision; monotonicity across 4
observations; duplicate relation rejected WITHOUT moving the counter;
contradiction increments; refs dedup; first-observed-at stays oldest;
delta_since sees re-observation (revision_to > revision_from);
stronger provenance wins; weaker never downgrades; refs capped at 50;
metadata extras preserved on merge.
"""

from __future__ import annotations

from webpent.appmodel.models import (
    AppModelEntity,
    AppModelEntityKind,
    AppModelRelation,
    AppModelRelationKind,
    ApplicationModel,
    DiscoveryProvenance,
)


def _endpoint(eid: str, *, provenance=DiscoveryProvenance.OBSERVED,
              refs: list[str] | None = None,
              metadata: dict | None = None) -> AppModelEntity:
    return AppModelEntity(
        id=eid, kind=AppModelEntityKind.ENDPOINT,
        label=f"endpoint:{eid}"[:160], provenance=provenance,
        evidence_refs=refs or ["ev-1"], metadata=metadata or {})


def _identity(iid: str) -> AppModelEntity:
    return AppModelEntity(
        id=iid, kind=AppModelEntityKind.IDENTITY,
        label=f"identity:{iid}"[:160])


class TestRevisionContract:
    def test_merge_increments_revision(self) -> None:
        """RED on the base: the merge path leaves revision untouched."""
        m = ApplicationModel()
        m.add_entity(_endpoint("ep-1"))
        before = m.revision
        m.add_entity(_endpoint("ep-1", refs=["ev-2"]))
        assert m.revision > before

    def test_monotonic_across_four_observations(self) -> None:
        m = ApplicationModel()
        m.add_entity(_endpoint("ep-1", refs=["ev-1"]))
        revisions = [m.revision]
        for i in range(2, 5):
            m.add_entity(_endpoint("ep-1", refs=[f"ev-{i}"]))
            revisions.append(m.revision)
        assert revisions == sorted(revisions), revisions
        assert len(set(revisions)) == 4  # every observation moved it

    def test_duplicate_relation_rejected_without_counter_move(self) -> None:
        m = ApplicationModel()
        m.add_entity(_endpoint("ep-1"))
        m.add_entity(_identity("id-1"))
        rel = AppModelRelation(
            id="rel-1", kind=AppModelRelationKind.OBSERVED_ON,
            source_id="id-1", target_id="ep-1")
        assert m.add_relation(rel) is True
        before = m.revision
        assert m.add_relation(rel) is False  # typed duplicate
        assert m.revision == before  # rejected → no counter move

    def test_contradiction_increments_revision(self) -> None:
        m = ApplicationModel()
        m.add_entity(_endpoint("ep-1"))
        before = m.revision
        assert m.mark_contradicted(
            "ep-1", contradicting_evidence_ref="ev-counter") is True
        assert m.revision > before


class TestMergeSemantics:
    def test_refs_dedup_on_merge(self) -> None:
        m = ApplicationModel()
        m.add_entity(_endpoint("ep-1", refs=["ev-1", "ev-2"]))
        m.add_entity(_endpoint("ep-1", refs=["ev-2", "ev-3"]))
        assert m.entities["ep-1"].ref_list() == ["ev-1", "ev-2", "ev-3"]

    def test_first_observed_at_wins(self) -> None:
        m = ApplicationModel()
        m.add_entity(_endpoint("ep-1"))
        first = m.entities["ep-1"].observed_at
        m.add_entity(AppModelEntity(
            id="ep-1", kind=AppModelEntityKind.ENDPOINT,
            label="endpoint:ep-1", provenance=DiscoveryProvenance.OBSERVED,
            evidence_refs=["ev-2"], observed_at="2020-01-01T00:00:00+00:00"))
        assert m.entities["ep-1"].observed_at == first

    def test_stronger_provenance_wins(self) -> None:
        m = ApplicationModel()
        m.add_entity(_endpoint("ep-1"))
        m.add_entity(_endpoint("ep-1", provenance=DiscoveryProvenance.DECLARED))
        assert str(m.entities["ep-1"].provenance) == "declared"

    def test_weaker_provenance_never_downgrades(self) -> None:
        m = ApplicationModel()
        m.add_entity(_endpoint("ep-1", provenance=DiscoveryProvenance.DECLARED))
        m.add_entity(_endpoint("ep-1", provenance=DiscoveryProvenance.INFERRED))
        assert str(m.entities["ep-1"].provenance) == "declared"

    def test_refs_capped_at_50(self) -> None:
        """The merge path must never exceed the 50-ref cap.  Pydantic
        already rejects single inputs above 50, so the cap is proven on
        the MERGE path: many sub-cap observations merge into one."""
        m = ApplicationModel()
        for batch in range(6):  # 6 x 10 = 60 potential refs
            m.add_entity(_endpoint("ep-1",
                                   refs=[f"ev-{batch}-{i}" for i in range(10)]))
        assert len(m.entities["ep-1"].ref_list()) <= 50

    def test_metadata_extras_preserved_on_merge(self) -> None:
        m = ApplicationModel()
        m.add_entity(_endpoint("ep-1", metadata={"custom_note": "keep-me",
                                                 "zone": "a"}))
        m.add_entity(_endpoint("ep-1", refs=["ev-2"],
                               metadata={"zone": "a", "extra": "new"}))
        meta = m.entities["ep-1"].metadata or {}
        assert meta.get("custom_note") == "keep-me"
        assert meta.get("extra") == "new"

    def test_delta_since_sees_reobservation(self) -> None:
        m = ApplicationModel()
        m.add_entity(_endpoint("ep-1"))
        before = m.model_copy(deep=True)
        m.add_entity(_endpoint("ep-1", refs=["ev-2"],
                               provenance=DiscoveryProvenance.DECLARED))
        delta = m.delta_since(before)
        assert delta["revision_to"] > delta["revision_from"]
        assert delta.get("provenance_changes", {}).get("ep-1") == {
            "from": "observed", "to": "declared"}
