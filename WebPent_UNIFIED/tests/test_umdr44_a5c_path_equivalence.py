"""UM-DR-44 A5c — incremental/rebuild equivalence (contract tests).

The two model paths (full rebuild via build_application_model with
crawled_data.surface_records; incremental via apply_observation) are
DIFFERENT BY DESIGN — but they must never DISAGREE about the identity
of the endpoints they both cover, and an incremental observation on
top of a rebuild must merge in place:

* the same URL mints the SAME entity id from both paths (the SSOT
  _endpoint_id_of is the single minter);
* rebuild-then-observation merges into the existing entity — no
  duplicate endpoint entity for the same tuple, revision bumped;
* double-apply of one observation is idempotent at the entity/relation
  level (same entity set; refs merged; no duplicated relations).
"""

from __future__ import annotations

from webpent.appmodel.builder import (
    _endpoint_id_of,
    build_application_model,
)
from webpent.appmodel.models import ApplicationModel

URL = "https://api.example.com/orders/7"


def _state_with(url: str) -> dict:
    return {
        "engagement_id": "eng-1",
        "crawled_data": {
            "surface_records": [
                {"url": url, "method": "GET"},
            ],
        },
    }


def _endpoint_ids(model: ApplicationModel) -> set[str]:
    return {
        eid for eid, e in model.entities.items()
        if str(e.kind) == "endpoint"}


class TestPathEquivalence:
    def test_same_url_mints_same_id_both_paths(self) -> None:
        rebuilt = build_application_model(_state_with(URL))
        incremental = ApplicationModel()
        result = incremental.apply_observation(
            {"url": URL, "method": "GET", "evidence_ref": "req-1"})
        assert result["applied"] is True
        rebuilt_ids = _endpoint_ids(rebuilt)
        incremental_ids = _endpoint_ids(incremental)
        assert rebuilt_ids and incremental_ids
        assert (rebuilt_ids & incremental_ids) == \
            {_endpoint_id_of(URL)}, (
                f"paths disagree on identity: rebuild={rebuilt_ids} "
                f"incremental={incremental_ids}"
            )

    def test_observation_on_rebuild_merges_in_place_with_bump(self) -> None:
        model = build_application_model(_state_with(URL))
        before = _endpoint_ids(model)
        revision_before = model.revision
        model.apply_observation(
            {"url": URL, "method": "POST", "evidence_ref": "req-2"})
        after = _endpoint_ids(model)
        # no duplicate entity for the same tuple — merged in place
        assert not (after - before), (
            f"incremental observation created duplicates: {after - before}")
        # the merge moved the revision (A5b contract)
        assert model.revision > revision_before
        # and the method facet accumulated onto the merged entity
        endpoint = model.entities[_endpoint_id_of(URL)]
        methods = set((endpoint.metadata or {}).get("methods_seen") or [])
        assert methods >= {"POST"}

    def test_double_apply_is_idempotent(self) -> None:
        model = ApplicationModel()
        obs = {"url": URL, "method": "GET", "actor": "user-a",
               "evidence_ref": "req-3"}
        model.apply_observation(dict(obs))
        snapshot_entities = set(model.entities)
        snapshot_relations = {
            (str(r.kind), r.source_id, r.target_id) for r in model.relations}
        model.apply_observation(dict(obs))
        assert set(model.entities) == snapshot_entities
        assert {
            (str(r.kind), r.source_id, r.target_id)
            for r in model.relations} == snapshot_relations
        # refs merged, not duplicated
        endpoint = model.entities[_endpoint_id_of(URL)]
        assert endpoint.ref_list().count("req-3") == 1
