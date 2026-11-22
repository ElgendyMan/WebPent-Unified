"""UM-DR-43 Workstream A — incremental application-model updates.

Pins the apply_observation contract the workstream requires:
  1. a single observation merges into the EXISTING model (no rebuild);
  2. provenance is preserved exactly — an INFERRED identity/access link
     is never stored as OBSERVED;
  3. re-observation strengthens confidence and merges evidence refs;
  4. an observation without an evidence_ref is REJECTED (traceability);
  5. unresolvable parts ABSTAIN with a reason instead of inventing
     structure (unknown inferred kinds, unparseable URLs);
  6. the full-rebuild path (build_application_model) still produces a
     model the incremental path can continue from — the two coexist.
"""
from __future__ import annotations

from webpent.appmodel.builder import (
    _endpoint_id_of,
    build_application_model,
)
# UM-DR-44 A5a (batch §6): endpoint entity ids are the canonical
# (scheme, host, effective-port, path) tuple, minted by the SSOT
# _endpoint_id_of. The legacy host+path literals below were replaced
# by SSOT-derived ids — a DELIBERATE contract change: https/http and
# implicit/explicit-port origins are DISTINCT endpoints now.

from webpent.appmodel.models import (
    AppModelEntityKind,
    AppModelRelationKind,
    ApplicationModel,
    DiscoveryProvenance,
)

_OBS = {
    "url": "https://api.example.com/orders/1",
    "method": "GET",
    "actor": "user-a",
    "status_code": 200,
    "evidence_ref": "req-abc123",
}


def test_single_observation_merges_into_existing_model():
    model = ApplicationModel(engagement_id="eng-1")
    before_revision = model.revision
    result = model.apply_observation(dict(_OBS))
    assert result["applied"] is True
    assert result["touched_count"] == 2  # endpoint + identity
    assert model.revision > before_revision
    assert _endpoint_id_of("https://api.example.com/orders/1") in model.entities
    assert "identity:user-a" in model.entities
    # the identity->endpoint relation exists and is typed
    kinds = {(r.kind, r.source_id, r.target_id) for r in model.relations}
    assert (AppModelRelationKind.OBSERVED_ON.value,
            "identity:user-a",
            _endpoint_id_of("https://api.example.com/orders/1")) in kinds


def test_provenance_is_exact_observed_vs_inferred():
    model = ApplicationModel(engagement_id="eng-1")
    model.apply_observation(dict(_OBS))
    endpoint = model.entities[_endpoint_id_of("https://api.example.com/orders/1")]
    identity = model.entities["identity:user-a"]
    relation = model.relations[0]
    assert endpoint.provenance == DiscoveryProvenance.OBSERVED.value
    # The observation evidences the REQUEST; the server's authorization
    # decision was NOT observed — the link must stay INFERRED.
    assert identity.provenance == DiscoveryProvenance.INFERRED.value
    assert relation.provenance == DiscoveryProvenance.INFERRED.value


def test_reobservation_merges_refs_and_keeps_identity():
    model = ApplicationModel(engagement_id="eng-1")
    model.apply_observation(dict(_OBS))
    model.apply_observation({**_OBS, "evidence_ref": "req-def456"})
    endpoint = model.entities[_endpoint_id_of("https://api.example.com/orders/1")]
    assert endpoint.ref_list() == ["req-abc123", "req-def456"]
    # no duplicate relation from the second observation
    assert len(model.relations) == 1


def test_observation_without_evidence_ref_is_rejected():
    model = ApplicationModel(engagement_id="eng-1")
    result = model.apply_observation({"url": "https://a.example/x"})
    assert result["applied"] is False
    assert result["reason"] == "evidence_ref_required"
    assert model.entities == {}  # nothing was invented


def test_unresolvable_parts_abstain_with_reason():
    model = ApplicationModel(engagement_id="eng-1")
    result = model.apply_observation({
        "url": "not-a-url",
        "evidence_ref": "req-1",
        "inferred": {"workflow": "checkout", "bogus_kind": "x"},
    })
    assert result["applied"] is True
    abstained = {a["what"]: a["why"] for a in result["abstained"]}
    assert abstained["endpoint"] == "unparseable_url"
    assert abstained["inferred:bogus_kind"] == "unknown_entity_kind"
    # the KNOWN inferred kind was still recorded, as INFERRED
    wf = model.entities["workflow:checkout"]
    assert wf.provenance == DiscoveryProvenance.INFERRED.value
    assert wf.kind == AppModelEntityKind.WORKFLOW.value


def test_incremental_path_continues_from_full_rebuild():
    """The two construction paths coexist: a full rebuild's model keeps
    accepting incremental observations without resetting."""
    state = {
        "engagement_id": "eng-2",
        "target_url": "https://api.example.com",
        "crawled_data": {
            "openapi_routes": [
                {"path": "/orders/1"},
                {"path": "/orders/2"},
            ],
        },
    }
    model = build_application_model(state)
    entities_before = set(model.entities)
    assert any(e.kind == AppModelEntityKind.ENDPOINT.value
               for e in model.entities.values())
    result = model.apply_observation({
        "url": "https://api.example.com/orders/3",
        "actor": "user-b",
        "evidence_ref": "req-live-1",
    })
    assert result["applied"] is True
    # nothing from the rebuild was lost
    assert entities_before <= set(model.entities)
    assert _endpoint_id_of("https://api.example.com/orders/3") in model.entities
    assert "identity:user-b" in model.entities
    # and the rebuild's endpoint for /orders/1 is distinct from /orders/3
    assert (_endpoint_id_of("https://api.example.com/orders/1") in model.entities
            and _endpoint_id_of("https://api.example.com/orders/3") in model.entities)
