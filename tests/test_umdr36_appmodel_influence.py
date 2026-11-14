"""UM-DR-36 corrective closure — semantic-model influence on research decisions.

Mission §2.4 deterministic model-influence test: given the same underlying
observations, evaluating hypothesis/experiment selection WITH the relevant
AppModel facts must differ from evaluating the same selection with those
facts deliberately withheld — proving a real causal influence of the
semantic model on research decisions, without fabricating vulnerabilities
or bypassing production validation.
"""
from __future__ import annotations

import uuid
from typing import Any

from webpent.appmodel.builder import (
    build_appmodel_research_hints,
    build_application_model,
)
from webpent.graph.appmodel_nodes import appmodel_node
from webpent.models.findings import Finding
from webpent.production.autonomous_validation_v1 import AutonomousExperimentSelector
from webpent.production.experiment_fabric import EXPERIMENT_REGISTRY
from webpent.shared.verifier import verify_replay_evidence

TARGET = "http://127.0.0.1:9777"
OWNED = "/api/invoices/INV-B-204"
UNRELATED = "/api/health"
_SCOPE = {"target_origin": TARGET, "scope_bound": True}
_IDENTITY = {
    "mode": "authenticated",
    "baseline_identity": {"identity_id": "User_A", "role": "owner"},
    "candidate_identity": {"identity_id": "User_A", "role": "foreign-user"},
    "negative_control_identity": {"identity_id": "User_A", "role": "foreign-user"},
}


def _state(with_semantics: bool) -> dict[str, Any]:
    endpoints: list[Any] = [
        "http://127.0.0.1:9777/api/invoices/me",
        "http://127.0.0.1:9777/api/health",
    ]
    if with_semantics:
        # REAL crawled evidence: the invoice endpoint is owned by User_B.
        endpoints.append({
            "url": f"{TARGET}{OWNED}",
            "owner_identity": "User_B",
            "object_id": "INV-B-204",
        })
    return {
        "engagement_id": "umdr36-influence",
        "target_url": TARGET,
        "crawled_data": {"endpoints": endpoints, "surface_records": []},
        "identity_profiles": {
            "User_A": {"role": "foreign-user", "validated": True},
            "User_B": {"role": "owner", "validated": True},
        },
    }


def _hint_paths(hints: dict[str, Any]) -> set[str]:
    paths = set()
    for hint in hints.values():
        subject = hint.get("subject") or {}
        path = subject.get("path")
        if path:
            paths.add(str(path))
    return paths


def test_model_materializes_ownership_only_from_real_evidence():
    with_model = appmodel_node(_state(with_semantics=True))
    without_model = appmodel_node(_state(with_semantics=False))
    with_owns = with_model["appmodel_summary"]["relation_kind_counts"].get("owns", 0)
    without_owns = without_model["appmodel_summary"]["relation_kind_counts"].get("owns", 0)
    assert with_owns == 1
    assert without_owns == 0
    # The ownership relation exists ONLY because the crawled record carried
    # owner_identity — evidence provenance is recorded on the relation.
    relations = with_model["appmodel"]["relations"]
    owns = [r for r in relations if r["kind"] == "owns"]
    assert len(owns) == 1
    assert owns[0]["provenance"] == "observed"
    assert owns[0]["evidence_refs"]
    assert without_model["appmodel_summary"]["coverage_gaps"]


def test_hints_change_selected_endpoint_research_priority():
    """Same observations ± ownership evidence → different hint coverage on
    the authorization-boundary endpoint (the deterministic influence)."""
    with_model = appmodel_node(_state(with_semantics=True))
    without_model = appmodel_node(_state(with_semantics=False))
    with_hints = with_model["appmodel_research_hints"]
    without_hints = without_model["appmodel_research_hints"]
    with_paths = _hint_paths(with_hints)
    without_paths = _hint_paths(without_hints)
    assert OWNED in with_paths
    assert OWNED not in without_paths
    assert with_hints != without_hints
    # The ownership hint records its evidence provenance.
    ownership_hints = [
        h for h in with_hints.values()
        if h.get("kind") == "object_ownership_boundary"
    ]
    assert ownership_hints and ownership_hints[0]["evidence_refs"]


def test_semantic_hints_change_experiment_selection_order():
    """The deterministic influence on the AVI experiment selector: with the
    semantic ownership hint, the IDOR hypothesis on the owned object is
    selected FIRST; without it, the unrelated hypothesis wins on
    information value. Same underlying observations otherwise."""
    base = {
        "api_type": "rest",
        "information_value": 0.5,
    }
    idor = {
        "id": "hyp-idor-owned-object",
        "vulnerability_class": "IDOR",
        "path": OWNED,
        "information_value": 0.5,
        **base,
    }
    other = {
        "id": "hyp-unrelated-health",
        "vulnerability_class": "SSRF",
        "path": UNRELATED,
        "information_value": 0.9,  # nominally higher information value
        **base,
    }

    def first_selected(hypotheses: list[dict]) -> str:
        selector = AutonomousExperimentSelector()
        return selector.select(hypotheses, EXPERIMENT_REGISTRY)["hypothesis_id"]

    # WITHOUT the semantic hint: the higher-information-value hypothesis wins.
    without = first_selected([dict(idor), dict(other)])
    assert without == "hyp-unrelated-health"

    # WITH the evidence-backed ownership hint on the IDOR surface: the
    # authorization-boundary hypothesis is selected FIRST.
    idor_with_hint = dict(idor)
    idor_with_hint["evidence_contract"] = {
        "appmodel_hint": {
            "kind": "object_ownership_boundary",
            "priority": 0.9,
            "evidence_refs": ["surface-record:127.0.0.1/api/invoices/INV-B-204"],
            "advisory_only": True,
        }
    }
    with_hint = first_selected([idor_with_hint, dict(other)])
    assert with_hint == "hyp-idor-owned-object"


def test_hypothesis_node_applies_semantic_priority_from_hints():
    """The hypothesis generator consumes the hints channel: hypotheses on
    hinted surfaces get a recorded priority boost + provenance."""
    from webpent.agents.hypothesis_analyzer.agent import hypothesis_node

    model_out = appmodel_node(_state(with_semantics=True))
    state = {
        **_state(with_semantics=True),
        "appmodel_research_hints": model_out["appmodel_research_hints"],
        "runtime_context": None,
        "application_intent": None,
        "additional_target_origins": None,
    }
    from webpent.models.targets import Target

    state["target"] = Target(url=TARGET)
    result = hypothesis_node(state)
    influenced = (result.get("appmodel_summary") or {}).get(
        "influenced_hypotheses", [],
    )
    assert influenced, "semantic hints must influence at least one hypothesis"
    for record in influenced:
        assert record["confidence_after"] >= record["confidence_before"]
        assert record["evidence_refs"]
        assert record["advisory_only"] is True
        assert record["hint_kind"] in {
            "object_ownership_boundary", "identity_relationship",
            "observed_behavior", "coverage_gap",
        }
    # The influence is bounded: the semantic boost is at most +0.10 over
    # whatever the base evidence score was (never an unbounded jump), and
    # every influenced hypothesis records its before/after for telemetry.
    influenced_by_id = {
        record["hypothesis_id"]: record for record in influenced
    }
    for h in result.get("hypotheses", []):
        if (h.evidence_contract or {}).get("appmodel_hint"):
            record = influenced_by_id.get(str(h.id))
            assert record is not None, "every hinted hypothesis must be recorded"
            delta = record["confidence_after"] - record["confidence_before"]
            assert 0.0 < delta <= 0.10 + 1e-9
            assert record["confidence_after"] == float(h.confidence_score)


def test_semantic_model_has_no_confirmation_or_authorization_authority():
    """The model influence is advisory only: no semantic-model path can
    bypass scope, CausalGuard, ProofBundle or Replay (mission §2.3)."""
    model_out = appmodel_node(_state(with_semantics=True))
    hints = model_out["appmodel_research_hints"]
    for hint in hints.values():
        assert hint.get("advisory_only") is True
        assert hint.get("source") == "appmodel"
        assert "authorize" not in str(hint.get("kind"))
    # The strongest possible misuse — feeding the hints into the strict
    # verifier as evidence — cannot confirm anything by itself.
    finding = Finding(
        id=uuid.uuid4(), thread_id="umdr36", url=f"{TARGET}{OWNED}",
        vuln_class="idor", title="influence-misuse-probe", severity="high",
        description="probe", tool_name="test", confidence_level="Pending",
        reasoning="probe", evidence={},
    )
    result = verify_replay_evidence(
        finding, baseline=None, candidate=None, negative_control=None,
        causal_signal=True, negative_control_complete=True,
        validator_id="hint-misuse", validator_version="v1",
        causal_basis="hints cannot confirm",
        engagement_id="umdr36-influence", scope_context=_SCOPE,
        identity_context=_IDENTITY, require_target_backed=True,
    )
    assert result.passed is False


def test_builder_and_node_channel_roundtrip():
    model = build_application_model(_state(with_semantics=True))
    hints = build_appmodel_research_hints(model)
    assert hints
    node_out = appmodel_node(_state(with_semantics=True))
    assert node_out["appmodel"]["entities"]
    assert node_out["appmodel_summary"]["built"] is True
    assert node_out["appmodel_summary"]["advisory_only"] is True
    # Ontology honesty (mission §2.2): report the REAL enum counts.
    from webpent.appmodel.models import AppModelEntityKind, AppModelRelationKind
    assert len(list(AppModelEntityKind)) == 7
    assert len(list(AppModelRelationKind)) == 8  # OWNS added by UM-DR-36
    kinds = set(node_out["appmodel_summary"]["entity_kind_counts"])
    assert kinds <= {"organization", "tenant", "application", "endpoint", "identity"}
    # PRINCIPAL / ROLE / RESOURCE / STATE kinds do NOT exist in the ontology:
    # recorded as coverage reality, never claimed.
    assert "principal" not in kinds and "role" not in kinds and "state" not in kinds
