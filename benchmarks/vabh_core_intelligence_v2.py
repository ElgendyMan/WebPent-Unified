"""Offline benchmark for the generic autonomous research core.

The benchmark uses synthetic, recorded knowledge facts only.  It measures
hypothesis coverage, portfolio selection, bounded decision-making, and the
fail-closed confirmation boundary.  It never creates requests, findings, or
qualification decisions.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from webpent.attack_graph.engine import AttackGraphEngine
from webpent.knowledge.model_v2 import build_target_knowledge_v2
from webpent.models.proof_bundle import build_proof_bundle
from webpent.research import (
    DEFAULT_PATTERNS,
    DecisionLoopContext,
    HypothesisGenerator,
    ResearchPlanner,
    decide_next_step,
)
from webpent.shared.confirmation_intelligence import evaluate_confirmation
from webpent.shared.proof_oracles import (
    CausalObservation,
    CausalOracleContract,
    OracleFamily,
)
from webpent.vabhfqr_v9 import VABHFQRV9Core

NOW = datetime(2026, 8, 28, tzinfo=timezone.utc)
OUTPUT = Path("reports/evaluation/vabh_core_intelligence_v2.json")


def _entity(kind: str, key: str, confidence: float = 0.9) -> dict[str, object]:
    return {
        "kind": kind,
        "canonical_key": key,
        "source_observation": "obs:core-v2",
        "confidence": confidence,
        "observed_at": NOW,
        "evidence_refs": ["evidence:core-v2"],
    }


def _recorded_model():
    observation = {
        "observation_id": "obs:core-v2",
        "source": "recorded-synthetic-fixture",
        "observed_at": NOW,
        "confidence": 1.0,
        "evidence_refs": ["evidence:core-v2"],
    }
    entities = [
        _entity("identity", "identity:opaque"),
        _entity("endpoint", "GET /objects/{id}", 0.95),
        _entity("resource", "resource:opaque"),
        _entity("role", "role:opaque"),
        _entity("permission", "permission:opaque"),
        _entity("trust_boundary", "tenant:opaque"),
        _entity("workflow", "workflow:opaque"),
        _entity("parameter", "parameter:opaque"),
        _entity("data_flow", "data-flow:opaque"),
    ]
    base = build_target_knowledge_v2(
        engagement_id="eng:core-v2",
        target_id="target:synthetic",
        observations=[observation],
        entities=entities,
    )
    ids = {item.canonical_key: item.entity_id for item in base.entities.values()}
    pairs = [
        ("exposes", "identity:opaque", "GET /objects/{id}"),
        ("can_access", "GET /objects/{id}", "resource:opaque"),
        ("requires_role", "GET /objects/{id}", "role:opaque"),
        ("grants", "role:opaque", "permission:opaque"),
        ("can_access", "GET /objects/{id}", "permission:opaque"),
        ("belongs_to", "resource:opaque", "tenant:opaque"),
        ("scoped_by", "GET /objects/{id}", "tenant:opaque"),
        ("transitions", "GET /objects/{id}", "workflow:opaque"),
        ("requires", "workflow:opaque", "GET /objects/{id}"),
        ("can_modify", "GET /objects/{id}", "workflow:opaque"),
        ("accepts", "GET /objects/{id}", "parameter:opaque"),
        ("has_parameter", "parameter:opaque", "GET /objects/{id}"),
        ("contains_parameter", "GET /objects/{id}", "parameter:opaque"),
        ("reflects", "GET /objects/{id}", "parameter:opaque"),
        ("queries", "GET /objects/{id}", "parameter:opaque"),
        ("fetches", "GET /objects/{id}", "data-flow:opaque"),
        ("resolves", "data-flow:opaque", "GET /objects/{id}"),
        ("flows_to", "GET /objects/{id}", "data-flow:opaque"),
        ("references", "GET /objects/{id}", "parameter:opaque"),
        ("reads", "parameter:opaque", "GET /objects/{id}"),
    ]
    relations = [
        {
            "relation": relation,
            "source_entity": ids[source],
            "target_entity": ids[target],
            "source_observation": "obs:core-v2",
            "confidence": 0.9,
            "evidence_refs": ["evidence:core-v2"],
        }
        for relation, source, target in pairs
    ]
    return build_target_knowledge_v2(
        engagement_id="eng:core-v2",
        target_id="target:synthetic",
        observations=[observation],
        entities=entities,
        relations=relations,
    )


def _observation(
    role: str,
    digest: str,
    signals: dict[str, object],
) -> CausalObservation:
    return CausalObservation(
        observation_ref=f"obs-{role}",
        role=role,
        semantic_fingerprint=f"semantic-{role}",
        request_digest=digest,
        response_digest=digest,
        signals=signals,
        target_backed=False,
        evidence_origin="offline_fixture",
    )


def _confirmed_contract() -> CausalOracleContract:
    return CausalOracleContract(
        family=OracleFamily.IDOR,
        baseline=_observation(
            "baseline",
            "sha256:" + "a" * 64,
            {"invariant_holds": True, "owner_relation": "owner"},
        ),
        candidate=_observation(
            "candidate",
            "sha256:" + "b" * 64,
            {"invariant_violated": True, "owner_relation": "foreign"},
        ),
        negative_control=_observation(
            "negative_control",
            "sha256:" + "c" * 64,
            {"invariant_holds": True, "owner_relation": "control"},
        ),
        expected_invariant="owner can access owned object",
        violated_invariant="foreign owner can access object",
    )


def _confirmed_proof(contract: CausalOracleContract):
    baseline = {"observation": "baseline", "ref": contract.baseline.observation_ref}
    candidate = {"observation": "candidate", "ref": contract.candidate.observation_ref}
    control = {"observation": "negative", "ref": contract.negative_control.observation_ref}
    bundle = build_proof_bundle(
        engagement_id="eng:core-v2",
        finding_id="recorded-evidence-only",
        hypothesis_id="hypothesis-idor-offline",
        target_fingerprint="offline-fixture",
        evidence=(baseline, candidate),
        evidence_refs=(
            contract.baseline.observation_ref,
            contract.candidate.observation_ref,
            contract.negative_control.observation_ref,
        ),
        negative_control=control,
        baseline=baseline,
        request_evidence=("request-baseline", "request-candidate"),
        response_evidence=("response-baseline", "response-candidate"),
        scope_context={"mode": "offline"},
        identity_context={"model": "synthetic"},
        causal_oracle={"causal_signal": True, "negative_control_complete": True},
        validator_id="vabh-core-intelligence-v2",
        validator_version="1",
        replay_metadata={"replayable": True},
        cleanup_status="not_applicable",
        oracle_decision="CONFIRMED",
        evidence_origin="offline_fixture",
    )
    return bundle.seal(), (baseline, candidate), control


def run() -> dict[str, object]:
    model = _recorded_model()
    graph = AttackGraphEngine().build(model)
    hypotheses = HypothesisGenerator(max_hypotheses=128).generate(model, graph)
    planner = ResearchPlanner(max_tasks=6)
    queue = planner.build_queue(
        hypotheses,
        engagement_id="eng:core-v2",
        target_id="target:synthetic",
        available_capabilities={"http_read"},
    )
    decision = decide_next_step(
        queue,
        DecisionLoopContext(
            scope_verified=True,
            policy_allows_proposal=True,
            remaining_budget=6,
            max_steps=6,
        ),
    )
    incomplete_confirmation = evaluate_confirmation(None)
    confirmed_contract = _confirmed_contract()
    confirmed_bundle, confirmed_evidence, confirmed_control = _confirmed_proof(confirmed_contract)
    confirmed = evaluate_confirmation(
        confirmed_contract,
        proof_bundle=confirmed_bundle,
        evidence_payloads=confirmed_evidence,
        negative_control_payload=confirmed_control,
    )
    confirmed_posture = str(getattr(confirmed.posture, "value", confirmed.posture))
    incomplete_posture = str(
        getattr(incomplete_confirmation.posture, "value", incomplete_confirmation.posture)
    )
    unified = VABHFQRV9Core().build_unified_intelligence(
        knowledge=model,
        graph=graph,
        engagement_id="eng:core-v2",
        target_id="target:synthetic",
        scope_verified=True,
        remaining_budget=6,
        max_steps=6,
        available_capabilities=("http_read",),
        available_evidence=("proof:sealed", "replay:verified"),
        required_evidence=("proof:sealed", "replay:verified"),
        negative_control_complete=True,
        replay_verified=True,
        confirmation_contract=confirmed_contract,
        proof_bundle=confirmed_bundle,
        evidence_payloads=confirmed_evidence,
        negative_control_payload=confirmed_control,
    )
    observed_patterns = {
        str(item.reason).split(" is plausible", 1)[0]
        for item in hypotheses
        if " is plausible" in str(item.reason)
    }
    pattern_names = {pattern.name for pattern in DEFAULT_PATTERNS}
    classes = sorted({str(item.vuln_class) for item in hypotheses})
    result = {
        "benchmark_id": "vabh-core-intelligence-v2",
        "mode": "offline_recorded_synthetic_facts",
        "target_execution": False,
        "requests_sent": 0,
        "findings_created": 0,
        "qualification_effect": False,
        "input": {
            "entity_count": len(model.entities),
            "relation_count": len(model.relations),
            "graph_node_count": len(graph.nodes),
            "graph_edge_count": len(graph.edges),
        },
        "discovery": {
            "hypothesis_count": len(hypotheses),
            "distinct_vulnerability_classes": classes,
            "distinct_pattern_count": len(observed_patterns & pattern_names),
            "expected_pattern_count": len(pattern_names),
            "pattern_coverage": round(
                len(observed_patterns & pattern_names) / len(pattern_names), 4
            ),
        },
        "portfolio": {
            "queue_size": len(queue.tasks),
            "selected_task_id": decision.selected_task_id,
            "decision_status": str(decision.status),
            "decision_stage": decision.stage,
            "execution_allowed": decision.execution_allowed,
            "mutation_allowed": decision.mutation_allowed,
        },
        "confirmation_boundary": {
            "incomplete_posture": str(incomplete_confirmation.posture),
            "incomplete_missing": list(incomplete_confirmation.missing),
            "confirmed_posture": str(confirmed.posture),
            "confirmed_score": confirmed.score,
            "confirmed_proof_bundle_valid": confirmed.proof_bundle_valid,
            "confirmed_replay_verified": confirmed.replay_verified,
            "confirmed_scoring_eligible": confirmed.scoring_eligible,
            "confirmed_official_qualification_granted": (confirmed.official_qualification_granted),
            "engineering_confirmed_cases": int(confirmed_posture == "engineering_confirmed"),
            "blocked_or_incomplete_cases": int(incomplete_posture in {"blocked", "needs_proof"}),
        },
        "unified_core": {
            "hypothesis_count": len(unified.hypothesis_ids),
            "queue_task_count": len(unified.queue_task_ids),
            "selected_task_id": unified.selected_task_id,
            "decision_status": unified.decision_status,
            "decision_stage": unified.decision_stage,
            "confirmation_posture": unified.confirmation_posture,
            "confirmation_score": unified.confirmation_score,
            "engineering_confirmed": unified.engineering_confirmed,
            "scoring_eligible": unified.scoring_eligible,
            "execution_allowed": unified.execution_allowed,
            "mutation_allowed": unified.mutation_allowed,
            "finding_created": unified.finding_created,
            "qualification_effect": unified.qualification_effect,
            "recommendations": list(unified.recommendations),
        },
        "interpretation": (
            "Discovery and proposal coverage are measured on synthetic recorded facts; "
            "confirmation is engineering-confirmed only when recorded baseline/candidate/control "
            "observations, oracle, proof, seal, and replay are complete; offline evidence remains "
            "ineligible for official scoring or qualification."
        ),
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
