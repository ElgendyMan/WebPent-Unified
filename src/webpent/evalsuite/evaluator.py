"""Ground-truth evaluator: score investigation states against the
defect layout the instance was generated with.

Polarity: every InstanceSpec enforcement flag is True when the
invariant is ENFORCED (safe). A family counts as defective when its
flag is False; the engine is expected to confirm exactly the defective
families and nothing else. Workflow-scoped families (identity of
transitions, order of transitions) are scored per workflow.

For every false positive and false negative the causal failure is
recorded from the investigation state alone (no oracle internals).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from webpent.egaie.eval_instances import InstanceSpec
    from webpent.egaie.schemas import InvestigationState

# Outcome labels (mirrored, not imported: the evaluator must not pull
# the orchestrator module graph in).
OUTCOME_CONFIRMED = "confirmed"
OUTCOME_CLEAN = "clean"
OUTCOME_INCONCLUSIVE = "inconclusive"

_RECON_ORIGIN = "differential:recon:"

# engine family -> spec enforcement flag(s). A list of flags means the
# family spans sub-invariants; the family is defective when ANY flag is
# False (the engine found a real violation of that family's invariant).
FAMILY_FLAGS: dict[str, tuple[str, ...]] = {
    # the identity family spans resource reads and cross-identity
    # mutations (pay-role probes land in this family)
    "IDENTITY_BOUNDARY": (
        "identity_read_enforced", "identity_mutation_enforced"),
    "PRICE_INTEGRITY": ("price_authoritative", "coupon_owner_enforced"),
    "BOUNDARY_LIMIT": ("balance_enforced",),
    "WORKFLOW_IDENTITY": ("workflow_identity_enforced",),
    "WORKFLOW_ORDER": ("order_enforced",),
}


def family_defective(spec: InstanceSpec, family: str) -> bool:
    flags = FAMILY_FLAGS[family]
    values = tuple(getattr(spec, flag) for flag in flags)
    if any(isinstance(v, dict) for v in values):
        # workflow-scoped: defective when any workflow is not enforced
        return any(
            any(not wf_enforced for wf_enforced in v.values())
            for v in values if isinstance(v, dict))
    return any(not v for v in values)


def _workflow_of(statement: str, spec: InstanceSpec) -> str | None:
    """The workflow a hypothesis probed, matched against the spec's own
    workflow ids (evaluator-side knowledge, engine-side statement)."""
    for wf_id in spec.workflow_bases:
        if wf_id in statement:
            return wf_id
    return None


def workflow_defective(spec: InstanceSpec, family: str,
                       wf_id: str | None) -> bool:
    flag = FAMILY_FLAGS[family][0]
    mapping = getattr(spec, flag)
    if wf_id is None or not isinstance(mapping, dict):
        return family_defective(spec, family)
    return not mapping.get(wf_id, True)


@dataclass
class FamilyScore:
    family: str
    defective: bool
    experiments: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)
    confirmed: list[dict[str, Any]] = field(default_factory=list)
    false_positives: list[dict[str, Any]] = field(default_factory=list)
    false_negatives: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "defective": self.defective,
            "experiments": self.experiments,
            "outcomes": dict(self.outcomes),
            "confirmed": list(self.confirmed),
            "false_positives": list(self.false_positives),
            "false_negatives": list(self.false_negatives),
        }


def _causal_failure(
    score: FamilyScore,
    outcomes: dict[str, int],
) -> str:
    """Why the engine missed a defect it should have found, derived
    from the recorded investigation state only."""
    if score.experiments == 0:
        return "no_hypothesis_generated"
    if outcomes.get("blocked", 0) == score.experiments:
        return "probe_blocked_by_authority"
    if outcomes.get("inconclusive", 0) == score.experiments:
        return "evidence_gap"
    if outcomes.get("clean", 0) == score.experiments:
        return "differential_not_discriminating"
    if outcomes.get("inconclusive", 0):
        return "partial_evidence_gap"
    return "unclassified"


def _label_leakage(
    state: InvestigationState, spec: InstanceSpec,
) -> list[str]:
    """Assert hidden labels never entered the investigation state.

    The defect flags and their values live only in the spec and this
    evaluator. The state must carry none of them."""
    forbidden = (
        "identity_read_enforced", "identity_mutation_enforced",
        "workflow_identity_enforced", "order_enforced",
        "price_authoritative", "coupon_owner_enforced",
        "balance_enforced", "ground_truth", "expected_verdict",
        "oracle", "profile",
    )
    hits: list[str] = []
    for record in state.hypotheses:
        text = f"{record.statement} {record.origin}".lower()
        for token in forbidden:
            if token in text:
                hits.append(
                    f"hypothese {record.hypothesis_id}: {token}")
    for experiment in state.experiments:
        text = (f"{experiment.description} "
                f"{experiment.rationale}").lower()
        for token in forbidden:
            if token in text:
                hits.append(
                    f"experiment {experiment.experiment_id}: {token}")
    return hits


def evaluate_instance(
    spec: InstanceSpec,
    state: InvestigationState,
) -> dict[str, Any]:
    """Score one completed investigation state against its spec."""
    leakage = _label_leakage(state, spec)
    confirmed_records = [
        record for record in state.hypotheses
        if record.origin.startswith(_RECON_ORIGIN)
        and record.status.value == "confirmed"
    ]
    # family score skeleton
    scores: dict[str, FamilyScore] = {}
    for family in FAMILY_FLAGS:
        scores[family] = FamilyScore(
            family=family, defective=family_defective(spec, family))
    # outcome tally per engine family (experiments, not statements)
    for experiment in state.experiments:
        score = scores.get(experiment.family)
        if score is None:
            continue
        score.experiments += 1
        outcome = state.experiment_outcomes.get(
            experiment.experiment_id, "unknown")
        score.outcomes[outcome] = score.outcomes.get(outcome, 0) + 1
    # confirmed findings: match against the defect layout
    for record in confirmed_records:
        score = scores.get(record.family)
        if score is None:
            continue
        entry = {
            "hypothesis_id": record.hypothesis_id,
            "statement": record.statement,
            "origin": record.origin,
        }
        wf_id = _workflow_of(record.statement, spec)
        if wf_id is not None:
            entry["workflow"] = wf_id
            score.confirmed.append(entry)
        else:
            score.confirmed.append(entry)
    # per-family verdicts
    for family, score in scores.items():
        if family in ("WORKFLOW_IDENTITY", "WORKFLOW_ORDER"):
            # per-workflow scoring
            flag = FAMILY_FLAGS[family][0]
            mapping = getattr(spec, flag)
            confirmed_wfs = {
                entry.get("workflow") for entry in score.confirmed}
            for wf_id, enforced in mapping.items():
                if enforced:
                    continue  # safe workflow: nothing to find
                if wf_id in confirmed_wfs:
                    continue  # found
                fn_outcomes = score.outcomes
                score.false_negatives.append({
                    "workflow": wf_id,
                    "causal_failure": _causal_failure(
                        score, fn_outcomes),
                })
            for entry in score.confirmed:
                wf_id = entry.get("workflow")
                if workflow_defective(spec, family, wf_id):
                    continue
                score.false_positives.append({
                    **entry,
                    "causal_failure": "oracle_accepted_safe_target",
                })
        else:
            if score.defective:
                if not score.confirmed:
                    score.false_negatives.append({
                        "causal_failure": _causal_failure(
                            score, score.outcomes),
                    })
            else:
                for entry in score.confirmed:
                    score.false_positives.append({
                        **entry,
                        "causal_failure": "oracle_accepted_safe_target",
                    })
    tp = sum(len(s.confirmed) - len(s.false_positives)
             for s in scores.values())
    fp = sum(len(s.false_positives) for s in scores.values())
    fn = sum(len(s.false_negatives) for s in scores.values())
    defective_families = sum(
        1 for s in scores.values() if s.defective)
    return {
        "instance_id": spec.instance_id,
        "seed": spec.seed,
        "blind": spec.blind,
        "leakage_findings": leakage,
        "families": {
            family: score.as_dict()
            for family, score in scores.items()},
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "defective_families": defective_families,
    }


def corpus_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-instance results (never a substitute for them)."""
    tp = sum(r["true_positives"] for r in results)
    fp = sum(r["false_positives"] for r in results)
    fn = sum(r["false_negatives"] for r in results)
    per_family: dict[str, dict[str, int]] = {}
    causal: dict[str, int] = {}
    for r in results:
        for family, s in r["families"].items():
            bucket = per_family.setdefault(family, {
                "confirmed": 0, "false_positives": 0,
                "false_negatives": 0})
            bucket["confirmed"] += len(s["confirmed"])
            bucket["false_positives"] += len(s["false_positives"])
            bucket["false_negatives"] += len(s["false_negatives"])
        for s in r["families"].values():
            for negative in s["false_negatives"]:
                key = negative["causal_failure"]
                causal[key] = causal.get(key, 0) + 1
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    return {
        "instances": len(results),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "per_family": per_family,
        "causal_failures": causal,
        "leakage_findings": sum(
            len(r["leakage_findings"]) for r in results),
    }
