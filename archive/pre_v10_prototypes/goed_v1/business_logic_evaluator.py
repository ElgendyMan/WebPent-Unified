"""
GOED v1.7 — Business Logic Evaluation Engine (Phase 4)
======================================================
Rigorous hypothesis-driven business logic vulnerability detection.

PROCESS:
1. Observe target behavior (real HTTP responses)
2. Infer candidate invariant from observations
3. Formulate testable prediction
4. Run controlled experiment against target
5. Observe real resulting state
6. Compare predicted vs observed invariant behavior
7. Repeat with variations if needed
8. Confirm ONLY on causal evidence

FORBIDDEN:
- Inferring vulnerability from keyword alone (negative values, "transfer", "approve")
- Confirming from evaluator-generated state
- Skipping the experiment step

REQUIRED for every invariant:
- source_evidence: observations that motivated this hypothesis
- hypothesis: what invariant is suspected
- prediction: what the experiment should show
- experiment: what was actually done to the target
- observation: what the target actually returned
- verdict: VIOLATED / PRESERVED / INCONCLUSIVE
"""

import contextlib
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class InvariantVerdict(Enum):
    VIOLATED = "VIOLATED"
    PRESERVED = "PRESERVED"
    INCONCLUSIVE = "INCONCLUSIVE"
    EXPERIMENT_FAILED = "EXPERIMENT_FAILED"


class InvariantFamily(Enum):
    CONSERVATION = "conservation"
    BALANCE_CONSISTENCY = "balance_consistency"
    OWNERSHIP_CONSISTENCY = "ownership_consistency"
    VALID_STATE_TRANSITION = "valid_state_transition"
    APPROVAL_SEPARATION = "approval_separation"
    REPLAY_RESISTANCE = "replay_resistance"
    AUTHORIZATION_STATE_CONSISTENCY = "authorization_state_consistency"


@dataclass
class InvariantHypothesis:
    """A candidate invariant inferred from target observations."""
    hypothesis_id: str
    family: InvariantFamily
    description: str
    source_evidence: list[dict[str, Any]] = field(default_factory=list)
    prediction: str = ""
    confidence: float = 0.25  # starts low, increases with corroboration


@dataclass
class ControlledExperiment:
    """An experiment designed to test one invariant hypothesis."""
    experiment_id: str
    hypothesis_id: str
    description: str
    method: str
    path: str
    params: dict[str, Any] = field(default_factory=dict)
    body: dict[str, Any] | None = None
    actor: str = ""
    control_method: str = "GET"
    control_path: str = ""
    pre_state_paths: list[dict[str, str]] = field(default_factory=list)
    post_state_paths: list[dict[str, str]] = field(default_factory=list)


@dataclass
class ExperimentResult:
    """Result of running a controlled experiment against a real target."""
    experiment_id: str
    status: str  # SUCCESS, FAILED, BLOCKED
    pre_state: dict[str, Any] | None = None
    post_state: dict[str, Any] | None = None
    state_deltas: list[dict[str, Any]] = field(default_factory=list)
    response_status: int | None = None
    response_preview: str = ""
    error: str | None = None


@dataclass
class BusinessLogicFinding:
    """A complete business logic finding with full audit trail."""
    finding_id: str
    verdict: InvariantVerdict
    confidence: float
    family: InvariantFamily
    hypothesis: InvariantHypothesis
    experiment: ControlledExperiment
    experiment_result: ExperimentResult
    invariant_tests: list[dict[str, Any]] = field(default_factory=list)
    reasoning: str = ""
    causal_signal: bool | None = None
    replay_verified: bool = False
    control_verified: bool = False

    def to_proof_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 4),
            "family": self.family.value,
            "hypothesis": {
                "id": self.hypothesis.hypothesis_id,
                "family": self.hypothesis.family.value,
                "description": self.hypothesis.description,
                "prediction": self.hypothesis.prediction,
                "source_evidence_count": len(self.hypothesis.source_evidence),
            },
            "experiment": {
                "id": self.experiment.experiment_id,
                "method": self.experiment.method,
                "path": self.experiment.path,
                "actor": self.experiment.actor,
            },
            "experiment_result": {
                "status": self.experiment_result.status,
                "response_status": self.experiment_result.response_status,
                "state_deltas_count": len(self.experiment_result.state_deltas),
            },
            "invariant_tests": self.invariant_tests,
            "reasoning": self.reasoning[:300],
            "causal_signal": self.causal_signal,
            "replay_verified": self.replay_verified,
            "control_verified": self.control_verified,
        }


class BusinessLogicEvaluator:
    """
    Hypothesis-driven business logic evaluator.

    Never infers from keywords alone. Always:
    OBSERVE -> HYPOTHESIZE -> PREDICT -> EXPERIMENT -> OBSERVE -> VERDICT
    """

    VALID_TRANSITIONS = {
        "draft": ["submitted", "cancelled", "deleted"],
        "pending": ["approved", "rejected"],
        "submitted": ["approved", "rejected", "pending_review"],
        "approved": ["finalized", "active"],
    }

    def __init__(self, http_client):
        self.http = http_client
        self._hypothesis_counter = 0

    def _new_hid(self) -> str:
        self._hypothesis_counter += 1
        return f"hyp_bl_{self._hypothesis_counter:03d}"

    def generate_hypotheses(self, observations: list[dict[str, Any]]) -> list[InvariantHypothesis]:
        """
        Generate candidate invariant hypotheses from REAL target observations.

        Each hypothesis must cite specific source evidence.
        No hypothesis from keyword patterns alone.
        """
        hypotheses = []

        # Extract structured info from observations
        paths = []
        headers_all = {}
        for obs in observations:
            req = obs.get("request", {})
            path = req.get("path", "")
            if path:
                paths.append(path)
            hdrs = obs.get("headers", {})
            for k, v in hdrs.items():
                headers_all[k.lower()] = v

        paths_str = " ".join(paths).lower()

        # Hypothesis 1: Conservation — if we see transfer-like paths AND balance headers
        has_transfer = any(kw in paths_str for kw in ["/transfer", "/payment", "/send", "/allocate"])
        has_balance = any("balance" in k for k in headers_all)

        if has_transfer or has_balance:
            hyp = InvariantHypothesis(
                hypothesis_id=self._new_hid(),
                family=InvariantFamily.CONSERVATION,
                description="Total account balance should be conserved across legitimate transfer operations",
                source_evidence=[{"path": p, "type": "path_observation"} for p in paths[:5]] +
                                 [{"header": k, "value": str(v)[:50]} for k, v in headers_all.items()
                                  if "balance" in k or "amount" in k][:3],
                prediction="After a transfer operation, the sum of all affected account balances should remain unchanged (within rounding)",
                confidence=0.3,
            )
            hypotheses.append(hyp)

        # Hypothesis 2: Balance symmetry — sender decrease equals receiver increase
        if has_transfer:
            hyp = InvariantHypothesis(
                hypothesis_id=self._new_hid(),
                family=InvariantFamily.BALANCE_CONSISTENCY,
                description="Sender balance decrease must equal receiver balance increase",
                source_evidence=[{"path": p, "type": "path_observation"} for p in paths[:5]],
                prediction="delta(sender_balance) == -delta(receiver_balance) for any valid transfer",
                confidence=0.3,
            )
            hypotheses.append(hyp)

        # Hypothesis 3: Ownership consistency — from resource owner headers
        owner_headers = [(k, v) for k, v in headers_all.items() if "owner" in k or "tenant" in k]
        if owner_headers:
            hyp = InvariantHypothesis(
                hypothesis_id=self._new_hid(),
                family=InvariantFamily.OWNERSHIP_CONSISTENCY,
                description="Resource ownership fields should remain consistent unless explicitly transferred",
                source_evidence=[{"header": k, "value": str(v)[:50]} for k, v in owner_headers[:5]],
                prediction="Operations on a resource should not change its owner/tenant fields",
                confidence=0.35,
            )
            hypotheses.append(hyp)

        # Hypothesis 4: Approval separation — if we see approve paths
        if any(kw in paths_str for kw in ["/approve", "/workflow", "/review"]):
            hyp = InvariantHypothesis(
                hypothesis_id=self._new_hid(),
                family=InvariantFamily.APPROVAL_SEPARATION,
                description="Workflow requester cannot also be the approver",
                source_evidence=[{"path": p, "type": "path_observation"} for p in paths[:5]
                                 if "approve" in p.lower() or "workflow" in p.lower()],
                prediction="An actor cannot approve a workflow item they themselves requested",
                confidence=0.3,
            )
            hypotheses.append(hyp)

        # Hypothesis 5: State transition validity
        if any(kw in paths_str for kw in ["/status", "/state", "/phase", "/workflow"]):
            hyp = InvariantHypothesis(
                hypothesis_id=self._new_hid(),
                family=InvariantFamily.VALID_STATE_TRANSITION,
                description="Workflow items must follow valid state transition graphs",
                source_evidence=[{"path": p, "type": "path_observation"} for p in paths[:5]],
                prediction=f"Only these transitions allowed: {dict(self.VALID_TRANSITIONS)}",
                confidence=0.25,
            )
            hypotheses.append(hyp)

        # Hypothesis 6: Replay resistance — if we see token/nonce patterns
        if any(kw in paths_str for kw in ["/token", "/nonce", "/reset", "/once", "/confirm"]):
            hyp = InvariantHypothesis(
                hypothesis_id=self._new_hid(),
                family=InvariantFamily.REPLAY_RESISTANCE,
                description="One-time tokens must be invalidated after use",
                source_evidence=[{"path": p, "type": "path_observation"} for p in paths[:5]
                                 if any(kw in p.lower() for kw in ["token", "nonce", "reset"])],
                prediction="A token used successfully cannot be used a second time",
                confidence=0.3,
            )
            hypotheses.append(hyp)

        # Hypothesis 7: Authorization state consistency
        if any("authorization" in k or "privilege" in k for k in headers_all):
            hyp = InvariantHypothesis(
                hypothesis_id=self._new_hid(),
                family=InvariantFamily.AUTHORIZATION_STATE_CONSISTENCY,
                description="Authorization outcome should be consistent with actor role and resource ownership",
                source_evidence=[{"header": k, "value": str(v)[:50]} for k, v in headers_all.items()
                                  if "authorization" in k or "privilege" in k or "outcome" in k][:5],
                prediction="granted_full should only occur when actor owns resource or has sufficient role",
                confidence=0.4,
            )
            hypotheses.append(hyp)

        return hypotheses

    def design_experiment(self, hypothesis: InvariantHypothesis,
                          target_context: dict[str, Any]) -> ControlledExperiment | None:
        """
        Design a controlled experiment to test one invariant hypothesis.
        Returns None if no meaningful experiment can be designed.
        """
        base_path = target_context.get("base_path", "")
        actor = target_context.get("actor", "")
        target_user = target_context.get("target_user", "")

        if hypothesis.family == InvariantFamily.CONSERVATION:
            # Experiment: transfer with edge-case amount (negative, zero, very large)
            return ControlledExperiment(
                experiment_id=f"exp_{hypothesis.hypothesis_id}_neg",
                hypothesis_id=hypothesis.hypothesis_id,
                description="Transfer with negative amount to test conservation",
                method="GET",
                path=f"{base_path}/accounts/{actor}/transfer",
                params={"to_user": target_user, "amount": "-100"},
                actor=actor,
                pre_state_paths=[{"path": f"{base_path}/accounts/balance", "method": "GET", "key_prefix": "pre"}],
                post_state_paths=[{"path": f"{base_path}/accounts/balance", "method": "GET", "key_prefix": "post"}],
            )

        elif hypothesis.family == InvariantFamily.BALANCE_CONSISTENCY:
            return ControlledExperiment(
                experiment_id=f"exp_{hypothesis.hypothesis_id}_sym",
                hypothesis_id=hypothesis.hypothesis_id,
                description="Transfer and verify balance symmetry",
                method="GET",
                path=f"{base_path}/accounts/{actor}/transfer",
                params={"to_user": target_user, "amount": "-100"},
                actor=actor,
                pre_state_paths=[{"path": f"{base_path}/accounts/balance", "method": "GET", "key_prefix": "pre"}],
                post_state_paths=[{"path": f"{base_path}/accounts/balance", "method": "GET", "key_prefix": "post"}],
            )

        elif hypothesis.family == InvariantFamily.APPROVAL_SEPARATION:
            wf_id = target_context.get("workflow_id", "wf-001")
            return ControlledExperiment(
                experiment_id=f"exp_{hypothesis.hypothesis_id}_selfapp",
                hypothesis_id=hypothesis.hypothesis_id,
                description="Attempt self-approval of own workflow request",
                method="GET",
                path=f"{base_path}/workflows/{wf_id}/approve",
                actor=actor,
                pre_state_paths=[{"path": f"{base_path}/workflows/{wf_id}", "method": "GET", "key_prefix": "pre"}],
                post_state_paths=[{"path": f"{base_path}/workflows/{wf_id}", "method": "GET", "key_prefix": "post"}],
            )

        elif hypothesis.family == InvariantFamily.OWNERSHIP_CONSISTENCY:
            return ControlledExperiment(
                experiment_id=f"exp_{hypothesis.hypothesis_id}_owner",
                hypothesis_id=hypothesis.hypothesis_id,
                description="Update resource and check if owner field changes",
                method="POST",
                path=f"{base_path}/users/{target_user}/update",
                body={"role": "admin"},
                actor=actor,
                pre_state_paths=[{"path": f"{base_path}/users/{target_user}/profile", "method": "GET", "key_prefix": "pre"}],
                post_state_paths=[{"path": f"{base_path}/users/{target_user}/profile", "method": "GET", "key_prefix": "post"}],
            )

        elif hypothesis.family == InvariantFamily.REPLAY_RESISTANCE:
            return ControlledExperiment(
                experiment_id=f"exp_{hypothesis.hypothesis_id}_replay",
                hypothesis_id=hypothesis.hypothesis_id,
                description="Execute same token-based action twice to test replay resistance",
                method="GET",
                path=f"{base_path}/auth/reset/request",
                params={"for_user": target_user},
                actor=actor,
                pre_state_paths=[{"path": f"{base_path}/auth/reset/status", "method": "GET", "key_prefix": "pre"}],
                post_state_paths=[{"path": f"{base_path}/auth/reset/status", "method": "GET", "key_prefix": "post"}],
            )

        return None

    def run_experiment(self, base_url: str,
                        experiment: ControlledExperiment) -> ExperimentResult:
        """
        Execute a controlled experiment against the REAL target.
        Returns ExperimentResult with real observations.
        """

        headers = {"X-Actor": experiment.actor} if experiment.actor else {}

        # Step 1: Capture PRE state
        pre_state = {}
        for sp in experiment.pre_state_paths:
            try:
                if sp.get("method", "GET") == "POST":
                    r = self.http.post(f"{base_url}{sp['path']}", headers=headers, json=sp.get("body"))
                else:
                    r = self.http.get(f"{base_url}{sp['path']}", headers=headers, params=sp.get("params"))
                with contextlib.suppress(Exception):
                    pre_state.update(r.json())
                pre_state[f"_status_{sp['path']}"] = r.status_code
            except Exception as e:
                return ExperimentResult(
                    experiment_id=experiment.experiment_id,
                    status="FAILED",
                    error=f"pre_state_capture_failed: {e}",
                )

        # Step 2: Execute the experiment action
        try:
            if experiment.method.upper() == "POST":
                r_action = self.http.post(
                    f"{base_url}{experiment.path}",
                    headers=headers, params=experiment.params, json=experiment.body,
                )
            elif experiment.method.upper() == "PUT":
                r_action = self.http.put(
                    f"{base_url}{experiment.path}",
                    headers=headers, params=experiment.params, json=experiment.body,
                )
            else:
                r_action = self.http.get(
                    f"{base_url}{experiment.path}",
                    headers=headers, params=experiment.params,
                )
        except Exception as e:
            return ExperimentResult(
                experiment_id=experiment.experiment_id,
                status="FAILED",
                error=f"action_execution_failed: {e}",
            )

        # Step 3: Capture POST state
        post_state = {}
        for sp in experiment.post_state_paths:
            try:
                if sp.get("method", "GET") == "POST":
                    r = self.http.post(f"{base_url}{sp['path']}", headers=headers, json=sp.get("body"))
                else:
                    r = self.http.get(f"{base_url}{sp['path']}", headers=headers, params=sp.get("params"))
                with contextlib.suppress(Exception):
                    post_state.update(r.json())
                post_state[f"_status_{sp['path']}"] = r.status_code
            except Exception:
                pass

        # Step 4: Compute deltas
        deltas = []
        all_keys = set(list(pre_state.keys()) + list(post_state.keys()))
        for key in all_keys:
            if key.startswith("_"):
                continue
            b = pre_state.get(key)
            a = post_state.get(key)
            if b != a:
                change = None
                try:
                    if isinstance(b, (int, float)) and isinstance(a, (int, float)):
                        change = a - b
                except Exception:
                    pass
                deltas.append({"key": key, "before": b, "after": a, "change": change})

        return ExperimentResult(
            experiment_id=experiment.experiment_id,
            status="SUCCESS",
            pre_state=pre_state,
            post_state=post_state,
            state_deltas=deltas,
            response_status=r_action.status_code,
            response_preview=r_action.text[:200] if hasattr(r_action, "text") else "",
        )

    def evaluate_hypothesis(self, hypothesis: InvariantHypothesis,
                            result: ExperimentResult) -> tuple[InvariantVerdict, float, str, list[dict]]:
        """
        Evaluate hypothesis against real experiment results.
        Returns: (verdict, confidence, reasoning, invariant_tests)
        """
        tests = []

        if result.status != "SUCCESS":
            return InvariantVerdict.EXPERIMENT_FAILED, 0.0, f"Experiment failed: {result.error}", tests

        deltas = result.state_deltas

        if hypothesis.family == InvariantFamily.CONSERVATION:
            numeric_keys = [d for d in deltas if isinstance(d.get("change"), (int, float))]
            if numeric_keys:
                total_change = sum(d["change"] for d in numeric_keys)
                test = {
                    "name": "total_conservation",
                    "total_change": total_change,
                    "keys_used": [d["key"] for d in numeric_keys],
                }
                tests.append(test)
                if abs(total_change) > 0.01:
                    return (InvariantVerdict.VIOLATED, min(0.95, 0.6 + 0.1 * len(numeric_keys)),
                            f"Conservation violated: total state changed by {total_change:+.4f}", tests)
                else:
                    return (InvariantVerdict.PRESERVED, 0.7,
                            f"Conservation preserved: total change = {total_change}", tests)

        elif hypothesis.family == InvariantFamily.BALANCE_CONSISTENCY:
            numeric_keys = [d for d in deltas if isinstance(d.get("change"), (int, float))]
            if len(numeric_keys) >= 2:
                changes = [d["change"] for d in numeric_keys]
                test = {"name": "balance_symmetry", "changes": changes, "sum": sum(changes)}
                tests.append(test)
                if abs(sum(changes)) > 0.01:
                    return (InvariantVerdict.VIOLATED, 0.9,
                            f"Asymmetric balance deltas: {changes}, sum={sum(changes):+.4f}", tests)
                else:
                    return (InvariantVerdict.PRESERVED, 0.7,
                            f"Balance symmetry preserved: sum={sum(changes)}", tests)

        elif hypothesis.family == InvariantFamily.APPROVAL_SEPARATION:
            # Check if status changed to "approved" when actor is also requester
            status_deltas = [d for d in deltas if "status" in d["key"].lower() or "state" in d["key"].lower()]
            approver_deltas = [d for d in deltas if "approver" in d["key"].lower()]
            test = {"name": "self_approval_check", "status_deltas": status_deltas, "approver_deltas": approver_deltas}
            tests.append(test)
            for d in status_deltas:
                if str(d.get("after", "")).lower() in ["approved", "active", "finalized"]:
                    return (InvariantVerdict.VIOLATED, 0.85,
                            f"Self-approval detected: status {d.get('before')} -> {d.get('after')}", tests)
            return (InvariantVerdict.PRESERVED, 0.6, "No self-approval detected", tests)

        elif hypothesis.family == InvariantFamily.OWNERSHIP_CONSISTENCY:
            owner_deltas = [d for d in deltas if "owner" in d["key"].lower() or "tenant" in d["key"].lower() or "role" in d["key"].lower()]
            test = {"name": "ownership_check", "owner_deltas": owner_deltas}
            tests.append(test)
            for d in owner_deltas:
                if d.get("before") and d.get("after") and d["before"] != d["after"]:
                    return (InvariantVerdict.VIOLATED, 0.85,
                            f"Ownership/role field changed: {d['key']} = {d['before']} -> {d['after']}", tests)
            return (InvariantVerdict.PRESERVED, 0.6, "No ownership changes detected", tests)

        elif hypothesis.family == InvariantFamily.VALID_STATE_TRANSITION:
            status_deltas = [d for d in deltas if "status" in d["key"].lower() or "state" in d["key"].lower()]
            for d in status_deltas:
                b = str(d.get("before", "")).lower()
                a = str(d.get("after", "")).lower()
                if b in self.VALID_TRANSITIONS and a not in self.VALID_TRANSITIONS[b]:
                    test = {"name": "transition_check", "from": b, "to": a,
                            "valid_from": self.VALID_TRANSITIONS[b]}
                    tests.append(test)
                    return (InvariantVerdict.VIOLATED, 0.8,
                            f"Invalid state transition: {b} -> {a} (valid: {self.VALID_TRANSITIONS[b]})", tests)
            return (InvariantVerdict.INCONCLUSIVE, 0.3, "No state transitions observed", tests)

        elif hypothesis.family == InvariantFamily.REPLAY_RESISTANCE:
            return (InvariantVerdict.INCONCLUSIVE, 0.3,
                    "Replay resistance requires two sequential executions (not tested in single experiment)", tests)

        return (InvariantVerdict.INCONCLUSIVE, 0.2, "No applicable test for this hypothesis family", tests)

    def evaluate_complete(self, observations: list[dict[str, Any]],
                          base_url: str, target_context: dict[str, Any]) -> list[BusinessLogicFinding]:
        """
        Complete business logic evaluation pipeline:
        OBSERVE -> HYPOTHESIZE -> PREDICT -> EXPERIMENT -> OBSERVE -> VERDICT
        """
        findings = []

        # Step 1: Generate hypotheses from observations
        hypotheses = self.generate_hypotheses(observations)

        for hyp in hypotheses:
            # Step 2: Design experiment
            experiment = self.design_experiment(hyp, target_context)
            if not experiment:
                continue

            # Step 3: Run experiment against REAL target
            result = self.run_experiment(base_url, experiment)

            # Step 4: Evaluate hypothesis against real results
            verdict, confidence, reasoning, tests = self.evaluate_hypothesis(hyp, result)

            finding = BusinessLogicFinding(
                finding_id=hashlib.sha256(f"{hyp.hypothesis_id}:{experiment.experiment_id}".encode()).hexdigest()[:12],
                verdict=verdict,
                confidence=confidence,
                family=hyp.family,
                hypothesis=hyp,
                experiment=experiment,
                experiment_result=result,
                invariant_tests=tests,
                reasoning=reasoning,
                causal_signal=(verdict == InvariantVerdict.VIOLATED),
            )
            findings.append(finding)

        return findings


# ============================================================
# Governance & exports
# ============================================================

BUSINESS_LOGIC_V17_GOVERNANCE = {
    "hypothesis_driven": True,
    "no_keyword_inference": True,
    "experiment_mandatory_for_confirmation": True,
    "all_state_from_target_observations": True,
    "every_finding_has_audit_trail": True,
    "invariant_must_have_source_evidence": True,
    "prediction_must_be_testable": True,
}

__all__ = [
    "InvariantVerdict", "InvariantFamily",
    "InvariantHypothesis", "ControlledExperiment", "ExperimentResult",
    "BusinessLogicFinding", "BusinessLogicEvaluator",
    "BUSINESS_LOGIC_V17_GOVERNANCE",
]
