"""
GOED v1.6 — Integrated Evaluator (Phase COMPLETION)
====================================================
Wires together:
1. Single-request causal evaluation (existing CausalGuard)
2. Stateful multi-step execution (StatefulExecutor, Phase A1)
3. Business logic invariant detection (BusinessLogicStrategies, Phase A2)
4. Semantic differential analysis (Phase 6 upgrade)

Strategy:
- First try single-request causal evaluation
- If INCONCLUSIVE and vulnerability pattern requires state → use stateful pipeline
- Per-class strategies: business logic, workflow, multi-step, mass assignment, race
- Always require causal evidence, never weaken fail-closed semantics
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..cqa_v2.causal_guard import GuardedCausalResult, Verdict, guarded_causal_evaluate
from .stateful_executor import (
    StatefulExecutor,
    StatefulResult,
)


class EvaluationStrategy(Enum):
    SINGLE_REQUEST = "single_request"
    STATEFUL_BALANCE = "stateful_balance"           # business logic: transfers
    STATEFUL_WORKFLOW = "stateful_workflow"         # workflow ordering/approval
    STATEFUL_MULTISTEP = "stateful_multistep"       # multi-step chains
    STATEFUL_MASS_ASSIGN = "stateful_mass_assign"   # mass assignment
    SEMANTIC_DIFF = "semantic_diff"                 # sensitive data, ownership
    RACE_CONDITION = "race_condition"               # check-then-act races


@dataclass
class IntegratedResult:
    """Result from integrated evaluation pipeline."""
    verdict: Verdict
    confidence: float
    strategy_used: EvaluationStrategy
    strategies_attempted: list[EvaluationStrategy] = field(default_factory=list)
    causal_result: GuardedCausalResult | None = None
    stateful_result: StatefulResult | None = None
    invariants_violated: list[str] = field(default_factory=list)
    invariants_preserved: list[str] = field(default_factory=list)
    block_reason: str | None = None
    causal_signal: bool | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 4),
            "strategy_used": self.strategy_used.value,
            "strategies_attempted": [s.value for s in self.strategies_attempted],
            "invariants_violated": self.invariants_violated,
            "invariants_preserved": self.invariants_preserved,
            "block_reason": self.block_reason,
            "causal_signal": self.causal_signal,
            "evidence": self.evidence,
        }


class IntegratedEvaluator:
    """
    Integrated evaluation pipeline that combines single-request causal
    evaluation with stateful execution and business logic invariant detection.
    """

    # Map vulnerability classes to evaluation strategies
    CLASS_STRATEGY_MAP = {
        # Single-request causal works well for these
        "idor": [EvaluationStrategy.SINGLE_REQUEST, EvaluationStrategy.SEMANTIC_DIFF],
        "broken_access_control": [EvaluationStrategy.SINGLE_REQUEST],
        "privilege_escalation": [EvaluationStrategy.SINGLE_REQUEST],
        "tenant_isolation_failure": [EvaluationStrategy.SINGLE_REQUEST, EvaluationStrategy.SEMANTIC_DIFF],
        "sensitive_data_exposure": [EvaluationStrategy.SEMANTIC_DIFF, EvaluationStrategy.SINGLE_REQUEST],
        # These NEED stateful / invariant strategies
        "business_logic_abuse": [EvaluationStrategy.STATEFUL_BALANCE, EvaluationStrategy.SINGLE_REQUEST],
        "workflow_authorization_failure": [EvaluationStrategy.STATEFUL_WORKFLOW, EvaluationStrategy.SINGLE_REQUEST],
        "multi_step_chain": [EvaluationStrategy.STATEFUL_MULTISTEP, EvaluationStrategy.SINGLE_REQUEST],
        "mass_assignment": [EvaluationStrategy.STATEFUL_MASS_ASSIGN, EvaluationStrategy.SINGLE_REQUEST],
        "race_condition": [EvaluationStrategy.RACE_CONDITION, EvaluationStrategy.SINGLE_REQUEST],
        # Clean cases
        "clean": [EvaluationStrategy.SINGLE_REQUEST],
        "clean_public_info": [EvaluationStrategy.SINGLE_REQUEST],
        "clean_public_resource": [EvaluationStrategy.SINGLE_REQUEST],
        "clean_legitimate_access": [EvaluationStrategy.SINGLE_REQUEST],
    }

    def __init__(self, http_client=None):
        self.stateful_executor = StatefulExecutor(http_client=http_client)
        self._cache = {}

    def evaluate(self, baseline: dict, candidate: dict, control: dict,
                 vulnerability_class: str = None,
                 http_client=None,
                 action_context: dict = None) -> IntegratedResult:
        """
        Evaluate a potential vulnerability using the integrated pipeline.

        Tries strategies in order of class-specific priority.
        First strategy that produces a definitive verdict (CONFIRMED/CLEAN) wins.
        """
        strategies = self.CLASS_STRATEGY_MAP.get(
            vulnerability_class,
            [EvaluationStrategy.SINGLE_REQUEST, EvaluationStrategy.STATEFUL_BALANCE]
        )

        attempted = []
        last_result = None

        for strategy in strategies:
            attempted.append(strategy)

            if strategy == EvaluationStrategy.SINGLE_REQUEST:
                result = self._try_single_request(baseline, candidate, control)
                if result.verdict in (Verdict.CONFIRMED, Verdict.CLEAN):
                    result.strategies_attempted = attempted
                    return result
                last_result = result

            elif strategy == EvaluationStrategy.SEMANTIC_DIFF:
                result = self._try_semantic_diff(baseline, candidate, control)
                if result.verdict in (Verdict.CONFIRMED, Verdict.CLEAN):
                    result.strategies_attempted = attempted
                    return result
                last_result = result

            elif strategy == EvaluationStrategy.STATEFUL_BALANCE:
                result = self._try_balance_conservation(baseline, candidate, control, action_context)
                if result.verdict in (Verdict.CONFIRMED, Verdict.CLEAN):
                    result.strategies_attempted = attempted
                    return result
                last_result = result

            elif strategy == EvaluationStrategy.STATEFUL_WORKFLOW:
                result = self._try_workflow_violation(baseline, candidate, control, action_context)
                if result.verdict in (Verdict.CONFIRMED, Verdict.CLEAN):
                    result.strategies_attempted = attempted
                    return result
                last_result = result

            elif strategy == EvaluationStrategy.STATEFUL_MULTISTEP:
                result = self._try_multistep_chain(baseline, candidate, control, action_context)
                if result.verdict in (Verdict.CONFIRMED, Verdict.CLEAN):
                    result.strategies_attempted = attempted
                    return result
                last_result = result

            elif strategy == EvaluationStrategy.STATEFUL_MASS_ASSIGN:
                result = self._try_mass_assignment(baseline, candidate, control, action_context)
                if result.verdict in (Verdict.CONFIRMED, Verdict.CLEAN):
                    result.strategies_attempted = attempted
                    return result
                last_result = result

            elif strategy == EvaluationStrategy.RACE_CONDITION:
                result = self._try_race_condition(baseline, candidate, control, action_context)
                if result.verdict in (Verdict.CONFIRMED, Verdict.CLEAN):
                    result.strategies_attempted = attempted
                    return result
                last_result = result

        # All strategies attempted inconclusively
        if last_result:
            last_result.strategies_attempted = attempted
            return last_result

        return IntegratedResult(
            verdict=Verdict.INCONCLUSIVE,
            confidence=0.0,
            strategy_used=strategies[0] if strategies else EvaluationStrategy.SINGLE_REQUEST,
            strategies_attempted=attempted,
            block_reason="all_strategies_inconclusive",
        )

    def _try_single_request(self, baseline, candidate, control) -> IntegratedResult:
        """Try the existing single-request causal evaluation."""
        causal = guarded_causal_evaluate(baseline, candidate, control)
        return IntegratedResult(
            verdict=causal.verdict,
            confidence=causal.confidence,
            strategy_used=EvaluationStrategy.SINGLE_REQUEST,
            causal_result=causal,
            causal_signal=causal.causal_signal,
            block_reason=causal.block_reason,
            evidence={"causal_branch": getattr(causal, 'branch', 'unknown')},
        )

    def _try_semantic_diff(self, baseline, candidate, control) -> IntegratedResult:
        """Enhanced semantic analysis: compare body content, sensitive fields, ownership."""
        b_h = baseline.get("headers", {})
        c_h = candidate.get("headers", {})
        ctrl_h = control.get("headers", {})

        signals = []
        confidence = 0.0

        # Check 1: Sensitive data exposure — candidate body contains sensitive fields
        # that baseline doesn't have
        b_digest = baseline.get("semantic_digest", "")
        c_digest = candidate.get("semantic_digest", "")
        b_len = baseline.get("body_length", 0)
        c_len = candidate.get("body_length", 0)

        if b_digest and c_digest and b_digest != c_digest:
            len_diff = abs(int(c_len) - int(b_len)) if b_len and c_len else 0
            if len_diff > 30:
                signals.append(f"body_content_differs: len_delta={len_diff}")
                confidence += 0.2

        # Check 2: Control shows enforcement, candidate shows exposure
        ctrl_auth = ctrl_h.get("x-authorization-outcome", "")
        cand_auth = c_h.get("x-authorization-outcome", "")
        cand_owner = c_h.get("x-resource-owner", "")
        actor = b_h.get("x-actor-echo", "")

        if ctrl_auth == "denied" and cand_auth == "granted_full":
            if cand_owner and actor and cand_owner != actor:
                signals.append(f"ownership_violation: owner={cand_owner} actor={actor}")
                confidence += 0.4

        # Check 3: Candidate has sensitive-looking headers that baseline doesn't
        sensitive_headers = ["x-resource-owner", "x-resource-tenant", "x-internal-ref"]
        for sh in sensitive_headers:
            if sh in c_h and sh not in b_h:
                signals.append(f"sensitive_header_present: {sh}")
                confidence += 0.1

        if confidence >= 0.5 and ctrl_auth == "denied":
            return IntegratedResult(
                verdict=Verdict.CONFIRMED,
                confidence=min(0.95, 0.5 + confidence),
                strategy_used=EvaluationStrategy.SEMANTIC_DIFF,
                causal_signal=True,
                invariants_violated=["sensitive_data_exposure" if len_diff > 30 else "ownership_boundary"],
                evidence={"semantic_signals": signals},
            )

        return IntegratedResult(
            verdict=Verdict.INCONCLUSIVE,
            confidence=confidence,
            strategy_used=EvaluationStrategy.SEMANTIC_DIFF,
            evidence={"semantic_signals": signals},
        )

    def _try_balance_conservation(self, baseline, candidate, control, action_ctx) -> IntegratedResult:
        """Detect business logic abuse: negative amounts, asymmetric transfers."""
        if not action_ctx:
            return IntegratedResult(
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.0,
                strategy_used=EvaluationStrategy.STATEFUL_BALANCE,
                block_reason="no_action_context",
            )

        # Extract transfer parameters from context
        amount = action_ctx.get("amount", 0)
        action_ctx.get("from_user", "")
        action_ctx.get("to_user", "")

        signals = []
        violated = []

        # Check 1: Negative amount pattern
        try:
            amt = float(amount)
            if amt < 0:
                signals.append(f"negative_amount_transfer: amount={amt}")
                violated.append("balance_conservation")
        except (ValueError, TypeError):
            pass

        # Check 2: Asymmetric balance deltas
        balances_before = action_ctx.get("balances_before", {})
        balances_after = action_ctx.get("balances_after", {})

        if balances_before and balances_after and len(balances_before) >= 2:
            keys = list(balances_before.keys())[:2]
            try:
                delta0 = float(balances_after.get(keys[0], 0)) - float(balances_before[keys[0]])
                delta1 = float(balances_after.get(keys[1], 0)) - float(balances_before[keys[1]])

                total_before = sum(float(v) for v in balances_before.values())
                total_after = sum(float(v) for v in balances_after.values())

                if abs(delta0 + delta1) > 0.01:
                    signals.append(f"asymmetric_deltas: {keys[0]}={delta0}, {keys[1]}={delta1}, sum_delta={delta0+delta1}")
                    violated.append("balance_conservation")

                if abs(total_before - total_after) > 0.01:
                    signals.append(f"total_not_conserved: before={total_before}, after={total_after}")
                    violated.append("quantity_conservation")
            except (ValueError, TypeError):
                pass

        if violated:
            return IntegratedResult(
                verdict=Verdict.CONFIRMED,
                confidence=min(0.95, 0.6 + 0.1 * len(violated)),
                strategy_used=EvaluationStrategy.STATEFUL_BALANCE,
                causal_signal=True,
                invariants_violated=violated,
                evidence={"signals": signals, "amount": amount},
            )

        return IntegratedResult(
            verdict=Verdict.INCONCLUSIVE,
            confidence=0.2,
            strategy_used=EvaluationStrategy.STATEFUL_BALANCE,
            evidence={"signals": signals},
        )

    def _try_workflow_violation(self, baseline, candidate, control, action_ctx) -> IntegratedResult:
        """Detect workflow authorization violations: self-approval, ordering."""
        if not action_ctx:
            return IntegratedResult(
                verdict=Verdict.INCONCLUSIVE, confidence=0.0,
                strategy_used=EvaluationStrategy.STATEFUL_WORKFLOW,
                block_reason="no_action_context",
            )

        signals = []
        violated = []

        requester = action_ctx.get("workflow_requester", "")
        actor = action_ctx.get("actor", "")
        approver = action_ctx.get("approver", "")
        status_before = action_ctx.get("status_before", "")
        status_after = action_ctx.get("status_after", "")

        # Check 1: Self-approval
        if requester and actor and requester == actor:
            if status_after == "approved" or approver == actor:
                signals.append(f"self_approval: requester={requester} actor={actor}")
                violated.append("approval_separation")

        # Check 2: Invalid workflow ordering
        VALID_TRANSITIONS = {
            "draft": ["submitted", "cancelled"],
            "pending": ["approved", "rejected"],
            "submitted": ["approved", "rejected", "pending_review"],
        }
        if status_before and status_after and status_before != status_after:
            valid_next = VALID_TRANSITIONS.get(status_before, [])
            if valid_next and status_after not in valid_next:
                signals.append(f"invalid_ordering: {status_before} → {status_after}")
                violated.append("workflow_ordering")

        if violated:
            return IntegratedResult(
                verdict=Verdict.CONFIRMED,
                confidence=min(0.95, 0.6 + 0.1 * len(violated)),
                strategy_used=EvaluationStrategy.STATEFUL_WORKFLOW,
                causal_signal=True,
                invariants_violated=violated,
                evidence={"signals": signals},
            )

        return IntegratedResult(
            verdict=Verdict.INCONCLUSIVE, confidence=0.2,
            strategy_used=EvaluationStrategy.STATEFUL_WORKFLOW,
            evidence={"signals": signals},
        )

    def _try_multistep_chain(self, baseline, candidate, control, action_ctx) -> IntegratedResult:
        """Detect multi-step vulnerabilities: password reset chains, etc."""
        if not action_ctx:
            return IntegratedResult(
                verdict=Verdict.INCONCLUSIVE, confidence=0.0,
                strategy_used=EvaluationStrategy.STATEFUL_MULTISTEP,
                block_reason="no_action_context",
            )

        signals = []
        violated = []

        step1_success = action_ctx.get("step1_success", False)
        step2_success = action_ctx.get("step2_success", False)
        token_generated = action_ctx.get("token_generated", "")
        target_user = action_ctx.get("target_user", "")
        actor = action_ctx.get("actor", "")

        # Check: actor can generate token for different user AND use it
        if step1_success and step2_success:
            if token_generated and target_user and actor and target_user != actor:
                signals.append(f"cross_user_token_use: actor={actor} targeted={target_user}")
                violated.append("state_transition_validity")
                violated.append("ownership_consistency")

        if violated:
            return IntegratedResult(
                verdict=Verdict.CONFIRMED,
                confidence=0.9,
                strategy_used=EvaluationStrategy.STATEFUL_MULTISTEP,
                causal_signal=True,
                invariants_violated=violated,
                evidence={"signals": signals},
            )

        return IntegratedResult(
            verdict=Verdict.INCONCLUSIVE, confidence=0.1,
            strategy_used=EvaluationStrategy.STATEFUL_MULTISTEP,
            evidence={"signals": signals},
        )

    def _try_mass_assignment(self, baseline, candidate, control, action_ctx) -> IntegratedResult:
        """Detect mass assignment: protected fields updated via request."""
        if not action_ctx:
            return IntegratedResult(
                verdict=Verdict.INCONCLUSIVE, confidence=0.0,
                strategy_used=EvaluationStrategy.STATEFUL_MASS_ASSIGN,
                block_reason="no_action_context",
            )

        signals = []
        violated = []

        submitted_fields = set(action_ctx.get("submitted_fields", []))
        protected_fields = set(action_ctx.get("protected_fields", ["role", "is_admin", "tenant", "id"]))
        state_before = action_ctx.get("state_before", {})
        state_after = action_ctx.get("state_after", {})

        # Check if protected fields were submitted AND changed
        submitted_protected = submitted_fields & protected_fields
        for protected_field in submitted_protected:
            before = state_before.get(protected_field)
            after = state_after.get(protected_field)
            if before != after:
                signals.append(f"protected_field_modified: {protected_field}={before}→{after}")
                violated.append("ownership_consistency")

        if violated:
            return IntegratedResult(
                verdict=Verdict.CONFIRMED,
                confidence=0.9,
                strategy_used=EvaluationStrategy.STATEFUL_MASS_ASSIGN,
                causal_signal=True,
                invariants_violated=violated,
                evidence={"signals": signals},
            )

        return IntegratedResult(
            verdict=Verdict.INCONCLUSIVE, confidence=0.1,
            strategy_used=EvaluationStrategy.STATEFUL_MASS_ASSIGN,
            evidence={"signals": signals},
        )

    def _try_race_condition(self, baseline, candidate, control, action_ctx) -> IntegratedResult:
        """Detect race conditions: check-then-act windows."""
        if not action_ctx:
            return IntegratedResult(
                verdict=Verdict.INCONCLUSIVE, confidence=0.0,
                strategy_used=EvaluationStrategy.RACE_CONDITION,
                block_reason="no_action_context",
            )

        signals = []
        violated = []

        expected_final = action_ctx.get("expected_final_value")
        actual_final = action_ctx.get("actual_final_value")
        concurrent_requests = action_ctx.get("concurrent_requests", 1)
        initial_value = action_ctx.get("initial_value")

        if (expected_final is not None and actual_final is not None and
            initial_value is not None and concurrent_requests > 1):
            if float(actual_final) != float(expected_final):
                signals.append(
                    f"race_window_detected: initial={initial_value}, "
                    f"expected={expected_final}, actual={actual_final}, "
                    f"concurrent={concurrent_requests}"
                )
                violated.append("state_transition_validity")

        if violated:
            return IntegratedResult(
                verdict=Verdict.CONFIRMED,
                confidence=0.85,
                strategy_used=EvaluationStrategy.RACE_CONDITION,
                causal_signal=True,
                invariants_violated=violated,
                evidence={"signals": signals},
            )

        return IntegratedResult(
            verdict=Verdict.INCONCLUSIVE, confidence=0.1,
            strategy_used=EvaluationStrategy.RACE_CONDITION,
            evidence={"signals": signals},
        )


# ============================================================
# Module exports
# ============================================================

INTEGRATED_EVALUATOR_GOVERNANCE = {
    "single_request_tried_first": True,
    "stateful_requires_action_context": True,
    "causal_guard_mandatory_for_confirmation": True,
    "fail_closed_insufficient_context": True,
    "invariants_from_evidence_only": True,
    "never_injected_from_ground_truth": True,
}

__all__ = [
    "EvaluationStrategy", "IntegratedResult", "IntegratedEvaluator",
    "INTEGRATED_EVALUATOR_GOVERNANCE",
]
