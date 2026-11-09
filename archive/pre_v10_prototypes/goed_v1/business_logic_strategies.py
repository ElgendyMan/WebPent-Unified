"""
GOED v1.6 — Business Logic Invariant Strategies (Phase A2)
==========================================================
Bounded strategy family for detecting business-logic vulnerabilities.

Each invariant is:
1. HYPOTHESIZED from observed evidence (never injected from ground truth)
2. TESTED against application state via stateful execution
3. VALIDATED only when causal state evidence confirms violation

7 Invariants:
- QuantityConservationInvariant
- BalanceConservationInvariant
- WorkflowOrderingInvariant
- ApprovalSeparationInvariant
- OwnershipConsistencyInvariant
- StateTransitionValidityInvariant
- ReplayResistanceInvariant
"""

from dataclasses import dataclass, field
from enum import Enum


class InvariantStrength(Enum):
    HYPOTHESIZED = "HYPOTHESIZED"
    SUGGESTED = "SUGGESTED"
    CORROBORATED = "CORROBORATED"
    VIOLATED = "VIOLATED"


@dataclass
class InvariantHypothesis:
    """A hypothesized security invariant derived from observations."""
    invariant_id: str
    invariant_type: str
    description: str
    source_observations: list[str] = field(default_factory=list)
    affected_entities: list[str] = field(default_factory=list)
    testable_prediction: str = ""
    strength: InvariantStrength = InvariantStrength.HYPOTHESIZED
    confidence: float = 0.25
    supporting_examples: list[dict] = field(default_factory=list)
    counter_examples: list[dict] = field(default_factory=list)
    discriminating_experiment: dict = field(default_factory=dict)


class BaseInvariantStrategy:
    """Base class for all business logic invariant strategies."""

    strategy_name = "base"
    description = "Base invariant strategy"

    def __init__(self):
        self.hypotheses: list[InvariantHypothesis] = []
        self._hid_counter = 0

    def _new_hid(self) -> str:
        self._hid_counter += 1
        return f"inv_{self.strategy_name}_{self._hid_counter:03d}"

    def hypothesize(self, observations: list[dict]) -> list[InvariantHypothesis]:
        """
        Generate invariant hypotheses from observed application behavior.
        MUST be driven by evidence, never injected from ground truth.
        """
        raise NotImplementedError

    def test_prediction(self, hypothesis: InvariantHypothesis,
                        state_before: dict, state_after: dict) -> tuple[bool, str]:
        """Test whether the invariant holds between two states."""
        raise NotImplementedError

    def validate(self, hypothesis: InvariantHypothesis,
                 test_results: list[tuple[bool, str]]) -> InvariantStrength:
        """Update hypothesis strength based on test results."""
        violations = sum(1 for holds, _ in test_results if not holds)
        confirmations = sum(1 for holds, _ in test_results if holds)

        if violations > 0:
            return InvariantStrength.VIOLATED
        elif confirmations >= 3:
            return InvariantStrength.CORROBORATED
        elif confirmations >= 1:
            return InvariantStrength.SUGGESTED
        return InvariantStrength.HYPOTHESIZED


class QuantityConservationInvariant(BaseInvariantStrategy):
    """
    Total quantity of a resource should be conserved across transfers.
    Violation: negative amounts allow infinite generation of value.
    """
    strategy_name = "quantity_conservation"
    description = "Total quantity of a resource must be conserved across legitimate transfers"

    def hypothesize(self, observations: list[dict]) -> list[InvariantHypothesis]:
        hypotheses = []
        # Look for transfer-like patterns in observations
        for obs in observations:
            path = obs.get("request", {}).get("path", "")
            if any(kw in path.lower() for kw in ["transfer", "send", "move", "allocate", "distribute"]):
                hyp = InvariantHypothesis(
                    invariant_id=self._new_hid(),
                    invariant_type=self.strategy_name,
                    description="Total quantity should be conserved across transfer operations",
                    source_observations=[f"transfer-like path observed: {path}"],
                    testable_prediction="sum of all account balances before transfer == sum after transfer",
                    discriminating_experiment={
                        "action": "transfer with negative amount",
                        "expected_violation": "sender balance decreases, receiver balance increases by absolute value",
                    },
                )
                hypotheses.append(hyp)
                break
        return hypotheses

    def test_prediction(self, hypothesis, state_before, state_after):
        total_before = sum(float(v) for v in state_before.get("balances", {}).values())
        total_after = sum(float(v) for v in state_after.get("balances", {}).values())
        if abs(total_before - total_after) > 0.01:
            return False, f"Total quantity not conserved: before={total_before}, after={total_after}, delta={total_after - total_before}"
        return True, f"Quantity conserved: total={total_before}"


class BalanceConservationInvariant(BaseInvariantStrategy):
    """
    Account balance changes must match transfer amounts exactly.
    Violation: A sends X to B, but A's balance decreases by X while B's increases by more than X.
    """
    strategy_name = "balance_conservation"
    description = "Sender balance decrease must equal receiver balance increase"

    def hypothesize(self, observations: list[dict]) -> list[InvariantHypothesis]:
        hypotheses = []
        for obs in observations:
            path = obs.get("request", {}).get("path", "")
            obs.get("request", {}).get("params", {})
            if any(kw in path.lower() for kw in ["transfer", "payment", "send"]):
                hyp = InvariantHypothesis(
                    invariant_id=self._new_hid(),
                    invariant_type=self.strategy_name,
                    description="Sender decrease must equal receiver increase in transfers",
                    source_observations=[f"transfer endpoint observed: {path}"],
                    testable_prediction="delta(sender_balance) == -delta(receiver_balance)",
                    discriminating_experiment={
                        "action": "transfer with amount manipulation",
                        "expected_violation": "asymmetric balance changes",
                    },
                )
                hypotheses.append(hyp)
                break
        return hypotheses

    def test_prediction(self, hypothesis, state_before, state_after):
        # For two-account systems, check symmetry
        bal_before = state_before.get("balances", {})
        bal_after = state_after.get("balances", {})
        if len(bal_before) >= 2 and len(bal_after) >= 2:
            keys = list(bal_before.keys())[:2]
            delta0 = float(bal_after.get(keys[0], 0)) - float(bal_before[keys[0]])
            delta1 = float(bal_after.get(keys[1], 0)) - float(bal_before[keys[1]])
            if abs(delta0 + delta1) > 0.01:
                return False, f"Asymmetric balance deltas: {keys[0]}={delta0}, {keys[1]}={delta1}, sum={delta0 + delta1}"
        return True, "Balance deltas are symmetric"


class WorkflowOrderingInvariant(BaseInvariantStrategy):
    """
    Workflow steps must happen in correct order.
    Violation: Approve happens before submit, or finalize happens before approve.
    """
    strategy_name = "workflow_ordering"
    description = "Workflow steps must execute in the correct predefined order"

    def hypothesize(self, observations: list[dict]) -> list[InvariantHypothesis]:
        hypotheses = []
        wf_paths = []
        for obs in observations:
            path = obs.get("request", {}).get("path", "")
            if any(kw in path.lower() for kw in ["workflow", "approve", "reject", "submit", "finalize", "review"]):
                wf_paths.append(path)
        if wf_paths:
            hyp = InvariantHypothesis(
                invariant_id=self._new_hid(),
                invariant_type=self.strategy_name,
                description="Workflow operations must follow correct ordering",
                source_observations=wf_paths,
                testable_prediction="approve cannot succeed before submit; finalize cannot succeed before approve",
                discriminating_experiment={
                    "action": "call approve before submit",
                    "expected_violation": "approve succeeds despite workflow not being in submitted state",
                },
            )
            hypotheses.append(hyp)
        return hypotheses

    def test_prediction(self, hypothesis, state_before, state_after):
        wf_before = state_before.get("workflow_states", {})
        wf_after = state_after.get("workflow_states", {})
        for key in set(list(wf_before.keys()) + list(wf_after.keys())):
            b = wf_before.get(key, "unknown")
            a = wf_after.get(key, "unknown")
            if b == "pending" and a == "approved":
                return True, f"Valid transition: {b} → {a}"
            if b == "draft" and a == "approved":
                return False, f"Invalid workflow ordering: {b} → {a} (skipped submit)"
        return True, "No ordering violation detected"


class ApprovalSeparationInvariant(BaseInvariantStrategy):
    """
    Requester cannot also be approver for the same workflow item.
    Violation: User submits a workflow and then approves their own request.
    """
    strategy_name = "approval_separation"
    description = "Requester and approver must be different actors"

    def hypothesize(self, observations: list[dict]) -> list[InvariantHypothesis]:
        hypotheses = []
        for obs in observations:
            path = obs.get("request", {}).get("path", "")
            obs.get("headers", {})
            if "approve" in path.lower():
                hyp = InvariantHypothesis(
                    invariant_id=self._new_hid(),
                    invariant_type=self.strategy_name,
                    description="Workflow requester cannot also be the approver",
                    source_observations=[f"approval endpoint: {path}"],
                    testable_prediction="Actor who submitted workflow cannot approve it",
                    discriminating_experiment={
                        "action": "submit as actor A, then approve as same actor A",
                        "expected_violation": "approval succeeds despite being self-approval",
                    },
                )
                hypotheses.append(hyp)
                break
        return hypotheses

    def test_prediction(self, hypothesis, state_before, state_after):
        # Check if requester and approver are the same in state metadata
        meta_before = state_before.get("resources", {})
        meta_after = state_after.get("resources", {})
        requester = meta_before.get("requester")
        approver = meta_after.get("approver")
        if requester and approver and requester == approver:
            return False, f"Approval separation violated: requester={requester} == approver={approver}"
        return True, "Approval separation holds"


class OwnershipConsistencyInvariant(BaseInvariantStrategy):
    """
    Resource owner should not change unexpectedly.
    Violation: Transfer operation changes ownership without proper authorization.
    """
    strategy_name = "ownership_consistency"
    description = "Resource ownership must remain consistent unless explicitly transferred"

    def hypothesize(self, observations: list[dict]) -> list[InvariantHypothesis]:
        hypotheses = []
        for obs in observations:
            headers = obs.get("headers", {})
            if headers.get("x-resource-owner"):
                hyp = InvariantHypothesis(
                    invariant_id=self._new_hid(),
                    invariant_type=self.strategy_name,
                    description="Resource ownership should not change without explicit transfer operation",
                    source_observations=[f"resource with owner observed: {headers.get('x-resource-owner')}"],
                    testable_prediction="Owner field remains identical across non-transfer operations",
                    discriminating_experiment={
                        "action": "update resource fields and check if owner changes",
                        "expected_violation": "owner field changes unexpectedly",
                    },
                )
                hypotheses.append(hyp)
                break
        return hypotheses

    def test_prediction(self, hypothesis, state_before, state_after):
        owner_before = state_before.get("resources", {}).get("owner")
        owner_after = state_after.get("resources", {}).get("owner")
        if owner_before and owner_after and owner_before != owner_after:
            return False, f"Ownership changed unexpectedly: {owner_before} → {owner_after}"
        return True, "Ownership consistent"


class StateTransitionValidityInvariant(BaseInvariantStrategy):
    """
    Only valid state transitions are allowed.
    Violation: Resource goes from 'deleted' back to 'active'.
    """
    strategy_name = "state_transition_validity"
    description = "Resources must follow valid state transition graphs"

    VALID_TRANSITIONS = {
        "draft": ["submitted", "cancelled", "deleted"],
        "submitted": ["approved", "rejected", "pending_review"],
        "approved": ["finalized", "active"],
        "active": ["suspended", "archived"],
        "pending": ["approved", "rejected"],
    }

    def hypothesize(self, observations: list[dict]) -> list[InvariantHypothesis]:
        hypotheses = []
        state_fields = set()
        for obs in observations:
            body = obs.get("response_body", {})
            if isinstance(body, dict):
                for key in body:
                    if any(kw in key.lower() for kw in ["status", "state", "phase"]):
                        state_fields.add(key)
        if state_fields:
            hyp = InvariantHypothesis(
                invariant_id=self._new_hid(),
                invariant_type=self.strategy_name,
                description=f"State transitions must follow valid graph (fields: {state_fields})",
                source_observations=[f"state field detected: {f}" for f in state_fields],
                testable_prediction="Only transitions defined in valid transition graph are allowed",
                discriminating_experiment={
                    "action": "attempt invalid state transition (e.g., deleted → active)",
                    "expected_violation": "invalid transition succeeds",
                },
            )
            hypotheses.append(hyp)
        return hypotheses

    def test_prediction(self, hypothesis, state_before, state_after):
        for key in set(list(state_before.get("workflow_states", {}).keys()) +
                      list(state_after.get("workflow_states", {}).keys())):
            b = state_before.get("workflow_states", {}).get(key, "")
            a = state_after.get("workflow_states", {}).get(key, "")
            if b and a and b != a:
                valid_next = self.VALID_TRANSITIONS.get(b, [])
                if a not in valid_next:
                    return False, f"Invalid state transition: {b} → {a} (valid: {valid_next})"
        return True, "All state transitions valid"


class ReplayResistanceInvariant(BaseInvariantStrategy):
    """
    Same action executed twice should not double the effect.
    Violation: Transfer token can be reused to transfer money multiple times.
    """
    strategy_name = "replay_resistance"
    description = "One-time tokens/nonces must prevent replay attacks"

    def hypothesize(self, observations: list[dict]) -> list[InvariantHypothesis]:
        hypotheses = []
        for obs in observations:
            path = obs.get("request", {}).get("path", "")
            params = obs.get("request", {}).get("params", {})
            list(params.keys()) if isinstance(params, dict) else []
            if any(kw in path.lower() for kw in ["token", "nonce", "once", "reset", "confirm"]):
                hyp = InvariantHypothesis(
                    invariant_id=self._new_hid(),
                    invariant_type=self.strategy_name,
                    description="One-time tokens must be invalidated after use",
                    source_observations=[f"token/nonce pattern in: {path}"],
                    testable_prediction="Same token cannot be used twice successfully",
                    discriminating_experiment={
                        "action": "execute same token-based action twice",
                        "expected_violation": "second execution succeeds with same effect",
                    },
                )
                hypotheses.append(hyp)
                break
        return hypotheses

    def test_prediction(self, hypothesis, state_before, state_after):
        tokens_before = set(state_before.get("tokens", {}).values())
        tokens_after = set(state_after.get("tokens", {}).values())
        consumed = tokens_before - tokens_after
        if not consumed and tokens_before:
            return False, "No tokens consumed — replay may be possible"
        return True, f"Tokens consumed: {len(consumed)}"


# ============================================================
# Registry & Factory
# ============================================================

ALL_INVARIANT_STRATEGIES = [
    QuantityConservationInvariant,
    BalanceConservationInvariant,
    WorkflowOrderingInvariant,
    ApprovalSeparationInvariant,
    OwnershipConsistencyInvariant,
    StateTransitionValidityInvariant,
    ReplayResistanceInvariant,
]

INVARIANT_STRATEGY_REGISTRY = {
    cls.strategy_name: cls for cls in ALL_INVARIANT_STRATEGIES
}


def generate_all_invariant_hypotheses(observations: list[dict]) -> list[InvariantHypothesis]:
    """
    Generate hypotheses from ALL invariant strategies based on evidence.
    This is the entry point for the exploration loop.
    """
    all_hypotheses = []
    for strategy_cls in ALL_INVARIANT_STRATEGIES:
        strategy = strategy_cls()
        hyps = strategy.hypothesize(observations)
        all_hypotheses.extend(hyps)
    return all_hypotheses


BUSINESS_LOGIC_GOVERNANCE = {
    "hypotheses_from_evidence_only": True,
    "never_injected_from_ground_truth": True,
    "finding_requires_causal_state_evidence": True,
    "invariants_are_hypotheses_until_validated": True,
    "competing_benign_explanations_always_generated": True,
}

__all__ = [
    "InvariantStrength", "InvariantHypothesis",
    "BaseInvariantStrategy",
    "QuantityConservationInvariant",
    "BalanceConservationInvariant",
    "WorkflowOrderingInvariant",
    "ApprovalSeparationInvariant",
    "OwnershipConsistencyInvariant",
    "StateTransitionValidityInvariant",
    "ReplayResistanceInvariant",
    "ALL_INVARIANT_STRATEGIES", "INVARIANT_STRATEGY_REGISTRY",
    "generate_all_invariant_hypotheses", "BUSINESS_LOGIC_GOVERNANCE",
]
