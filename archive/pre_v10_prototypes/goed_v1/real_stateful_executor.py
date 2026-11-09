"""
GOED v1.7 — Real Stateful Execution Engine (Phase 2)
===================================================
Every state observation originates from ACTUAL TARGET HTTP responses.

FLOW:
  1. pre_state_request  -> TARGET -> real_response -> parse_state()
  2. action_request      -> TARGET -> real_response -> parse_effects()
  3. post_state_request -> TARGET -> real_response -> parse_state()
  4. state_diff = compare(pre_state, post_state)
  5. invariant_test(state_diff) -> verdict

FORBIDDEN:
- expected_state_change used as observed evidence
- evaluator-generated "observed" state
- injected expected deltas
- ground-truth-derived state

ALLOWED:
- test actors (synthetic credentials for local targets)
- local synthetic targets
- parsing real HTTP responses into structured state observations
"""

import contextlib
import copy
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ObservationSource(Enum):
    """Where each piece of state data came from — for audit trail."""
    TARGET_RESPONSE_BODY = "target_response_body"
    TARGET_RESPONSE_HEADER = "target_response_header"
    TARGET_RESPONSE_STATUS = "target_response_status"
    DERIVED_FROM_MULTIPLE_OBSERVATIONS = "derived_from_multiple_observations"
    EXPERIMENTAL_HYPOTHESIS = "experimental_hypothesis"  # never used as proof alone


@dataclass
class StateObservation:
    """A single piece of state observed from a real target response."""
    key: str
    value: Any
    source: ObservationSource
    source_path: str  # HTTP path that produced this observation
    source_method: str = "GET"
    response_status: int | None = None
    raw_field_path: str | None = None  # e.g. "data.balance" within JSON body
    observation_id: str = ""

    def __post_init__(self):
        if not self.observation_id:
            h = hashlib.sha256(f"{self.source_path}:{self.key}:{self.value}".encode()).hexdigest()[:12]
            self.observation_id = f"obs_{h}"


@dataclass
class StateSnapshot:
    """Complete application state captured from real target observations."""
    snapshot_id: str
    actor: str
    observations: list[StateObservation] = field(default_factory=list)
    raw_responses: list[dict[str, Any]] = field(default_factory=list)
    timestamp: str = ""

    def get_value(self, key: str) -> Any | None:
        """Get a value by key from observations."""
        for obs in reversed(self.observations):
            if obs.key == key:
                return obs.value
        return None

    def get_all(self, key_prefix: str) -> list[StateObservation]:
        """Get all observations matching a key prefix."""
        return [o for o in self.observations if o.key.startswith(key_prefix)]

    def to_dict(self) -> dict[str, Any]:
        """Structured dictionary for diffing and proof."""
        result = {}
        for obs in self.observations:
            result[obs.key] = {
                "value": obs.value,
                "source": obs.source.value,
                "source_path": obs.source_path,
                "observation_id": obs.observation_id,
            }
        return result

    def flat_values(self) -> dict[str, Any]:
        """Simple key->value mapping for invariant tests."""
        return {o.key: o.value for o in self.observations}


@dataclass
class StateDelta:
    """Difference between two state snapshots, derived from real observations."""
    delta_id: str
    key: str
    value_before: Any
    value_after: Any
    change: Any  # after - before for numeric, flag for non-numeric
    source_before: str  # observation_id
    source_after: str   # observation_id
    invariant_relevance: list[str] = field(default_factory=list)


@dataclass
class ActionSpec:
    """Specification of a state-changing action to execute against a REAL target."""
    action_id: str
    action_type: str  # transfer, approve, reset, update, claim, create, delete
    method: str
    path: str
    params: dict[str, Any] = field(default_factory=dict)
    body: dict[str, Any] | None = None
    actor: str = ""
    # For invariant testing: what state keys to observe before/after
    observe_keys_before: list[str] = field(default_factory=list)
    observe_keys_after: list[str] = field(default_factory=list)
    # Paths to query for state capture
    pre_state_paths: list[dict[str, str]] = field(default_factory=list)  # [{path, method, key_prefix}]
    post_state_paths: list[dict[str, str]] = field(default_factory=list)


@dataclass
class StepTrace:
    """Complete trace of one execution step for ProofBundle."""
    step_id: str
    step_type: str  # pre_state_capture, action_execution, post_state_capture, replay, control
    method: str
    path: str
    request_params: dict[str, Any] = field(default_factory=dict)
    request_body: dict[str, Any] | None = None
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body_preview: str | None = None  # truncated for bundle size
    response_body_length: int = 0
    observations_produced: list[str] = field(default_factory=list)  # observation IDs
    timestamp: str = ""
    duration_ms: float = 0.0


@dataclass
class InvariantTest:
    """One invariant hypothesis tested against real state deltas."""
    invariant_name: str
    invariant_family: str  # conservation, ownership, ordering, separation, transition, replay, authorization
    source_evidence: list[str]  # observation IDs or paths that motivated this hypothesis
    prediction: str
    delta_keys_used: list[str]
    verdict: str  # VIOLATED, PRESERVED, INCONCLUSIVE
    confidence: float
    reasoning: str


@dataclass
class StatefulResult:
    """Complete result of a real stateful evaluation chain."""
    result_id: str
    verdict: str  # CONFIRMED, CLEAN, INCONCLUSIVE, BLOCKED
    confidence: float
    action_executed: ActionSpec
    pre_state: StateSnapshot
    post_state: StateSnapshot
    state_deltas: list[StateDelta] = field(default_factory=list)
    step_trace: list[StepTrace] = field(default_factory=list)
    invariant_tests: list[InvariantTest] = field(default_factory=list)
    invariants_violated: list[str] = field(default_factory=list)
    invariants_preserved: list[str] = field(default_factory=list)
    replay_verified: bool = False
    control_replay_verified: bool = False
    block_reason: str | None = None
    causal_signal: bool | None = None

    def to_proof_dict(self) -> dict[str, Any]:
        """Produce a complete audit trail for ProofBundle inclusion."""
        return {
            "result_id": self.result_id,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 4),
            "action": {
                "action_id": self.action_executed.action_id,
                "action_type": self.action_executed.action_type,
                "method": self.action_executed.method,
                "path": self.action_executed.path,
            },
            "pre_state_observations": len(self.pre_state.observations),
            "post_state_observations": len(self.post_state.observations),
            "state_deltas": [
                {
                    "key": d.key, "before": d.value_before, "after": d.value_after,
                    "change": d.change, "source_before": d.source_before,
                    "source_after": d.source_after,
                }
                for d in self.state_deltas
            ],
            "step_count": len(self.step_trace),
            "steps": [
                {
                    "step_id": s.step_id, "step_type": s.step_type,
                    "method": s.method, "path": s.path,
                    "response_status": s.response_status,
                    "observations_produced": s.observations_produced,
                    "duration_ms": round(s.duration_ms, 2),
                }
                for s in self.step_trace
            ],
            "invariant_tests": [
                {
                    "name": t.invariant_name, "family": t.invariant_family,
                    "verdict": t.verdict, "confidence": round(t.confidence, 4),
                    "reasoning": t.reasoning[:200],
                }
                for t in self.invariant_tests
            ],
            "invariants_violated": self.invariants_violated,
            "invariants_preserved": self.invariants_preserved,
            "replay_verified": self.replay_verified,
            "control_replay_verified": self.control_replay_verified,
            "block_reason": self.block_reason,
            "causal_signal": self.causal_signal,
        }


class RealStatefulExecutor:
    """
    Executes stateful evaluations against REAL targets via HTTP.

    Every piece of state is parsed from actual target responses.
    Every delta is computed from real before/after observations.
    Every invariant is tested against real deltas.

    This class is HTTP-client-agnostic. An actual HTTP client is passed in.
    For local testing, a mock client or httpx client can be used.
    """

    def __init__(self, http_client):
        """http_client must support .get() and .post() returning response objects with
        .status_code, .headers, .json(), .text attributes."""
        self.http = http_client
        self._step_counter = 0

    def _new_step_id(self) -> str:
        self._step_counter += 1
        return f"step_{self._step_counter:03d}"

    def _parse_state_from_response(self, response, path: str, method: str,
                                     key_prefix: str = "") -> list[StateObservation]:
        """
        Parse structured state observations from a REAL HTTP response.

        Sources:
        1. JSON response body fields
        2. Response headers (X-Resource-*, X-Balance, X-Workflow-*, etc.)
        3. Status code semantics
        """
        observations = []

        # Source 1: Response body (JSON)
        try:
            body = response.json()
            if isinstance(body, dict):
                for field_path, value in self._flatten_json(body, prefix=key_prefix):
                    observations.append(StateObservation(
                        key=field_path,
                        value=value,
                        source=ObservationSource.TARGET_RESPONSE_BODY,
                        source_path=path,
                        source_method=method,
                        response_status=response.status_code,
                        raw_field_path=field_path,
                    ))
        except (ValueError, AttributeError):
            pass

        # Source 2: Response headers
        state_headers = [
            "x-resource-owner", "x-resource-tenant", "x-resource-type",
            "x-resource-id", "x-entity-id", "x-workflow-status", "x-workflow-requester",
            "x-workflow-approver", "x-balance", "x-account-balance",
            "x-token-id", "x-session-id", "x-effective-privilege",
            "x-authorization-outcome", "x-actor-role", "x-actor-tenant",
            "x-counter-value", "x-claim-remaining",
        ]
        try:
            resp_headers = {k.lower(): v for k, v in response.headers.items()}
        except Exception:
            resp_headers = {}

        for hdr in state_headers:
            if hdr in resp_headers:
                val = resp_headers[hdr]
                # Try numeric conversion
                with contextlib.suppress(ValueError, TypeError):
                    val = float(val) if "." in val else int(val)
                key_name = hdr.replace("x-", "").replace("-", "_")
                if key_prefix:
                    key_name = f"{key_prefix}.{key_name}"
                observations.append(StateObservation(
                    key=key_name,
                    value=val,
                    source=ObservationSource.TARGET_RESPONSE_HEADER,
                    source_path=path,
                    source_method=method,
                    response_status=response.status_code,
                    raw_field_path=f"header:{hdr}",
                ))

        # Source 3: Status code as observation
        observations.append(StateObservation(
            key=f"{key_prefix}.status_code" if key_prefix else "status_code",
            value=response.status_code,
            source=ObservationSource.TARGET_RESPONSE_STATUS,
            source_path=path,
            source_method=method,
            response_status=response.status_code,
        ))

        return observations

    def _flatten_json(self, obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
        """Flatten nested JSON into dot-notation key-value pairs."""
        result = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    result.extend(self._flatten_json(v, key))
                else:
                    result.append((key, v))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                key = f"{prefix}[{i}]"
                if isinstance(v, (dict, list)):
                    result.extend(self._flatten_json(v, key))
                else:
                    result.append((key, v))
        return result

    def _capture_state(self, base_url: str, actor: str,
                        state_paths: list[dict[str, str]],
                        step_type: str = "pre_state_capture") -> tuple[StateSnapshot, list[StepTrace]]:
        """
        Capture application state by making REAL requests to specified paths
        and parsing the responses into StateObservation objects.
        """
        import time as _time
        snapshot = StateSnapshot(
            snapshot_id=hashlib.sha256(f"{actor}:{_time.time()}".encode()).hexdigest()[:16],
            actor=actor,
            timestamp=_time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
        )
        steps = []

        for sp in state_paths:
            path = sp["path"]
            method = sp.get("method", "GET")
            key_prefix = sp.get("key_prefix", "")
            headers = {"X-Actor": actor} if actor else {}

            t0 = _time.time()
            try:
                if method.upper() == "POST":
                    response = self.http.post(f"{base_url}{path}", headers=headers, json=sp.get("body"))
                else:
                    response = self.http.get(f"{base_url}{path}", headers=headers, params=sp.get("params"))
            except Exception:
                step = StepTrace(
                    step_id=self._new_step_id(), step_type=step_type,
                    method=method, path=path,
                    timestamp=_time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                    duration_ms=(_time.time() - t0) * 1000,
                )
                steps.append(step)
                continue

            duration = (_time.time() - t0) * 1000

            observations = self._parse_state_from_response(
                response, path, method, key_prefix=key_prefix
            )

            # Store raw response reference
            try:
                body_text = response.text
                snapshot.raw_responses.append({
                    "path": path, "method": method, "status": response.status_code,
                    "body_preview": body_text[:500], "body_length": len(body_text),
                })
            except Exception:
                pass

            snapshot.observations.extend(observations)

            step = StepTrace(
                step_id=self._new_step_id(), step_type=step_type,
                method=method, path=path,
                response_status=response.status_code,
                response_headers=dict(dict(response.headers).items()),
                response_body_preview=getattr(response, "text", "")[:200],
                response_body_length=len(getattr(response, "text", "")),
                observations_produced=[o.observation_id for o in observations],
                timestamp=_time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                duration_ms=duration,
            )
            steps.append(step)

        return snapshot, steps

    def _execute_action(self, base_url: str, action: ActionSpec) -> StepTrace:
        """Execute the state-changing action against the REAL target."""
        import time as _time
        headers = {"X-Actor": action.actor} if action.actor else {}

        t0 = _time.time()
        try:
            if action.method.upper() == "POST":
                response = self.http.post(
                    f"{base_url}{action.path}",
                    headers=headers, params=action.params, json=action.body,
                )
            elif action.method.upper() == "PUT":
                response = self.http.put(
                    f"{base_url}{action.path}",
                    headers=headers, params=action.params, json=action.body,
                )
            elif action.method.upper() == "PATCH":
                response = self.http.patch(
                    f"{base_url}{action.path}",
                    headers=headers, params=action.params, json=action.body,
                )
            else:
                response = self.http.get(
                    f"{base_url}{action.path}",
                    headers=headers, params=action.params,
                )
        except Exception:
            return StepTrace(
                step_id=self._new_step_id(), step_type="action_execution",
                method=action.method, path=action.path,
                timestamp=_time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                duration_ms=(_time.time() - t0) * 1000,
            )

        duration = (_time.time() - t0) * 1000

        return StepTrace(
            step_id=self._new_step_id(), step_type="action_execution",
            method=action.method, path=action.path,
            request_params=dict(action.params),
            request_body=copy.deepcopy(action.body),
            response_status=response.status_code,
            response_headers=dict(dict(response.headers).items()),
            response_body_preview=getattr(response, "text", "")[:200],
            response_body_length=len(getattr(response, "text", "")),
            timestamp=_time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
            duration_ms=duration,
        )

    def _compute_state_deltas(self, pre: StateSnapshot,
                               post: StateSnapshot) -> list[StateDelta]:
        """
        Compute deltas between pre and post state snapshots.
        ONLY uses real observations — no synthetic values.
        """
        deltas = []
        pre_flat = pre.flat_values()
        post_flat = post.flat_values()

        all_keys = set(list(pre_flat.keys()) + list(post_flat.keys()))

        # Find observations for source tracking
        pre_obs_map = {o.key: o.observation_id for o in pre.observations}
        post_obs_map = {o.key: o.observation_id for o in post.observations}

        for key in all_keys:
            before = pre_flat.get(key)
            after = post_flat.get(key)

            if before != after:
                # Compute change
                change = None
                try:
                    if isinstance(before, (int, float)) and isinstance(after, (int, float)):
                        change = after - before
                except (TypeError, ValueError):
                    change = f"{before} -> {after}"

                delta = StateDelta(
                    delta_id=hashlib.sha256(f"{key}:{before}:{after}".encode()).hexdigest()[:12],
                    key=key,
                    value_before=before,
                    value_after=after,
                    change=change,
                    source_before=pre_obs_map.get(key, "unknown"),
                    source_after=post_obs_map.get(key, "unknown"),
                )

                # Tag invariant relevance
                if "balance" in key.lower() or "amount" in key.lower():
                    delta.invariant_relevance.append("conservation")
                    delta.invariant_relevance.append("balance_consistency")
                if "owner" in key.lower() or "tenant" in key.lower():
                    delta.invariant_relevance.append("ownership_consistency")
                    delta.invariant_relevance.append("authorization_state_consistency")
                if "workflow" in key.lower() or "status" in key.lower() or "state" in key.lower():
                    delta.invariant_relevance.append("valid_state_transition")
                    delta.invariant_relevance.append("ordering")
                if "approver" in key.lower() or "requester" in key.lower():
                    delta.invariant_relevance.append("approval_separation")
                if "token" in key.lower() or "nonce" in key.lower():
                    delta.invariant_relevance.append("replay_resistance")
                if "counter" in key.lower() or "claim" in key.lower() or "remaining" in key.lower():
                    delta.invariant_relevance.append("conservation")

                deltas.append(delta)

        return deltas

    def _test_invariants(self, deltas: list[StateDelta],
                         pre: StateSnapshot, post: StateSnapshot,
                         action: ActionSpec) -> list[InvariantTest]:
        """
        Test invariant hypotheses against REAL state deltas.
        Each test records: source evidence, prediction, delta keys used, verdict.
        """
        tests = []
        pre_flat = pre.flat_values()
        post_flat = post.flat_values()

        # Conservation invariants (balances, totals, counters)
        conservation_deltas = [d for d in deltas if "conservation" in d.invariant_relevance]
        if conservation_deltas:
            balance_keys = [d.key for d in conservation_deltas if "balance" in d.key.lower()]
            if len(balance_keys) >= 2:
                total_before = sum(float(pre_flat.get(k, 0)) for k in balance_keys)
                total_after = sum(float(post_flat.get(k, 0)) for k in balance_keys)
                total_delta = total_after - total_before

                if abs(total_delta) > 0.01:
                    tests.append(InvariantTest(
                        invariant_name="total_balance_conservation",
                        invariant_family="conservation",
                        source_evidence=[d.source_before for d in conservation_deltas[:3]] +
                                        [d.source_after for d in conservation_deltas[:3]],
                        prediction=f"Total of {balance_keys} should be conserved",
                        delta_keys_used=balance_keys,
                        verdict="VIOLATED",
                        confidence=min(0.95, 0.6 + 0.1 * len(conservation_deltas)),
                        reasoning=f"Total balance not conserved: before={total_before:.2f}, after={total_after:.2f}, delta={total_delta:+.2f}",
                    ))
                else:
                    tests.append(InvariantTest(
                        invariant_name="total_balance_conservation",
                        invariant_family="conservation",
                        source_evidence=[d.source_before for d in conservation_deltas[:3]],
                        prediction=f"Total of {balance_keys} should be conserved",
                        delta_keys_used=balance_keys,
                        verdict="PRESERVED",
                        confidence=0.7,
                        reasoning=f"Total conserved: before={total_before:.2f}, after={total_after:.2f}",
                    ))

            # Individual balance asymmetry check
            numeric_deltas = [d for d in conservation_deltas if isinstance(d.change, (int, float))]
            if len(numeric_deltas) >= 2:
                changes = [d.change for d in numeric_deltas]
                if abs(sum(changes)) > 0.01:
                    tests.append(InvariantTest(
                        invariant_name="balance_symmetry",
                        invariant_family="balance_consistency",
                        source_evidence=[d.source_before for d in numeric_deltas] +
                                        [d.source_after for d in numeric_deltas],
                        prediction="Sender decrease should equal receiver increase",
                        delta_keys_used=[d.key for d in numeric_deltas],
                        verdict="VIOLATED",
                        confidence=0.9,
                        reasoning=f"Asymmetric deltas: changes={changes}, sum={sum(changes):+.4f}",
                    ))

        # Ownership consistency
        ownership_deltas = [d for d in deltas if "ownership_consistency" in d.invariant_relevance]
        for d in ownership_deltas:
            if d.value_before and d.value_after and d.value_before != d.value_after:
                pre_flat.get("actor_tenant") or pre_flat.get("x_actor_tenant")
                tests.append(InvariantTest(
                    invariant_name=f"ownership_change_{d.key}",
                    invariant_family="ownership_consistency",
                    source_evidence=[d.source_before, d.source_after],
                    prediction=f"Ownership field {d.key} should not change unexpectedly",
                    delta_keys_used=[d.key],
                    verdict="VIOLATED",
                    confidence=0.85,
                    reasoning=f"Ownership changed: {d.value_before} -> {d.value_after}",
                ))

        # State transition validity
        transition_deltas = [d for d in deltas if "valid_state_transition" in d.invariant_relevance]
        VALID_TRANSITIONS = {
            "draft": ["submitted", "cancelled", "deleted"],
            "pending": ["approved", "rejected"],
            "submitted": ["approved", "rejected", "pending_review"],
            "approved": ["finalized", "active"],
        }
        for d in transition_deltas:
            b = str(d.value_before).lower() if d.value_before else ""
            a = str(d.value_after).lower() if d.value_after else ""
            if b in VALID_TRANSITIONS and a not in VALID_TRANSITIONS[b]:
                tests.append(InvariantTest(
                    invariant_name=f"state_transition_{d.key}",
                    invariant_family="valid_state_transition",
                    source_evidence=[d.source_before, d.source_after],
                    prediction=f"Valid transitions from {b}: {VALID_TRANSITIONS[b]}",
                    delta_keys_used=[d.key],
                    verdict="VIOLATED",
                    confidence=0.8,
                    reasoning=f"Invalid state transition: {b} -> {a}",
                ))

        # Approval separation
        if action.action_type == "approve" or "approval_separation" in str(deltas):
            requester = pre_flat.get("workflow_requester") or pre_flat.get("x_workflow_requester")
            approver_actor = action.actor
            if requester and approver_actor and str(requester) == str(approver_actor):
                tests.append(InvariantTest(
                    invariant_name="self_approval",
                    invariant_family="approval_separation",
                    source_evidence=[o.observation_id for o in pre.observations
                                    if "requester" in o.key.lower()][:3],
                    prediction="Requester cannot also be approver",
                    delta_keys_used=[],
                    verdict="VIOLATED",
                    confidence=0.85,
                    reasoning=f"Self-approval detected: requester={requester}, actor={approver_actor}",
                ))

        # Counter / race condition detection
        counter_deltas = [d for d in deltas if "counter" in d.key.lower() or "remaining" in d.key.lower() or "claim" in d.key.lower()]
        for d in counter_deltas:
            if isinstance(d.change, (int, float)) and d.change != 0:
                tests.append(InvariantTest(
                    invariant_name=f"counter_state_change_{d.key}",
                    invariant_family="conservation",
                    source_evidence=[d.source_before, d.source_after],
                    prediction="Counter should only decrement by 1 per successful claim",
                    delta_keys_used=[d.key],
                    verdict="VIOLATED" if abs(d.change) > 1.5 else "PRESERVED",
                    confidence=0.7,
                    reasoning=f"Counter changed by {d.change}: {d.value_before} -> {d.value_after}",
                ))

        return tests

    def execute_chain(self, base_url: str, action: ActionSpec,
                      control_path: str | None = None) -> StatefulResult:
        """
        Execute a complete stateful evaluation chain against a REAL target.

        FLOW (all against real target):
        1. Capture PRE state from specified paths
        2. Execute the action
        3. Capture POST state from specified paths
        4. Compute deltas (only from real observations)
        5. Test invariants against deltas
        6. Produce verdict with complete audit trail

        No synthetic state. No injected deltas. No expected_state_change as evidence.
        """
        import time as _time
        result_id = hashlib.sha256(
            f"{action.action_id}:{action.actor}:{_time.time()}".encode()
        ).hexdigest()[:16]

        all_steps = []

        # Step 1: Capture PRE state from REAL target
        pre_state_paths = action.pre_state_paths or [{"path": action.path.split("?")[0], "method": "GET"}]
        pre_snapshot, pre_steps = self._capture_state(
            base_url, action.actor, pre_state_paths, "pre_state_capture"
        )
        all_steps.extend(pre_steps)

        if not pre_snapshot.observations:
            return StatefulResult(
                result_id=result_id, verdict="BLOCKED", confidence=0.0,
                action_executed=action, pre_state=pre_snapshot, post_state=pre_snapshot,
                step_trace=all_steps,
                block_reason="no_pre_state_observations_from_target",
            )

        # Step 2: Execute action against REAL target
        action_step = self._execute_action(base_url, action)
        all_steps.append(action_step)

        if action_step.response_status is None:
            return StatefulResult(
                result_id=result_id, verdict="BLOCKED", confidence=0.0,
                action_executed=action, pre_state=pre_snapshot, post_state=pre_snapshot,
                step_trace=all_steps,
                block_reason="action_execution_failed_no_response",
            )

        # Step 3: Capture POST state from REAL target
        post_state_paths = action.post_state_paths or action.pre_state_paths or [{"path": action.path.split("?")[0], "method": "GET"}]
        post_snapshot, post_steps = self._capture_state(
            base_url, action.actor, post_state_paths, "post_state_capture"
        )
        all_steps.extend(post_steps)

        if not post_snapshot.observations:
            return StatefulResult(
                result_id=result_id, verdict="BLOCKED", confidence=0.0,
                action_executed=action, pre_state=pre_snapshot, post_state=post_snapshot,
                step_trace=all_steps,
                block_reason="no_post_state_observations_from_target",
            )

        # Step 4: Compute state deltas from REAL observations
        state_deltas = self._compute_state_deltas(pre_snapshot, post_snapshot)

        # Step 5: Test invariants against REAL deltas
        invariant_tests = self._test_invariants(state_deltas, pre_snapshot, post_snapshot, action)

        violated = [t.invariant_name for t in invariant_tests if t.verdict == "VIOLATED"]
        preserved = [t.invariant_name for t in invariant_tests if t.verdict == "PRESERVED"]

        # Step 6: Determine verdict
        confidence = 0.0
        verdict = "INCONCLUSIVE"
        causal_signal = None

        if violated:
            # Confidence based on strongest invariant test
            max_conf = max((t.confidence for t in invariant_tests if t.verdict == "VIOLATED"), default=0.5)
            confidence = min(0.95, max_conf + 0.1 * len(violated))
            verdict = "CONFIRMED"
            causal_signal = True
        elif preserved and not state_deltas:
            confidence = 0.6
            verdict = "CLEAN"
            causal_signal = False
        elif preserved:
            confidence = 0.5
            verdict = "INCONCLUSIVE"

        return StatefulResult(
            result_id=result_id,
            verdict=verdict,
            confidence=confidence,
            action_executed=action,
            pre_state=pre_snapshot,
            post_state=post_snapshot,
            state_deltas=state_deltas,
            step_trace=all_steps,
            invariant_tests=invariant_tests,
            invariants_violated=violated,
            invariants_preserved=preserved,
            causal_signal=causal_signal,
        )


# ============================================================
# Module exports & governance
# ============================================================

REAL_STATEFUL_GOVERNANCE = {
    "all_state_originates_from_target_http_responses": True,
    "no_expected_state_change_as_evidence": True,
    "no_synthetic_state_mutation_inside_evaluator": True,
    "every_delta_backed_by_observation_ids": True,
    "every_step_recorded_in_trace": True,
    "invariant_tests_reference_source_evidence": True,
    "fail_closed_insufficient_observations": True,
    "http_client_pluggable": True,
}

__all__ = [
    "ObservationSource", "StateObservation", "StateSnapshot",
    "StateDelta", "ActionSpec", "StepTrace", "InvariantTest",
    "StatefulResult", "RealStatefulExecutor", "REAL_STATEFUL_GOVERNANCE",
]
