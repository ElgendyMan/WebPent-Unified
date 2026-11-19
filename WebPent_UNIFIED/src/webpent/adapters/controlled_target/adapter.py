"""Purpose-built loopback target for deterministic causal IDOR validation.

This module is deliberately target-local.  It starts an ephemeral HTTP server on
127.0.0.1 only, exposes one read-only resource route, and keeps all identities
and resources opaque and in memory.  The intentional access-control defect is
part of this disposable validation target; it is not a generic detector rule.
"""

from __future__ import annotations

import hashlib
import json
import threading
import urllib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

from webpent.models.findings import Finding, Severity, VulnClass
from webpent.shared.generic_web_contracts import (
    LIFECYCLE_CONTRACT_VERSION,
    CapabilityRecord,
    CaseDefinition,
    LifecycleAuthorization,
    LifecycleRunContext,
    LifecycleStageResult,
)
from webpent.shared.proof_oracles import (
    CausalObservation,
    CausalOracleContract,
    OracleEngine,
    OracleFamily,
)
from webpent.shared.semantic_observations import SemanticProfileRegistry
from webpent.shared.target_adapters import (
    RegisteredTargetAdapter,
    TargetCaseBinding,
    TargetManifest,
)
from webpent.shared.target_context import IdentityContext
from webpent.shared.target_spec import AuthorizationRecord, TargetSpec
from webpent.shared.verifier import verify_replay_evidence
from webpent.shared.workflow_contracts import READ_ONLY_NAVIGATION

CONTROLLED_TARGET_ID = "controlled_local_idor_target_v1"
CONTROLLED_IDOR_CASE_ID = "controlled.idor.owner_resource.v1"
CONTROLLED_IDOR_ORACLE_ID = "controlled.idor.causal_owner_boundary.v1"
CONTROLLED_TARGET_VERSION = "1.0"
CONTROLLED_ROUTE_PREFIX = "/controlled/resources/"
CONTROLLED_CAMPAIGN_ID = "controlled-local-idor-campaign-v1"
CONTROLLED_VALIDATOR_ID = "controlled-local-idor-verifier"
CONTROLLED_VALIDATOR_VERSION = "1.0"

_OWNER_ACTOR = "actor_owner_7f3a"
_ATTACKER_ACTOR = "actor_attacker_2c91"
_OWNER_RESOURCE = "resource_owned_a81d"
_UNRELATED_RESOURCE = "resource_unrelated_c42e"


@dataclass(frozen=True)
class _ControlledState:
    """Opaque, deterministic state for the disposable target."""

    owner_actor: str = _OWNER_ACTOR
    attacker_actor: str = _ATTACKER_ACTOR
    owned_resource: str = _OWNER_RESOURCE
    unrelated_resource: str = _UNRELATED_RESOURCE

    def as_dict(self) -> dict[str, str]:
        return {
            "owner_actor": self.owner_actor,
            "attacker_actor": self.attacker_actor,
            "owned_resource": self.owned_resource,
            "unrelated_resource": self.unrelated_resource,
        }

    def state_hash(self) -> str:
        payload = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"


class _ControlledRequestHandler(BaseHTTPRequestHandler):
    """Serve one fixed, intentionally vulnerable read-only route."""

    server_version = "WebPentControlledTarget/1.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        target = self.server.controlled_target  # type: ignore[attr-defined]
        parsed = urlsplit(self.path)
        prefix = CONTROLLED_ROUTE_PREFIX
        path_parts = parsed.path.split("/")
        if (
            not parsed.path.startswith(prefix)
            or len(path_parts) != 4
            or not path_parts[3]
            or path_parts[1:3] != ["controlled", "resources"]
        ):
            self._send_json(404, {"error": "not_found"})
            return

        resource_id = path_parts[3]
        actor_values = parse_qs(parsed.query, keep_blank_values=True).get("actor", [])
        actor = actor_values[0] if len(actor_values) == 1 else ""
        state = target.state
        if actor not in {state.owner_actor, state.attacker_actor}:
            self._send_json(400, {"error": "invalid_actor_selector"})
            return
        if resource_id not in {state.owned_resource, state.unrelated_resource}:
            self._send_json(404, {"error": "resource_not_found"})
            return

        resource_owner = state.owner_actor
        is_owner_access = actor == resource_owner
        intentional_idor_access = (
            actor == state.attacker_actor and resource_id == state.owned_resource
        )
        allowed = is_owner_access or intentional_idor_access
        status = 200 if allowed else 403
        body: dict[str, str] = {
            "resource_id": resource_id,
            "access": "allowed" if allowed else "denied",
            "owner_relation": "owner" if is_owner_access else "protected_foreign",
        }
        self._send_json(status, body)

    def do_POST(self) -> None:  # noqa: N802 - explicit GET-only boundary
        self._send_json(405, {"error": "method_not_allowed"})

    def do_PUT(self) -> None:  # noqa: N802 - explicit GET-only boundary
        self._send_json(405, {"error": "method_not_allowed"})

    def do_DELETE(self) -> None:  # noqa: N802 - explicit GET-only boundary
        self._send_json(405, {"error": "method_not_allowed"})

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _send_json(self, status: int, payload: dict[str, str]) -> None:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class ControlledIDORTarget:
    """Disposable local target and lifecycle adapter for one causal IDOR case."""

    lifecycle_contract_version = LIFECYCLE_CONTRACT_VERSION
    semantic_profiles = SemanticProfileRegistry({})

    def __init__(self) -> None:
        self.target_id = CONTROLLED_TARGET_ID
        self.target_origin = ""
        self.state = _ControlledState()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        # P1-14 (0.33.0): the adapter is a module-level singleton shared by
        # concurrent lifecycle callers; check-then-act on _server/_request_count
        # needs a lock or two threads can leak a ThreadingHTTPServer and
        # overshoot max_requests by N-1.
        self._lifecycle_lock = threading.Lock()
        self._target_spec: TargetSpec | None = None
        self._last_verification = None
        self._observations: dict[str, dict[str, Any]] = {}
        self._request_count = 0

    @property
    def running(self) -> bool:
        return self._server is not None and self._thread is not None and self._thread.is_alive()

    @property
    def state_hash(self) -> str:
        return self.state.state_hash()

    @property
    def target_context_hash(self) -> str:
        spec_payload = self._target_spec.safe_dict() if self._target_spec else {}
        return _digest(
            {"target_id": self.target_id, "state_hash": self.state_hash, "spec": spec_payload}
        )[7:]

    @property
    def request_count(self) -> int:
        return self._request_count

    def start(self) -> ControlledIDORTarget:
        # P1-14 (0.33.0): lock the check-then-act — two concurrent starts
        # used to both pass `self._server is None` and leak one server.
        with self._lifecycle_lock:
            if self._server is not None:
                return self
            self.state = _ControlledState()
            server = ThreadingHTTPServer(("127.0.0.1", 0), _ControlledRequestHandler)
            server.daemon_threads = True
            server.controlled_target = self  # type: ignore[attr-defined]
            self._server = server
            self.target_origin = f"http://127.0.0.1:{server.server_address[1]}"
            self._thread = threading.Thread(
                target=server.serve_forever,
                name="webpent-controlled-id-or-target",
                daemon=True,
            )
        self._thread.start()
        return self

    def stop(self) -> None:
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        self._target_spec = None
        self._observations.clear()
        self._last_verification = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2.0)
        self.target_origin = ""

    def __enter__(self) -> ControlledIDORTarget:
        return self.start()

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        del exc_type, exc, tb
        self.stop()

    def bind_target_spec(self, spec: TargetSpec) -> None:
        if not self.running or not self.target_origin:
            raise ValueError("controlled_target_must_be_running_before_spec_binding")
        if spec.base_url != self.target_origin:
            raise ValueError("controlled_target_spec_origin_mismatch")
        decision = spec.scope_validator().decide(
            f"{self.target_origin}{CONTROLLED_ROUTE_PREFIX}{self.state.owned_resource}?actor={self.state.owner_actor}"
        )
        if not decision.allowed:
            raise ValueError(f"controlled_target_spec_route_out_of_scope:{decision.reason_code}")
        self._target_spec = spec

    def reset(self) -> str:
        """Restore the deterministic initial snapshot without network I/O."""
        before = self.state_hash
        self.state = _ControlledState()
        after = self.state_hash
        if before != after:
            raise AssertionError("controlled_target_reset_not_deterministic")
        self._observations.clear()
        self._last_verification = None
        self._request_count = 0
        return after

    def snapshot(self) -> dict[str, str]:
        return {"fixture_ref": f"{self.target_id}:disposable", "state_hash": self.state_hash}

    def readiness(self) -> dict[str, bool | str]:
        route_ready = bool(self.running and self.target_origin and self._target_spec)
        return {
            "preconditions_ready": route_ready
            and self.preconditions_ready(CONTROLLED_IDOR_CASE_ID),
            "fixture_ready": self.state_hash == _ControlledState().state_hash(),
            "identity_model_ready": True,
            "reset_verified": self.reset() == _ControlledState().state_hash(),
            "runtime_digest_verified": True,
            "network_scope_verified": bool(self.target_origin.startswith("http://127.0.0.1:")),
            "state_hash": self.state_hash,
        }

    def describe_target(self) -> dict[str, str]:
        return {
            "target_id": self.target_id,
            "target_origin": self.target_origin,
            "target_version": CONTROLLED_TARGET_VERSION,
            "target_classification": "controlled_local_target_backed_validation",
            "fixture_disposable": "True",
            "intentional_vulnerability": "idor",
            "network_scope": "loopback_127.0.0.1_ephemeral_port",
            "allowed_method": "GET",
            "raw_response_persistence": "False",
            "state_hash": self.state_hash,
        }

    def capabilities(self) -> tuple[CapabilityRecord, ...]:
        available = self.running and self._target_spec is not None
        reason = (
            "controlled_target_runtime_ready"
            if available
            else "controlled_target_runtime_not_ready"
        )
        return tuple(
            CapabilityRecord(capability_id, "available" if available else "blocked", reason)
            for capability_id in (
                "read_only_navigation",
                "identity_model",
                "ownership_model",
                "deterministic_reset",
                "oracle_signal",
                "independent_negative_control",
            )
        )

    def prepare(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        if case.case_id != CONTROLLED_IDOR_CASE_ID:
            return LifecycleStageResult(
                "prepare", "unsupported", "case_not_owned_by_controlled_target"
            )
        if not self.running or self._target_spec is None:
            return LifecycleStageResult(
                "prepare", "blocked", "controlled_target_precondition_not_ready"
            )
        if not authorization.authorized:
            return LifecycleStageResult("prepare", "blocked", "explicit_authorization_required")
        if authorization.allowed_origin != self.target_origin:
            return LifecycleStageResult(
                "prepare", "blocked", "authorized_origin_outside_controlled_target"
            )
        if run_context.target_id != self.target_id or run_context.case_id != case.case_id:
            return LifecycleStageResult("prepare", "blocked", "controlled_target_context_mismatch")
        if not self.preconditions_ready(case.case_id):
            return LifecycleStageResult("prepare", "blocked", "controlled_target_readiness_failed")
        return LifecycleStageResult(
            "prepare",
            "ready",
            "controlled_local_target_preconditions_satisfied",
            metadata={"target_classification": "controlled_local_target_backed_validation"},
        )

    def baseline(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del authorization
        if case.case_id != CONTROLLED_IDOR_CASE_ID or not self.preconditions_ready(case.case_id):
            return LifecycleStageResult(
                "baseline", "blocked", "controlled_target_precondition_not_ready"
            )
        observation = self._request_observation(
            role="baseline",
            actor=self.state.owner_actor,
            resource=self.state.owned_resource,
            run_context=run_context,
        )
        self._observations["baseline"] = observation
        return LifecycleStageResult(
            "baseline",
            "completed",
            "owner_baseline_observed_over_loopback_http",
            observation_refs=(observation["observation_ref"],),
            metadata={"target_backed": "True"},
        )

    def execute_safe_action(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del authorization
        if case.case_id != CONTROLLED_IDOR_CASE_ID or not self.preconditions_ready(case.case_id):
            return LifecycleStageResult(
                "execute_safe_action", "blocked", "controlled_target_precondition_not_ready"
            )
        observation = self._request_observation(
            role="candidate",
            actor=self.state.attacker_actor,
            resource=self.state.owned_resource,
            run_context=run_context,
        )
        self._observations["candidate"] = observation
        return LifecycleStageResult(
            "execute_safe_action",
            "completed",
            "attacker_foreign_resource_candidate_observed_over_loopback_http",
            observation_refs=(observation["observation_ref"],),
            metadata={"target_backed": "True"},
        )

    def observe(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del authorization, run_context
        if case.case_id != CONTROLLED_IDOR_CASE_ID or "candidate" not in self._observations:
            return LifecycleStageResult(
                "observe", "inconclusive", "candidate_observation_not_available"
            )
        return LifecycleStageResult(
            "observe",
            "completed",
            "candidate_observation_collected_without_additional_request",
            observation_refs=(self._observations["candidate"]["observation_ref"],),
            metadata={"target_backed": "True"},
        )

    def execute_negative_control(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del authorization
        if case.case_id != CONTROLLED_IDOR_CASE_ID:
            return LifecycleStageResult(
                "execute_negative_control", "unsupported", "case_not_owned_by_controlled_target"
            )
        if not all(key in self._observations for key in ("baseline", "candidate")):
            return LifecycleStageResult(
                "execute_negative_control", "blocked", "baseline_and_candidate_required"
            )
        control = self._request_observation(
            role="negative_control",
            actor=self.state.attacker_actor,
            resource=self.state.unrelated_resource,
            run_context=run_context,
        )
        self._observations["negative_control"] = control
        causal_result = OracleEngine.evaluate_experiment(
            CausalOracleContract(
                family=OracleFamily.IDOR,
                baseline=_causal_model(self._observations["baseline"]),
                candidate=_causal_model(self._observations["candidate"]),
                negative_control=_causal_model(control),
                expected_invariant=(
                    "owner access is allowed and protected non-owner access is denied"
                ),
                violated_invariant="attacker access to the owner's protected resource is denied",
            )
        )
        decision_value = getattr(causal_result.decision, "value", causal_result.decision)
        if str(decision_value) != "CONFIRMED":
            return LifecycleStageResult(
                "execute_negative_control",
                "inconclusive",
                f"controlled_idor_oracle_{str(decision_value).lower()}",
                observation_refs=(control["observation_ref"],),
            )
        finding = Finding(
            title="Controlled local IDOR causal proof",
            severity=Severity.MEDIUM,
            description=(
                "Purpose-built local target permits a synthetic attacker to read "
                "an owner resource."
            ),
            tool_name=CONTROLLED_VALIDATOR_ID,
            url=self._resource_url(self.state.owned_resource, self.state.attacker_actor),
            vuln_class=VulnClass.IDOR,
            target_param="resource_id",
            request_data={"method": "GET", "route": CONTROLLED_ROUTE_PREFIX},
        )
        target_fingerprint = _target_fingerprint(
            f"{self.target_origin}{CONTROLLED_ROUTE_PREFIX}{{resource_id}}"
        )
        verification = verify_replay_evidence(
            finding,
            baseline=self._observations["baseline"],
            candidate=self._observations["candidate"],
            negative_control=control,
            target_fingerprint=target_fingerprint,
            validator_id=CONTROLLED_VALIDATOR_ID,
            validator_version=CONTROLLED_VALIDATOR_VERSION,
            causal_basis=causal_result.reason,
            engagement_id=run_context.engagement_id,
            hypothesis_id=f"{CONTROLLED_IDOR_CASE_ID}:foreign-owner-read",
            scope_context={
                "target_origin": self.target_origin,
                "scope_bound": True,
                "loopback_only": True,
                "allowed_method": "GET",
                "route_template": CONTROLLED_ROUTE_PREFIX,
            },
            identity_context={
                "mode": "synthetic_opaque_identities",
                "baseline_identity": IdentityContext(
                    "identity:owner", self.state.owner_actor
                ).as_dict(),
                "candidate_identity": IdentityContext(
                    "identity:attacker", self.state.attacker_actor
                ).as_dict(),
                "negative_control_identity": IdentityContext(
                    "identity:attacker", self.state.attacker_actor
                ).as_dict(),
            },
            replay_metadata={
                "sequence": ["baseline", "candidate", "negative_control"],
                "reset_state_hash": self.state_hash,
                "actual_loopback_gets": 3,
            },
            require_target_backed=True,
            causal_result=causal_result,
            campaign_id=CONTROLLED_CAMPAIGN_ID,
            run_id=run_context.run_id,
            vulnerability_class=OracleFamily.IDOR.value,
            target_identity=self.target_id,
            target_context_hash=self.target_context_hash,
        )
        self._last_verification = verification
        return LifecycleStageResult(
            "execute_negative_control",
            "completed" if verification.passed else "inconclusive",
            "controlled_idor_target_backed_proof_verified"
            if verification.passed
            else verification.reason,
            observation_refs=(control["observation_ref"],),
            verification=verification,
            metadata={
                "target_backed": "True",
                "negative_control_independent": "True",
                "validator_id": CONTROLLED_VALIDATOR_ID,
                "validator_version": CONTROLLED_VALIDATOR_VERSION,
            },
        )

    def cleanup(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del case, authorization, run_context
        self._observations.clear()
        return LifecycleStageResult(
            "cleanup", "completed", "controlled_target_adapter_state_cleared"
        )

    def workflow_ids(self) -> tuple[str, ...]:
        return (READ_ONLY_NAVIGATION,)

    def workflow_executors(self) -> dict[str, object]:
        return {}

    def case_ids(self) -> tuple[str, ...]:
        return (CONTROLLED_IDOR_CASE_ID,)

    def case_definition(self) -> CaseDefinition:
        return CaseDefinition(
            case_id=CONTROLLED_IDOR_CASE_ID,
            workflow_id=READ_ONLY_NAVIGATION,
            required_capabilities=(
                "read_only_navigation",
                "identity_model",
                "ownership_model",
                "deterministic_reset",
                "oracle_signal",
                "independent_negative_control",
            ),
            mutates_state=False,
            requires_auth=False,
            requires_negative_control=True,
        )

    def case(self, case_id: str) -> TargetCaseBinding | None:
        if str(case_id or "").strip() != CONTROLLED_IDOR_CASE_ID:
            return None
        return TargetCaseBinding(
            case_id=CONTROLLED_IDOR_CASE_ID,
            operation="navigate",
            path=CONTROLLED_ROUTE_PREFIX,
            oracle_id=CONTROLLED_IDOR_ORACLE_ID,
            workflow_id=READ_ONLY_NAVIGATION,
            semantic_profile=None,
            scoring_status="technical_proof_only_not_approved_scoring_case",
        )

    def semantic_profile_for_case(self, case_id: str) -> str | None:
        return None if str(case_id or "").strip() == CONTROLLED_IDOR_CASE_ID else None

    def accepts_origin(self, origin: str) -> bool:
        return bool(self.target_origin) and _normalize_origin(origin) == _normalize_origin(
            self.target_origin
        )

    def preconditions_ready(self, case_id: str) -> bool:
        if str(case_id or "").strip() != CONTROLLED_IDOR_CASE_ID:
            return False
        if not self.running or self._target_spec is None:
            return False
        if not self.target_origin.startswith("http://127.0.0.1:"):
            return False
        return (
            self._target_spec.scope_validator()
            .decide(self._resource_url(self.state.owned_resource, self.state.owner_actor))
            .allowed
        )

    def supports_operation(self, operation: str) -> bool:
        return str(operation or "").strip() == "navigate"

    def _resource_url(self, resource: str, actor: str) -> str:
        return f"{self.target_origin}{CONTROLLED_ROUTE_PREFIX}{resource}?actor={actor}"

    def _request_observation(
        self,
        *,
        role: str,
        actor: str,
        resource: str,
        run_context: LifecycleRunContext,
    ) -> dict[str, Any]:
        url = self._resource_url(resource, actor)
        if self._target_spec is None:
            raise RuntimeError("controlled_target_spec_not_bound")
        decision = self._target_spec.scope_validator().decide(url, method="GET")
        if not decision.allowed:
            raise RuntimeError(f"controlled_target_request_out_of_scope:{decision.reason_code}")
        # P1-14 (0.33.0): budget check+increment is atomic now — the unlocked
        # check-then-act let concurrent calls overshoot max_requests.
        with self._lifecycle_lock:
            if self._request_count >= self._target_spec.max_requests:
                raise RuntimeError("controlled_target_request_budget_exhausted")
            self._request_count += 1
        request_facts = {
            "method": "GET",
            "route_template": CONTROLLED_ROUTE_PREFIX,
            "actor_role": "owner" if actor == self.state.owner_actor else "attacker",
            "resource_relation": _resource_relation(self.state, actor, resource),
        }
        request_digest = _digest(request_facts)
        status, response_facts = _http_get_redacted(url, self._target_spec.timeout_seconds)
        response_digest = _digest({"status_code": status, **response_facts})
        relation = _resource_relation(self.state, actor, resource)
        is_owner = actor == self.state.owner_actor and resource == self.state.owned_resource
        is_vulnerable_candidate = (
            actor == self.state.attacker_actor and resource == self.state.owned_resource
        )
        control_denied = (
            actor == self.state.attacker_actor
            and resource == self.state.unrelated_resource
            and status == 403
        )
        access_allowed = status == 200
        return {
            "target_backed": True,
            "evidence_origin": "target_runtime",
            "observation_role": role,
            "observation_ref": f"target:{run_context.run_id}:{role}",
            "target_fingerprint": _target_fingerprint(
                f"{self.target_origin}{CONTROLLED_ROUTE_PREFIX}{{resource_id}}"
            ),
            "request_digest": request_digest,
            "response_digest": response_digest,
            "status_code": status,
            "body_length": int(response_facts.get("body_length", 0)),
            "semantic_fingerprint": f"idor:{relation}:{'allowed' if access_allowed else 'denied'}",
            "signals": {
                "invariant_holds": bool(is_owner or control_denied),
                "invariant_violated": bool(is_vulnerable_candidate and access_allowed),
                "access_authorized": bool(is_owner),
                "access_outcome": "allowed" if access_allowed else "denied",
                "actor_role": "owner" if actor == self.state.owner_actor else "attacker",
                "resource_relation": relation,
                "policy_expectation": "allow_owner_deny_protected_non_owner",
                "independent_control": bool(role == "negative_control"),
            },
        }


def build_controlled_target_spec(
    origin: str,
    *,
    engagement_id: str = "controlled-local-idor-engagement-v1",
    authorization: AuthorizationRecord | None = None,
) -> TargetSpec:
    """Build an explicit, unauthenticated spec for the ephemeral loopback target."""
    now = datetime.now(UTC)
    record = authorization or AuthorizationRecord(
        authorization_id="auth-controlled-local-idor-v1",
        authorized_by="owner-approved-controlled-local-target",
        operator="local-validation-runner",
        permitted_test_types=["GET-only-causal-validation"],
        exclusions=["external_targets", "credentials", "state_mutation", "callbacks"],
        emergency_stop_contact="local-process-exit",
        time_window_start=now - timedelta(minutes=1),
        time_window_end=now + timedelta(hours=1),
        user_confirmed=True,
    )
    parsed = urlsplit(origin)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
        raise ValueError("controlled_target_origin_must_be_ephemeral_loopback_http")
    return TargetSpec(
        engagement_id=engagement_id,
        base_url=origin,
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[parsed.port],
        # TargetSpec requires the origin root itself to be in scope; the
        # adapter separately enforces the fixed resource route grammar.
        allowed_paths=["/", CONTROLLED_ROUTE_PREFIX],
        excluded_paths=[],
        profile="single_target_safe",
        auth_mode="unauthenticated",
        allowed_schemes=["http"],
        max_requests=3,
        max_concurrency=1,
        requests_per_second=10.0,
        timeout_seconds=3,
        allow_private_target=True,
        authorization=record,
    )


def build_controlled_idor_target() -> ControlledIDORTarget:
    """Create an unstarted target; callers must use its context manager or start()."""
    return ControlledIDORTarget()


def build_controlled_idor_registration(
    adapter: ControlledIDORTarget,
) -> RegisteredTargetAdapter:
    if not adapter.running or not adapter.target_origin:
        raise ValueError("controlled_target_must_be_running_before_registration")
    return RegisteredTargetAdapter(
        adapter=adapter,
        source="webpent.adapters.controlled_target.adapter",
        version=CONTROLLED_TARGET_VERSION,
        policy_ref="controlled-local-loopback-get-only-v1",
        proof_contract="causal-id-oracle-target-runtime-sealed-replay-v1",
        manifest=TargetManifest(
            target_id=adapter.target_id,
            adapter_version=CONTROLLED_TARGET_VERSION,
            supported_capabilities=frozenset(
                {
                    "read_only_navigation",
                    "identity_model",
                    "ownership_model",
                    "deterministic_reset",
                    "oracle_signal",
                    "independent_negative_control",
                }
            ),
            supported_case_types=frozenset({"navigate"}),
            authorization_requirements=(
                "controlled_local_target_authorization",
                "loopback_origin",
                "get_only_causal_validation",
            ),
            allowed_scope=(adapter.target_origin,),
            redaction_policy="structured_digests_only_no_raw_bodies_or_credentials",
            cleanup_policy="shutdown_ephemeral_server_and_clear_in_memory_fixture",
        ),
        metadata={
            "target_family": "controlled_local_target",
            "target_version": CONTROLLED_TARGET_VERSION,
            "intentional_vulnerability": "idor",
            "approved_scoring_case": False,
            "qualification_effect": False,
            "external_scope": False,
        },
    )


def _http_get_redacted(url: str, timeout_seconds: int) -> tuple[int, dict[str, Any]]:
    http_request = request.Request(
        url, method="GET", headers={"Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(
            http_request, timeout=timeout_seconds
        ) as response:
            status = int(response.status)
            body = response.read(64 * 1024)
    except HTTPError as exc:
        status = int(exc.code)
        body = exc.read(64 * 1024)
    except (URLError, OSError) as exc:
        raise RuntimeError(f"controlled_target_http_request_failed:{type(exc).__name__}") from exc
    return status, {"body_length": len(body), "response_shape": "json_redacted"}


def _causal_model(observation: dict[str, Any]) -> CausalObservation:
    return CausalObservation(
        observation_ref=observation["observation_ref"],
        role=observation["observation_role"],
        semantic_fingerprint=observation["semantic_fingerprint"],
        request_digest=observation["request_digest"],
        response_digest=observation["response_digest"],
        signals=observation["signals"],
        target_backed=True,
        evidence_origin="target_runtime",
    )


def _resource_relation(state: _ControlledState, actor: str, resource: str) -> str:
    if actor == state.owner_actor and resource == state.owned_resource:
        return "owner_owned_resource"
    if actor == state.attacker_actor and resource == state.owned_resource:
        return "foreign_owner_resource"
    if actor == state.attacker_actor and resource == state.unrelated_resource:
        return "unrelated_protected_resource"
    return "unsupported_relation"


def _target_fingerprint(url: str) -> str:
    parsed = urlsplit(str(url))
    shape = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path or '/'}"
    return f"sha256:{hashlib.sha256(shape.encode('utf-8')).hexdigest()}"


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"


def _normalize_origin(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    if parsed.scheme.lower() != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
        return ""
    return f"http://127.0.0.1:{parsed.port}"


CONTROLLED_TARGET_ADAPTER = ControlledIDORTarget()

__all__ = [
    "CONTROLLED_CAMPAIGN_ID",
    "CONTROLLED_IDOR_CASE_ID",
    "CONTROLLED_IDOR_ORACLE_ID",
    "CONTROLLED_TARGET_ADAPTER",
    "CONTROLLED_TARGET_ID",
    "ControlledIDORTarget",
    "build_controlled_idor_registration",
    "build_controlled_idor_target",
    "build_controlled_target_spec",
]
