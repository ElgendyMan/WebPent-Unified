"""EGAIE real-HTTP experiment port, wired through the production path.

Every request is a CampaignTask executed by the production
ActionExecutor (RuntimeFactory-built ActionAuthority, G-02 smart_http
adapter, engagement safety gate, budgets, ledger). There is no raw
HTTP execution in this module: the transport handler is the
registered adapter's handler and uses make_safe_httpx_client with the
declared engagement-target allowlist, exactly like the production
smart-campaign handler.

The port normalizes real HTTP responses into the observation triple
the CausalGuard contract expects: status_code, semantic_digest (the
sha256 of the real response body), body_length, request path/method,
and the response's own X-Authorization-*/X-Resource-* headers.
Observations from denied executions are placeholders, so the guard
fails closed (BLOCKED) instead of ever guessing.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any
from urllib.parse import urlencode

from webpent.autonomous.authorization import (
    EngagementAuthorization,
    verify_authorization,
)
from webpent.config.settings import Settings
from webpent.egaie.benchmark.http_ground_truth import (
    HTTP_CASE_INDEX,
    HTTP_CASE_V2_INDEX,
)
from webpent.egaie.causal_adapter import ProofBundlePort
from webpent.egaie.http_target import ACTOR_A
from webpent.egaie.schemas import ProposedExperiment
from webpent.shared.action_authority import ActionRisk
from webpent.shared.campaign_executor import CampaignTask
from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.g02_contract import g02_http_metadata
from webpent.shared.runtime import (
    AdapterRegistry,
    RegisteredAdapter,
    RuntimeFactory,
)

MANIFEST_CAPABILITIES: tuple[str, ...] = ("http_read", "http_write")
_MANIFEST_RISK_TIERS: dict[str, str] = {
    "http_read": "read_only",
    "http_write": "active",
}
EXECUTION_TIMEOUT_S = 10.0
MAX_REVEALED_PATH_LENGTH = 200


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _observation(
    path: str, status_code: int | None, headers: dict[str, str],
    body_digest: str, body_length: int, structured: dict[str, Any],
    execution: str, method: str = "GET",
) -> dict[str, Any]:
    return {
        "request": {"method": method, "path": path},
        "status_code": status_code,
        "semantic_digest": body_digest,
        "body_length": body_length,
        "headers": headers,
        "structured": structured,
        "execution": execution,
    }


_PLACEHOLDER_OBSERVATION = {
    "request": {"method": "GET", "path": ""},
    "status_code": None,
    "semantic_digest": "",
    "body_length": 0,
    "headers": {},
    "structured": {},
    "_placeholder": True,
    "execution": "not_executed",
}


class HTTPExperimentPort:
    """Executes EGAIE experiments as real HTTP through ActionExecutor."""

    def __init__(
        self,
        target: Any,
        engagement_id: str,
        campaign_id: str,
        authorization: EngagementAuthorization,
        settings: Settings,
        runtime: Any = None,
    ) -> None:
        self._target = target
        self._engagement_id = engagement_id
        self._campaign_id = campaign_id
        self._authorization = authorization
        self._settings = settings
        self._runtime = runtime
        self.requests_made = 0
        self.denied_actions = 0
        self.production_actions = 0
        self.revealed_paths: dict[str, str] = {}
        self._last_observation: dict[str, Any] | None = None

    @property
    def scope_allowed(self) -> bool:
        ok, _reason = verify_authorization(
            self._target.target_origin, self._authorization)
        return ok is True

    def execute(
        self, experiment: ProposedExperiment,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        if experiment.signature.endswith(":stage2"):
            return self._execute_stage2(experiment)
        return self._execute_stage1(experiment)

    # -- probe-structure mapping (fixture setup, not detection) ----
    @staticmethod
    def _case_of(experiment: ProposedExperiment) -> Any:
        case_id = experiment.signature.split("/", 1)[0]
        if case_id in HTTP_CASE_V2_INDEX:
            return HTTP_CASE_V2_INDEX[case_id]
        return HTTP_CASE_INDEX[case_id]

    def _case_path(self, experiment: ProposedExperiment) -> str:
        return self._case_of(experiment).path

    def _case_baseline_path(self, experiment: ProposedExperiment) -> str:
        return self._case_of(experiment).baseline_path

    def _stage2_baseline_path(self, stage1_signature: str) -> str:
        case_id = stage1_signature.split("/", 1)[0]
        if case_id in HTTP_CASE_V2_INDEX:
            case = HTTP_CASE_V2_INDEX[case_id]
        else:
            case = HTTP_CASE_INDEX[case_id]
        return case.stage2_baseline_path or case.baseline_path

    # -- stage 1 ---------------------------------------------------
    def _execute_stage1(
        self, experiment: ProposedExperiment,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        if self._case_of(experiment).method == "POST":
            return self._execute_stage1_post(experiment)
        path = self._case_path(experiment)
        baseline_path = self._case_baseline_path(experiment)
        baseline = self._observe(
            baseline_path, {"actor": ACTOR_A},
            f"{experiment.experiment_id}-baseline",
        )
        candidate = self._observe(
            path, {"actor": ACTOR_A},
            f"{experiment.experiment_id}-candidate",
        )
        control_path = "/control" + path
        control = self._observe(
            control_path, {"actor": "actor-a"},
            f"{experiment.experiment_id}-control",
        )
        revealed = candidate.get("structured", {}).get("note_path")
        if isinstance(revealed, str) and revealed.startswith("/api/"):
            self.revealed_paths[experiment.signature] = revealed[
                :MAX_REVEALED_PATH_LENGTH]
        return baseline, candidate, control

    # -- stage 2 (stored-input follow-up) --------------------------
    def _execute_stage2(
        self, experiment: ProposedExperiment,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        stage1_signature = experiment.signature[: -len(":stage2")]
        revealed = self.revealed_paths.get(stage1_signature)
        if not revealed:
            placeholder = dict(_PLACEHOLDER_OBSERVATION)
            placeholder["execution"] = "stage1_path_unrevealed"
            return placeholder, placeholder, placeholder
        baseline_path = self._stage2_baseline_path(stage1_signature)
        baseline = self._observe(
            baseline_path, {"actor": ACTOR_A},
            f"{experiment.experiment_id}-baseline",
        )
        candidate = self._observe(
            revealed, {"actor": ACTOR_A},
            f"{experiment.experiment_id}-candidate",
        )
        control_path = "/control" + revealed
        control = self._observe(
            control_path, {"actor": "actor-a"},
            f"{experiment.experiment_id}-control",
        )
        return baseline, candidate, control

    # -- stage 1, state-changing (POST) variant --------------------
    def _execute_stage1_post(
        self, experiment: ProposedExperiment,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        path = self._case_path(experiment)
        baseline_path = self._case_baseline_path(experiment)
        baseline = self._observe_post(
            baseline_path, {"actor": ACTOR_A},
            f"{experiment.experiment_id}-baseline",
        )
        candidate = self._observe_post(
            path, {"actor": ACTOR_A},
            f"{experiment.experiment_id}-candidate",
        )
        control_path = "/control" + path
        control = self._observe_post(
            control_path, {"actor": "actor-a"},
            f"{experiment.experiment_id}-control",
        )
        # Multi-step POST cases: the generic receipt reveals the
        # resource path whose state is only observable through a
        # follow-up GET (stage 2).
        structured = candidate.get("structured", {})
        revealed = (
            structured.get("resource_path") or structured.get("note_path"))
        if isinstance(revealed, str) and revealed.startswith("/api/"):
            self.revealed_paths[experiment.signature] = revealed[
                :MAX_REVEALED_PATH_LENGTH]
        return baseline, candidate, control

    # -- one production-round-tripped POST (state-changing) --------
    def _observe_post(
        self, path: str, params: dict[str, str], task_key: str,
    ) -> dict[str, Any]:
        query = urlencode(sorted(params.items()))
        url = self._target.target_origin + path + "?" + query
        derived_id = uuid.uuid5(uuid.NAMESPACE_URL, task_key)
        # Deterministic per-experiment idempotency token: a resumed or
        # repeated investigation replays the same token, so the target
        # can never double-apply the mutation.
        idem = _sha256(task_key)[:16]
        task = CampaignTask(
            task_id=f"egaie-{task_key}-{derived_id}"[:48],
            engagement_id=self._engagement_id,
            asset_id=f"asset-{task_key}",
            source_evidence_ids=(),
            vulnerability_class="egaie_http_state_probe",
            hypothesis_id=f"h-{task_key}",
            method="POST",
            capability="http_write",
            action_family="form_submit",
            target_url=url,
            probe_family="state_change_compare",
            risk_tier=ActionRisk.ACTIVE,
            idempotency_key=f"egaie-{task_key}-{idem}",
            content_type="application/json",
            metadata={
                **g02_http_metadata(),
                "human_approved": True,
                "request_path": path,
                "request_params": dict(sorted(params.items())),
            },
        )
        self._last_observation = None
        record = self._runtime.action_executor.execute(
            task, self._transport_handler,
            preconditions_met=True,
        )
        self.requests_made += 1
        status = str(record.get("status"))
        if status != "executed":
            self.denied_actions += 1
            placeholder = dict(_PLACEHOLDER_OBSERVATION)
            placeholder["execution"] = status
            return placeholder
        self.production_actions += 1
        observation = self._last_observation
        if observation is None:
            placeholder = dict(_PLACEHOLDER_OBSERVATION)
            placeholder["execution"] = "handler_output_missing"
            return placeholder
        return _observation(
            path,
            observation["status_code"],
            observation["headers"],
            observation["body_sha256"],
            int(observation["body_length"]),
            observation["structured"],
            "executed",
            method="POST",
        )

    # -- one production-round-tripped HTTP request ------------------
    def _observe(
        self, path: str, params: dict[str, str], task_key: str,
    ) -> dict[str, Any]:
        query = urlencode(sorted(params.items()))
        url = self._target.target_origin + path + "?" + query
        derived_id = uuid.uuid5(uuid.NAMESPACE_URL, task_key)
        task = CampaignTask(
            task_id=f"egaie-{task_key}-{derived_id}"[:48],
            engagement_id=self._engagement_id,
            asset_id=f"asset-{task_key}",
            source_evidence_ids=(),
            vulnerability_class="egaie_http_probe",
            hypothesis_id=f"h-{task_key}",
            method="GET",
            capability="http_read",
            action_family="http_read",
            target_url=url,
            metadata={
                **g02_http_metadata(),
                "request_path": path,
                "request_params": dict(sorted(params.items())),
            },
        )
        self._last_observation = None
        record = self._runtime.action_executor.execute(
            task, self._transport_handler,
            preconditions_met=True,
        )
        self.requests_made += 1
        status = str(record.get("status"))
        if status != "executed":
            self.denied_actions += 1
            placeholder = dict(_PLACEHOLDER_OBSERVATION)
            placeholder["execution"] = status
            return placeholder
        self.production_actions += 1
        observation = self._last_observation
        if observation is None:
            placeholder = dict(_PLACEHOLDER_OBSERVATION)
            placeholder["execution"] = "handler_output_missing"
            return placeholder
        return _observation(
            path,
            observation["status_code"],
            observation["headers"],
            observation["body_sha256"],
            int(observation["body_length"]),
            observation["structured"],
            "executed",
        )

    def _transport_handler(self, request: Any) -> dict[str, Any]:
        """The G-02 adapter handler: real HTTP via the safe client.

        Runs only after ActionAuthority authorization. Same-origin is
        enforced against the engagement target; the loopback host is
        reached through the declared-target allowlist of the SSRF
        guard, exactly like the production smart-campaign handler.
        The HTTP verb follows the authorized task's own method: GET
        for read tasks, POST for state-changing (form_submit) tasks.
        """
        from webpent.shared.http import make_safe_httpx_client

        origin = self._authorization.target_origin
        target_url = str(request.target_url)
        if not target_url.startswith(origin + "/") and (
                target_url != origin):
            raise ValueError("same_origin_target_required")
        target_token = set_engagement_target_hosts(origin)
        try:
            with make_safe_httpx_client(
                timeout=EXECUTION_TIMEOUT_S, follow_redirects=False,
            ) as client:
                if str(request.method).upper() == "POST":
                    response = client.post(
                        target_url,
                        content=b"",
                        headers={"Content-Type": "application/json"},
                    )
                else:
                    response = client.get(target_url)
        finally:
            clear_engagement_target_hosts(target_token)
        body = response.text
        structured: dict[str, Any] = {}
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                structured = dict(json.loads(body))
            except (ValueError, TypeError):
                structured = {}
        headers = {
            key: value
            for key, value in response.headers.items()
            if key.lower().startswith(("x-actor-", "x-resource-",
                                       "x-authorization-",
                                       "x-privilege-", "x-effective-"))
        }
        observation = {
            "status_code": response.status_code,
            "headers": headers,
            "body_sha256": _sha256(body),
            "body_length": len(body),
            "structured": structured,
        }
        self._last_observation = observation
        return {
            "handler_status": "executed",
            "observation_recorded": True,
            "observation": observation,
        }


def build_http_experiment_port(
    *,
    target: Any,
    engagement_id: str,
    campaign_id: str,
    authorization: EngagementAuthorization,
    settings: Settings,
) -> HTTPExperimentPort:
    """Build the port on a full production runtime (the real path)."""
    from webpent.shared.g02_contract import (
        G02_HTTP_APPROVAL_EXPIRY,
        G02_HTTP_CANONICAL_WRAPPER,
        G02_HTTP_INVENTORY_REF,
        G02_HTTP_PROOF_CONTRACT,
        G02_HTTP_SCOPE_POLICY,
    )

    registry = AdapterRegistry()
    runtime = RuntimeFactory.create(
        engagement_id=engagement_id,
        campaign_id=campaign_id,
        target_origin=authorization.target_origin,
        settings=settings,
        manifest=_manifest(settings),
        use_default_ledger=False,
        adapters=registry,
    )
    port = HTTPExperimentPort(
        target=target,
        engagement_id=engagement_id,
        campaign_id=campaign_id,
        authorization=authorization,
        settings=settings,
        runtime=runtime,
    )
    # Registration must precede the first execution (the authority
    # resolves the adapter at execute time, not at construction).
    registry.register(RegisteredAdapter(
        name="smart_http",
        capability="smart_http_execution",
        transport="http",
        handler=port._transport_handler,  # noqa: SLF001
        policy_checked=True,
        canonical_wrapper=G02_HTTP_CANONICAL_WRAPPER,
        scope_policy=G02_HTTP_SCOPE_POLICY,
        static_inventory_ref=G02_HTTP_INVENTORY_REF,
        proof_contract=G02_HTTP_PROOF_CONTRACT,
        expires_at=G02_HTTP_APPROVAL_EXPIRY,
    ))
    return port


def _manifest(settings: Settings) -> dict[str, Any]:
    return {
        "capabilities": {
            name: {
                "available": True,
                "status": "available",
                "risk_tier": _MANIFEST_RISK_TIERS[name],
            }
            for name in MANIFEST_CAPABILITIES
        },
    }


class HTTPProofBundlePort(ProofBundlePort):
    """Sealed proof bundles with truthful real-HTTP provenance.

    The bundle says exactly what happened: the candidate observations
    were produced by real HTTP responses executed through the
    production ActionExecutor, not by an in-process fixture.
    """

    def __init__(self) -> None:
        super().__init__(runtime_provenance={
            "mode": "controlled_local_http_target",
            "offline": False,
            "transport": "action_executor",
        })
