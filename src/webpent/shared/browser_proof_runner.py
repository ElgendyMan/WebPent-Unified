"""Strict typed browser proof orchestration.

The runner is deliberately transport-free.  It creates only digest/reference
metadata for ephemeral probes and delegates every browser operation to the
registered control-plane replay engine.  It never calls Playwright directly,
never signs a bundle, and never promotes a finding.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from webpent.models.findings import Finding
from webpent.shared.control_plane import (
    BrowserActionRequest,
    BrowserSessionRef,
    EngagementScope,
    ScopeDecisionType,
)
from webpent.shared.control_plane_runtime import BrowserActionAdapter
from webpent.shared.control_plane_spine import ActionReplayEngine, ReplayReceipt
from webpent.shared.runtime import (
    CONTROL_PLANE_BROWSER_INVENTORY_REF,
    CONTROL_PLANE_BROWSER_PROOF_CONTRACT,
)
from webpent.shared.verifier import VerificationResult, verify_replay_evidence


@dataclass(frozen=True)
class EphemeralProbe:
    """Reference and digest for a probe value held only by the live resolver."""

    role: str
    probe_ref: str
    probe_digest: str

    @classmethod
    def from_value(
        cls,
        role: str,
        value: str,
        *,
        probe_ref: str | None = None,
    ) -> EphemeralProbe:
        if not isinstance(value, str) or not value:
            raise ValueError("browser_probe_value_required")
        ref = str(probe_ref or f"probe://ephemeral/{uuid4().hex}")
        if not ref.startswith("probe://"):
            raise ValueError("browser_probe_reference_invalid")
        digest = "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
        return cls(role=str(role), probe_ref=ref, probe_digest=digest)

    def validate(self, expected_role: str) -> None:
        if self.role != expected_role:
            raise ValueError("browser_probe_role_mismatch")
        if not self.probe_ref.startswith("probe://"):
            raise ValueError("browser_probe_reference_invalid")
        if not self.probe_digest.startswith("sha256:") or len(self.probe_digest) != 71:
            raise ValueError("browser_probe_digest_invalid")


CausalPredicate = Callable[
    [Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]],
    tuple[bool, str] | bool,
]


@dataclass(frozen=True)
class BrowserProofRun:
    """Bounded runner result; attestation exists only after verifier success."""

    passed: bool
    reason: str
    observations: Mapping[str, Mapping[str, Any]]
    attestation: Mapping[str, Any] | None = None
    verifier_result: VerificationResult | None = None
    diagnostics: Mapping[str, Any] = field(default_factory=dict)


def _origin(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    port = parsed.port
    default = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
        parsed.scheme.lower() == "https" and port in {None, 443}
    )
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}" + (
        "" if default else f":{port}"
    )


def _target_fingerprint(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    shape = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    return "sha256:" + hashlib.sha256(shape.encode("utf-8", "replace")).hexdigest()


def _bounded_observation(receipt: ReplayReceipt) -> dict[str, Any]:
    observation = receipt.observation
    if not isinstance(observation, Mapping):
        return {}
    # replay_browser already projects/redacts; this second projection keeps the
    # runner contract explicit and prevents future adapter fields from leaking.
    allowed = {
        "handler_id",
        "handler_version",
        "target_backed",
        "observation_role",
        "target_fingerprint",
        "request_digest",
        "response_digest",
        "status_code",
        "final_url_shape_digest",
        "dialog_count",
        "dialog_events",
        "network_event_count",
        "network_event_shape_digests",
        "dom_digest",
        "screenshot_digest",
        "replayable",
    }
    result = {key: observation[key] for key in allowed if key in observation}
    return result


def _non_dialog_delta(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> bool:
    """Require a response/network/DOM delta in addition to any dialog signal."""
    fields = (
        "response_digest",
        "status_code",
        "final_url_shape_digest",
        "network_event_count",
        "dom_digest",
    )
    return any(baseline.get(field) != candidate.get(field) for field in fields)


class BrowserProofRunner:
    """Run a generic three-observation browser proof through the control plane."""

    def __init__(
        self,
        *,
        replay_engine: ActionReplayEngine,
        adapter: BrowserActionAdapter,
        session: BrowserSessionRef,
        scope: EngagementScope,
        engagement_id: str,
        validator_id: str = "webpent.browser-proof",
        validator_version: str = "1.0",
        browser_operation: str = "validate_input",
        workflow_id: str | None = None,
        workflow_allowlist: Collection[str] | None = None,
        g02_inventory_ref: str = CONTROL_PLANE_BROWSER_INVENTORY_REF,
        g02_proof_contract: str = CONTROL_PLANE_BROWSER_PROOF_CONTRACT,
    ) -> None:
        self.replay_engine = replay_engine
        self.adapter = adapter
        self.session = session
        self.scope = scope
        self.engagement_id = str(engagement_id or "").strip()
        self.validator_id = str(validator_id or "").strip()
        self.validator_version = str(validator_version or "").strip()
        self.browser_operation = str(browser_operation or "").strip()
        self.workflow_id = str(workflow_id or "").strip() or None
        self.workflow_allowlist = frozenset(
            str(item).strip() for item in (workflow_allowlist or ()) if str(item).strip()
        )
        self.g02_inventory_ref = str(g02_inventory_ref or "").strip()
        self.g02_proof_contract = str(g02_proof_contract or "").strip()
        if not self.engagement_id or self.session.engagement_id != self.engagement_id:
            raise ValueError("browser_proof_engagement_mismatch")
        if self.scope.engagement_id != self.engagement_id:
            raise ValueError("browser_proof_scope_engagement_mismatch")
        if not self.validator_id or not self.validator_version:
            raise ValueError("browser_proof_validator_identity_required")
        if self.browser_operation not in {"validate_input", "typed_search"}:
            raise ValueError("browser_proof_operation_not_allowlisted")
        if self.browser_operation == "typed_search" and (
            not self.workflow_id or self.workflow_id not in self.workflow_allowlist
        ):
            raise ValueError("browser_proof_workflow_not_allowlisted")
        if self.browser_operation == "validate_input" and self.workflow_id is not None:
            raise ValueError("browser_proof_workflow_not_allowed")

    @staticmethod
    def _action_id(finding: Finding, role: str) -> str:
        return f"browser-proof-{str(finding.id)}-{role}-{uuid4().hex[:12]}"

    def _request(
        self,
        finding: Finding,
        probe: EphemeralProbe,
        *,
        target_url: str,
    ) -> BrowserActionRequest:
        decision = self._scope_decision(target_url)
        return BrowserActionRequest(
            action_id=self._action_id(finding, probe.role),
            engagement_id=self.engagement_id,
            session_id=self.session.session_id,
            operation=self.browser_operation,
            url=target_url,
            scope_decision=decision,
            timeout_ms=15_000,
            idempotency_key=f"{self.engagement_id}:{finding.id}:{probe.role}:{uuid4().hex}",
            observation_role=probe.role,
            probe_ref=probe.probe_ref,
            probe_digest=probe.probe_digest,
            workflow_id=self.workflow_id,
        )

    def _scope_decision(self, target_url: str):
        from webpent.shared.control_plane import evaluate_scope

        return evaluate_scope(self.scope, target_url, method="POST")

    def _replay(
        self,
        finding: Finding,
        probe: EphemeralProbe,
        *,
        target_url: str,
        probe_value: str | None = None,
    ) -> ReplayReceipt:
        registrar = getattr(self.adapter, "register_ephemeral_probe", None)
        cleaner = getattr(self.adapter, "clear_ephemeral_probe", None)
        if probe_value is not None:
            if not callable(registrar):
                raise RuntimeError("ephemeral_probe_registrar_unavailable")
            registrar(probe.probe_ref, probe_value)
        try:
            request = self._request(finding, probe, target_url=target_url)
            return self.replay_engine.replay_browser(
                request,
                self.session,
                self.adapter,
                target_url=target_url,
                vulnerability_class=str(finding.vuln_class),
                hypothesis_id=f"finding:{finding.id}",
                validator_id=self.validator_id,
                g02_inventory_ref=self.g02_inventory_ref,
                g02_proof_contract=self.g02_proof_contract,
            )
        finally:
            if callable(cleaner):
                cleaner(probe.probe_ref)

    @staticmethod
    def _receipt_diagnostic(receipt: ReplayReceipt, role: str) -> dict[str, Any]:
        observation = _bounded_observation(receipt)
        status = str(receipt.status or "")[:40]
        if status not in {"completed", "executed"}:
            return {
                "failure_code": "receipt_status_unusable",
                "role": role,
                "receipt_status": status,
                "missing_fields": ["completed_receipt"],
            }
        if not observation:
            return {
                "failure_code": "observation_missing",
                "role": role,
                "receipt_status": status,
                "missing_fields": ["observation"],
            }
        if observation.get("observation_role") != role:
            return {
                "failure_code": "observation_role_mismatch",
                "role": role,
                "receipt_status": status,
                "missing_fields": ["observation_role"],
            }
        missing_fields: list[str] = []
        if observation.get("target_backed") is not True:
            missing_fields.append("target_backed")
        if observation.get("replayable") is not True:
            missing_fields.append("replayable")
        for field_name in ("target_fingerprint", "request_digest", "response_digest"):
            value = observation.get(field_name)
            if not isinstance(value, str) or not value.startswith("sha256:"):
                missing_fields.append(field_name)
        return {
            "failure_code": "observation_fields_invalid",
            "role": role,
            "receipt_status": status,
            "missing_fields": missing_fields,
        }

    @staticmethod
    def _receipt_observation(receipt: ReplayReceipt, role: str) -> dict[str, Any] | None:
        if receipt.status not in {"completed", "executed"}:
            return None
        observation = _bounded_observation(receipt)
        if not observation:
            return None
        if observation.get("observation_role") != role:
            return None
        if observation.get("target_backed") is not True:
            return None
        if observation.get("replayable") is not True:
            return None
        for field_name in ("target_fingerprint", "request_digest", "response_digest"):
            value = observation.get(field_name)
            if not isinstance(value, str) or not value.startswith("sha256:"):
                return None
        return observation

    def run(
        self,
        finding: Finding,
        *,
        baseline: EphemeralProbe,
        candidate: EphemeralProbe,
        negative_control: EphemeralProbe,
        causal_predicate: CausalPredicate,
        scope_context: Mapping[str, Any],
        identity_context: Mapping[str, Any],
        target_url: str | None = None,
        replay_metadata: Mapping[str, Any] | None = None,
        target_package: Mapping[str, Any] | None = None,
        probe_values: Mapping[str, str] | None = None,
    ) -> BrowserProofRun:
        """Return an attestation only when all three typed replays verify."""
        try:
            baseline.validate("baseline")
            candidate.validate("candidate")
            negative_control.validate("negative_control")
        except ValueError as exc:
            return BrowserProofRun(False, str(exc), {})
        if candidate.probe_digest == negative_control.probe_digest:
            return BrowserProofRun(False, "negative_control_probe_must_be_distinct", {})
        if not callable(causal_predicate):
            return BrowserProofRun(False, "causal_predicate_required", {})

        url = str(target_url or finding.url or "").strip()
        if not url or _origin(url) != _origin(finding.url):
            return BrowserProofRun(False, "finding_target_origin_mismatch", {})
        if self._scope_decision(url).decision != ScopeDecisionType.ALLOWED:
            return BrowserProofRun(False, "target_outside_declared_scope", {})
        if self.session.session_id == "":
            return BrowserProofRun(False, "browser_session_required", {})

        values = dict(probe_values or {})
        if any(
            ref not in values or not isinstance(values[ref], str)
            for ref in (baseline.probe_ref, candidate.probe_ref, negative_control.probe_ref)
        ):
            return BrowserProofRun(False, "ephemeral_probe_values_required", {})
        try:
            receipts = {
                "baseline": self._replay(
                    finding, baseline, target_url=url, probe_value=values[baseline.probe_ref]
                ),
                "candidate": self._replay(
                    finding, candidate, target_url=url, probe_value=values[candidate.probe_ref]
                ),
                "negative_control": self._replay(
                    finding, negative_control, target_url=url,
                    probe_value=values[negative_control.probe_ref]
                ),
            }
        except Exception as exc:
            return BrowserProofRun(False, f"typed_replay_failed:{type(exc).__name__}", {})
        observations: dict[str, Mapping[str, Any]] = {}
        for role, receipt in receipts.items():
            observation = self._receipt_observation(receipt, role)
            if observation is None:
                return BrowserProofRun(
                    False,
                    f"{role}_observation_missing_or_unusable",
                    observations,
                    diagnostics=BrowserProofRunner._receipt_diagnostic(receipt, role),
                )
            observations[role] = observation
        expected_fingerprint = _target_fingerprint(url)
        if any(
            observation.get("target_fingerprint") != expected_fingerprint
            for observation in observations.values()
        ):
            return BrowserProofRun(False, "target_fingerprint_mismatch", observations)
        if observations["candidate"].get("request_digest") == observations["negative_control"].get(
            "request_digest"
        ):
            return BrowserProofRun(False, "negative_control_request_must_be_distinct", observations)
        if not _non_dialog_delta(observations["baseline"], observations["candidate"]):
            return BrowserProofRun(False, "non_dialog_causal_delta_required", observations)

        try:
            predicate_result = causal_predicate(
                observations["baseline"],
                observations["candidate"],
                observations["negative_control"],
            )
            if isinstance(predicate_result, tuple):
                causal_signal, causal_basis = predicate_result
            else:
                causal_signal, causal_basis = (
                    bool(predicate_result),
                    "explicit_browser_observation_predicate",
                )
        except Exception:
            return BrowserProofRun(False, "causal_predicate_failed", observations)
        causal_basis = str(causal_basis or "").strip()
        if not causal_signal or not causal_basis:
            return BrowserProofRun(False, "causal_signal_not_demonstrated", observations)
        if causal_basis.lower() in {"dialog", "dialog_only", "llm", "reflection", "lab_route"}:
            return BrowserProofRun(False, "dialog_only_or_non_causal_basis_denied", observations)

        package = dict(target_package or {})
        verification = verify_replay_evidence(
            finding,
            baseline=dict(observations["baseline"]),
            candidate=dict(observations["candidate"]),
            negative_control=dict(observations["negative_control"]),
            causal_signal=True,
            negative_control_complete=True,
            validator_id=self.validator_id,
            validator_version=self.validator_version,
            causal_basis=causal_basis,
            engagement_id=self.engagement_id,
            hypothesis_id=f"finding:{finding.id}",
            scope_context=dict(scope_context),
            identity_context=dict(identity_context),
            replay_metadata={
                "runner": "browser_proof_runner.v1",
                "receipt_statuses": {role: receipt.status for role, receipt in receipts.items()},
                **dict(replay_metadata or {}),
            },
            target_package_id=package.get("target_package_id") or package.get("package_id"),
            target_package_sha256=(
                package.get("target_package_sha256")
                or package.get("package_sha256")
            ),
            target_package_scope_digest=package.get("target_package_scope_digest"),
            target_package_policy_digest=package.get("target_package_policy_digest"),
            require_target_backed=True,
        )
        if not verification.passed or not verification.evidence.get("proof_verified"):
            return BrowserProofRun(
                False,
                verification.reason,
                observations,
                verifier_result=verification,
            )
        # The attestation is the only promotion-bound output.  CampaignExecutor
        # remains responsible for sealing/storing/replaying the final bundle.
        return BrowserProofRun(
            True,
            verification.reason,
            observations,
            attestation=dict(verification.evidence),
            verifier_result=verification,
        )


__all__ = ["BrowserProofRun", "BrowserProofRunner", "CausalPredicate", "EphemeralProbe"]
