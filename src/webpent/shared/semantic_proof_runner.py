"""Strict three-way runner for read-only semantic target adapters.

This runner is transport-free and delegates every GET to the existing control
plane.  It is deliberately stricter than an observation collector: a profile
must be registered and promotable, candidate semantics must differ from both
baseline and the independent negative control, and the central verifier must
seal and replay the resulting bundle.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
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
    evaluate_scope,
)
from webpent.shared.control_plane_runtime import (
    BrowserActionAdapter,
    project_browser_observation,
)
from webpent.shared.control_plane_spine import ActionReplayEngine, ReplayReceipt
from webpent.shared.runtime import (
    CONTROL_PLANE_BROWSER_INVENTORY_REF,
    CONTROL_PLANE_BROWSER_PROOF_CONTRACT,
)
from webpent.shared.semantic_observations import (
    SemanticProfileRegistry,
    semantic_profile_contract,
)
from webpent.shared.verifier import VerificationResult, verify_replay_evidence


@dataclass(frozen=True)
class SemanticProofRun:
    """Bounded result; attestation exists only after central verification."""

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


def _origin_fingerprint(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    shape = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    return "sha256:" + hashlib.sha256(shape.encode("utf-8", "replace")).hexdigest()


_SEMANTIC_FIELDS = frozenset(
    {
        "semantic_profile",
        "semantic_observation_version",
        "content_type_family",
        "response_length_bucket",
        "semantic_path_digest",
        "metric_line_count_bucket",
        "policy_directive_count_bucket",
        "log_record_count_bucket",
        "signature_field_count_bucket",
        "semantic_reason",
        "semantic_match",
        "semantic_oracle_ready",
        "directory_shape",
        "verbose_error_shape",
        "scoreboard_shape",
    }
)


def _bounded_observation(receipt: ReplayReceipt) -> dict[str, Any]:
    projected = project_browser_observation(receipt.observation)
    return {
        key: value
        for key, value in projected.items()
        if key in _SEMANTIC_FIELDS
        or key
        in {
            "handler_id",
            "handler_version",
            "target_backed",
            "observation_role",
            "target_fingerprint",
            "request_digest",
            "response_digest",
            "status_code",
            "final_url_shape_digest",
            "replayable",
        }
    }


def _receipt_observation(
    receipt: ReplayReceipt, role: str, *, expected_fingerprint: str
) -> dict[str, Any] | None:
    if receipt.status not in {"completed", "executed"}:
        return None
    observation = _bounded_observation(receipt)
    required = ("target_fingerprint", "request_digest", "response_digest")
    if (
        observation.get("observation_role") != role
        or observation.get("target_backed") is not True
        or observation.get("replayable") is not True
        or observation.get("target_fingerprint") != expected_fingerprint
        or any(
            not isinstance(observation.get(field), str)
            or not observation[field].startswith("sha256:")
            for field in required
        )
    ):
        return None
    return observation


class SemanticProofRunner:
    """Run a reviewed read-only semantic profile through central replay."""

    def __init__(
        self,
        *,
        replay_engine: ActionReplayEngine,
        adapter: BrowserActionAdapter,
        session: BrowserSessionRef,
        scope: EngagementScope,
        engagement_id: str,
        semantic_profile: str,
        semantic_profiles: SemanticProfileRegistry | None,
        validator_id: str,
        validator_version: str = "1.0",
        g02_inventory_ref: str = CONTROL_PLANE_BROWSER_INVENTORY_REF,
        g02_proof_contract: str = CONTROL_PLANE_BROWSER_PROOF_CONTRACT,
    ) -> None:
        if semantic_profiles is None:
            raise ValueError("semantic_profile_registry_required")
        contract = semantic_profile_contract(
            semantic_profile,
            registry=semantic_profiles,
        )
        if contract is None:
            raise ValueError("semantic_profile_not_registered")
        if contract.get("promotable") is not True:
            raise ValueError("semantic_profile_not_promotable")
        self.replay_engine = replay_engine
        self.adapter = adapter
        self.session = session
        self.scope = scope
        self.engagement_id = str(engagement_id or "").strip()
        self.semantic_profile = str(semantic_profile).strip()
        self.semantic_profiles = semantic_profiles
        self.validator_id = str(validator_id or "").strip()
        self.validator_version = str(validator_version or "").strip()
        self.g02_inventory_ref = str(g02_inventory_ref or "").strip()
        self.g02_proof_contract = str(g02_proof_contract or "").strip()
        if not self.engagement_id or session.engagement_id != self.engagement_id:
            raise ValueError("semantic_proof_engagement_mismatch")
        if scope.engagement_id != self.engagement_id:
            raise ValueError("semantic_proof_scope_engagement_mismatch")
        if not self.validator_id or not self.validator_version:
            raise ValueError("semantic_proof_validator_identity_required")

    def _request(self, finding: Finding, role: str, url: str) -> BrowserActionRequest:
        decision = evaluate_scope(self.scope, url, method="GET")
        return BrowserActionRequest(
            action_id=f"semantic-proof-{finding.id}-{role}-{uuid4().hex[:12]}",
            engagement_id=self.engagement_id,
            session_id=self.session.session_id,
            operation="navigate",
            url=url,
            scope_decision=decision,
            timeout_ms=15_000,
            idempotency_key=f"{self.engagement_id}:{finding.id}:{role}:{uuid4().hex}",
            observation_role=role,
            semantic_profile=self.semantic_profile,
        )

    def _replay(self, finding: Finding, role: str, url: str) -> ReplayReceipt:
        request = self._request(finding, role, url)
        return self.replay_engine.replay_browser(
            request,
            self.session,
            self.adapter,
            target_url=url,
            vulnerability_class=str(finding.vuln_class),
            hypothesis_id=f"finding:{finding.id}",
            validator_id=self.validator_id,
            g02_inventory_ref=self.g02_inventory_ref,
            g02_proof_contract=self.g02_proof_contract,
        )

    def run(
        self,
        finding: Finding,
        *,
        baseline_url: str,
        candidate_url: str,
        negative_control_url: str,
        scope_context: Mapping[str, Any],
        identity_context: Mapping[str, Any],
        replay_metadata: Mapping[str, Any] | None = None,
        target_package: Mapping[str, Any] | None = None,
    ) -> SemanticProofRun:
        urls = {
            "baseline": str(baseline_url or "").strip(),
            "candidate": str(candidate_url or "").strip(),
            "negative_control": str(negative_control_url or "").strip(),
        }
        if not all(urls.values()):
            return SemanticProofRun(False, "semantic_urls_required", {})
        if any(_origin(url) != _origin(finding.url) for url in urls.values()):
            return SemanticProofRun(False, "semantic_target_origin_mismatch", {})
        expected_fingerprint = _origin_fingerprint(finding.url)
        if any(_origin_fingerprint(url) != expected_fingerprint for url in urls.values()):
            return SemanticProofRun(
                False,
                "semantic_controls_must_preserve_target_fingerprint",
                {},
            )
        if any(
            evaluate_scope(self.scope, url, method="GET").decision
            != ScopeDecisionType.ALLOWED
            for url in urls.values()
        ):
            return SemanticProofRun(False, "semantic_target_outside_scope", {})
        if self.session.session_id == "":
            return SemanticProofRun(False, "browser_session_required", {})
        try:
            receipts = {
                role: self._replay(finding, role, url)
                for role, url in urls.items()
            }
        except Exception as exc:
            return SemanticProofRun(False, f"semantic_replay_failed:{type(exc).__name__}", {})
        observations: dict[str, Mapping[str, Any]] = {}
        for role, receipt in receipts.items():
            observation = _receipt_observation(
                receipt, role, expected_fingerprint=expected_fingerprint
            )
            if observation is None:
                return SemanticProofRun(
                    False,
                    f"{role}_semantic_observation_missing_or_unusable",
                    observations,
                    diagnostics={"receipt_status": receipt.status},
                )
            observations[role] = observation
        baseline = observations["baseline"]
        candidate = observations["candidate"]
        negative = observations["negative_control"]
        request_digests = {
            candidate.get("request_digest"),
            negative.get("request_digest"),
        }
        if len(request_digests) != 2:
            return SemanticProofRun(
                False,
                "negative_control_request_must_be_distinct",
                observations,
            )
        if (
            candidate.get("semantic_match") is not True
            or baseline.get("semantic_match") is True
            or negative.get("semantic_match") is True
        ):
            return SemanticProofRun(
                False,
                "semantic_causal_delta_not_demonstrated",
                observations,
            )
        if candidate.get("response_digest") == baseline.get("response_digest"):
            return SemanticProofRun(
                False,
                "semantic_candidate_response_delta_required",
                observations,
            )
        if candidate.get("response_digest") == negative.get("response_digest"):
            return SemanticProofRun(
                False,
                "semantic_negative_control_response_must_differ",
                observations,
            )
        contract = (
            semantic_profile_contract(
                self.semantic_profile,
                registry=self.semantic_profiles,
            )
            or {}
        )
        causal_basis = (
            f"{self.semantic_profile}:candidate_semantic_match_only_with_independent_control;"
            f"contract={contract.get('reason', 'registered')}"
        )
        package = dict(target_package or {})
        verification = verify_replay_evidence(
            finding,
            baseline=dict(baseline),
            candidate=dict(candidate),
            negative_control=dict(negative),
            causal_signal=True,
            negative_control_complete=True,
            validator_id=self.validator_id,
            validator_version=self.validator_version,
            causal_basis=causal_basis,
            engagement_id=self.engagement_id,
            hypothesis_id=f"finding:{finding.id}",
            scope_context=dict(scope_context),
            identity_context=dict(identity_context),
            target_fingerprint=expected_fingerprint,
            replay_metadata={
                "runner": "semantic_proof_runner.v1",
                "semantic_profile": self.semantic_profile,
                "receipt_statuses": {
                    role: receipt.status for role, receipt in receipts.items()
                },
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
            return SemanticProofRun(
                False,
                verification.reason,
                observations,
                verifier_result=verification,
            )
        return SemanticProofRun(
            True,
            verification.reason,
            observations,
            attestation=dict(verification.evidence),
            verifier_result=verification,
        )


__all__ = ["SemanticProofRun", "SemanticProofRunner"]
