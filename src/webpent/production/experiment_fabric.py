"""TEAM-1 — Canonical Experiment Execution Fabric V2.

ONE registry, ONE runner, ONE observation normalizer, ONE validator adapter.
ResearchLoop remains the ONLY scheduler. All execution delegates to
ModernOrchestrator (ScopeLaw + ToolBoundary). No validator opens raw HTTP.

Flow: ResearchLoop → ExperimentRegistry → GenericExperimentRunner →
ObservationNormalizer → ValidatorAdapter → EvidenceQuality → ProofBundle →
OutcomeTracker → WorldModel/ResearchLoop → next decision.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from webpent.models.evidence import redact_sensitive, sha256_text
from webpent.production.validators import (
    ValidationResult,
    run_validator,
)

# ---- PART 2: Canonical Experiment Registry (descriptive, NOT scheduler) ----

EXPERIMENT_REGISTRY: dict[str, dict[str, Any]] = {
    "IDOR": {
        "experiment_id": "exp_idor_v1", "vulnerability_class": "IDOR",
        "action_type": "differential_access",
        "baseline": {"method": "GET", "principal": "owner", "description": "owner accesses own resource"},
        "candidate": {"method": "GET", "principal": "foreign", "description": "foreign principal accesses owner resource"},
        "negative_control": {"method": "GET", "principal": "foreign", "resource": "invalid_id", "description": "invalid resource id"},
        "expected_observation": {"status_diff": True, "body_diff": True},
        "validator": "IDOR", "replay_required": True,
        "execution_bounds": {"max_requests": 3, "max_redirects": 0},
    },
    "OPEN_REDIRECT": {
        "experiment_id": "exp_redirect_v1", "vulnerability_class": "OPEN_REDIRECT",
        "action_type": "redirect_param",
        "baseline": {"param": "url", "value": "https://trusted.com/home"},
        "candidate": {"param": "url", "value": "https://evil.com/steal"},
        "negative_control": {"param": "url", "value": ""},
        "expected_observation": {"location_header": True},
        "validator": "OPEN_REDIRECT", "replay_required": True,
        "contract_version": "v1",
        "hypothesis_template": "redirect parameter may return an unallowlisted external Location",
        "test_matrix": {"baseline": "normal navigation", "candidate": "external redirect parameter", "negative_control": "missing or invalid parameter"},
        "execution_bounds": {"max_requests": 3},
    },
    "SSRF": {
        "experiment_id": "exp_ssrf_v1", "vulnerability_class": "SSRF",
        "action_type": "url_param_fetch",
        "baseline": {"param": "url", "value": "https://api.example.com/data"},
        "candidate": {"param": "url", "value": "http://169.254.169.254/latest/meta-data/"},
        "negative_control": {"param": "url", "value": "ftp://invalid"},
        "expected_observation": {"body_indicators": ["metadata", "iam", "token"]},
        "validator": "SSRF", "replay_required": True,
        "contract_version": "v1",
        "hypothesis_template": "URL-bearing server-side fetch may reach an internal resource",
        "test_matrix": {"baseline": "normal external URL fetch", "candidate": "internal/metadata URL fetch", "negative_control": "invalid scheme or rejected URL"},
        "execution_bounds": {"max_requests": 3},
    },
    "XSS": {
        "experiment_id": "exp_xss_v1", "vulnerability_class": "XSS",
        "action_type": "reflected_input",
        "baseline": {"method": "GET", "payload": "", "description": "clean input"},
        "candidate": {"method": "GET", "payload": "<script>webpent_xss_probe_7f1</script>", "description": "benign reflection marker"},
        "negative_control": {"method": "GET", "payload": "webpent_encoded_control_7f1", "description": "encoded/reflection control"},
        "expected_observation": {"html_reflection": True, "unencoded": True},
        "validator": "XSS", "replay_required": True,
        "contract_version": "v1", "hypothesis_template": "input parameter may reflect user input unencoded",
        "execution_bounds": {"max_requests": 3},
    },
    "SQLI": {
        "experiment_id": "exp_sqli_v1", "vulnerability_class": "SQLI",
        "action_type": "query_injection",
        "baseline": {"method": "GET", "payload": "", "description": "clean query value"},
        "candidate": {"method": "GET", "payload": "' OR '1'='1", "description": "boolean/error SQL probe"},
        "negative_control": {"method": "GET", "payload": "'", "description": "non-boolean quote control"},
        "expected_observation": {"sql_error_or_boolean_diff": True},
        "validator": "SQLI", "replay_required": True,
        "contract_version": "v1", "hypothesis_template": "query-backed input may be injectable",
        "execution_bounds": {"max_requests": 3},
    },
    "MASS_ASSIGNMENT": {
        "experiment_id": "exp_massassign_v1", "vulnerability_class": "MASS_ASSIGNMENT",
        "action_type": "field_injection",
        "baseline": {"method": "PUT", "body_fields": ["name", "email"]},
        "candidate": {"method": "PUT", "body_fields": ["name", "email", "role", "is_admin"]},
        "negative_control": {"method": "PUT", "body_fields": ["name"]},
        "expected_observation": {"protected_field_present": True},
        "validator": "MASS_ASSIGNMENT", "replay_required": True,
        "execution_bounds": {"max_requests": 3},
    },
    "INFO_DISCLOSURE": {
        "experiment_id": "exp_infodisc_v1", "vulnerability_class": "INFO_DISCLOSURE",
        "action_type": "debug_resource",
        "baseline": {"path": "/api/public"},
        "candidate": {"path": "/api/debug", "method": "GET"},
        "negative_control": {"path": "/api/health"},
        "expected_observation": {"sensitive_patterns": ["password", "secret", "token", "stack"]},
        "validator": "INFO_DISCLOSURE", "replay_required": True,
        "contract_version": "v1",
        "hypothesis_template": "debug/error/resource endpoint may expose multiple sensitive data classes",
        "test_matrix": {"baseline": "ordinary public endpoint", "candidate": "observed disclosure endpoint", "negative_control": "ordinary unrelated endpoint"},
        "execution_bounds": {"max_requests": 3},
    },
    "AUTH_BYPASS": {
        "experiment_id": "exp_authbypass_v1", "vulnerability_class": "AUTH_BYPASS",
        "action_type": "bypass_payload",
        "baseline": {"method": "GET", "auth": "none", "path": "/api/private"},
        "candidate": {"method": "GET", "auth": "bypass_header", "path": "/api/private"},
        "negative_control": {"method": "GET", "auth": "invalid_bypass", "path": "/api/private"},
        "expected_observation": {"status_diff": True},
        "validator": "AUTH_BYPASS", "replay_required": True,
        "execution_bounds": {"max_requests": 3},
    },
    # Sprint I-2 Part 4 (B12 fix): BOLA (Broken Object Level Authorization) is
    # the same comparative-access experiment class as IDOR — a foreign
    # principal attempts to read an object owned by another principal. It
    # routes to the SAME IDOR-class runner (validate_idor handles BOLA per
    # validators.py:265; the identity binding's IDOR/BOLA branch is
    # autonomous_validation_v1.py:919-936). Registered here so a BOLA
    # hypothesis routes to the fabric/AVI branch, NOT the non-fabric
    # FindingLifecycle branch.
    "BOLA": {
        "experiment_id": "exp_bola_v1", "vulnerability_class": "BOLA",
        "action_type": "differential_access",
        "baseline": {"method": "GET", "principal": "owner", "description": "owner accesses own object"},
        "candidate": {"method": "GET", "principal": "foreign", "description": "foreign principal accesses owner object"},
        "negative_control": {"method": "GET", "principal": "foreign", "resource": "denied_id", "description": "known-denied object id"},
        "expected_observation": {"status_diff": True, "body_diff": True},
        "validator": "BOLA", "replay_required": True,
        "execution_bounds": {"max_requests": 3},
    },
    # Vulnerability Arsenal Sprint A — four new families. Same contract shape as
    # the existing entries. All execution still flows through the governed
    # boundary; RACE_CONDITION carries an explicit bounded concurrency window
    # (the only entry whose candidate may execute more than 3 HTTP requests, via
    # the bounded burst executor in AVI).
    "RACE_CONDITION": {
        "experiment_id": "exp_race_condition_v1", "vulnerability_class": "RACE_CONDITION",
        "action_type": "concurrent_state_change",
        "baseline": {"method": "POST", "description": "one sequential state-changing request succeeds once"},
        "candidate": {"method": "POST", "concurrent": True, "concurrency": 5,
                      "description": "bounded burst that should only succeed once"},
        "negative_control": {"method": "POST", "concurrent": True, "concurrency": 5,
                             "description": "burst against a request the server rejects"},
        "expected_observation": {"concurrent_successes_gt": 1},
        "validator": "RACE_CONDITION", "replay_required": True,
        "execution_bounds": {"max_requests": 11, "max_concurrency": 5},
    },
    "BUSINESS_LOGIC": {
        "experiment_id": "exp_business_logic_v1", "vulnerability_class": "BUSINESS_LOGIC",
        "action_type": "value_manipulation",
        "baseline": {"method": "POST", "description": "legitimate value accepted"},
        "candidate": {"method": "POST", "description": "manipulated value (negative/zero/reused) submitted"},
        "negative_control": {"method": "POST", "description": "benign value at the same endpoint"},
        "expected_observation": {"candidate_accepts_manipulated": True, "control_clean": True},
        "validator": "BUSINESS_LOGIC", "replay_required": True,
        "execution_bounds": {"max_requests": 3},
    },
    "FILE_UPLOAD": {
        "experiment_id": "exp_file_upload_v1", "vulnerability_class": "FILE_UPLOAD",
        "action_type": "multipart_upload",
        "baseline": {"method": "POST", "description": "benign file upload"},
        "candidate": {"method": "POST", "description": "dangerous artifact upload (svg xss/traversal/mime)"},
        "negative_control": {"method": "POST", "description": "marker-free control upload"},
        "expected_observation": {"artifact_reachable": True, "impact_proven": True},
        "validator": "FILE_UPLOAD", "replay_required": True,
        "execution_bounds": {"max_requests": 3},
    },
    "JWT_MANIPULATION": {
        "experiment_id": "exp_jwt_manipulation_v1", "vulnerability_class": "JWT_MANIPULATION",
        "action_type": "token_tampering",
        "baseline": {"method": "GET", "auth": "none", "description": "protected route without credential"},
        "candidate": {"method": "GET", "auth": "tampered_jwt", "description": "tampered JWT presented"},
        "negative_control": {"method": "GET", "auth": "invalid_token", "description": "syntactically invalid token"},
        "expected_observation": {"status_diff": True},
        "validator": "JWT_MANIPULATION", "replay_required": True,
        "execution_bounds": {"max_requests": 3},
    },
    # U-7: Six fabric families
    "SSTI": {"experiment_id": "exp_ssti_v1", "vulnerability_class": "SSTI", "action_type": "template_injection", "baseline": {"method": "GET", "payload": ""}, "candidate": {"method": "GET", "payload": "{{7*7}}"}, "negative_control": {"method": "GET", "payload": "7*7"}, "expected_observation": {"candidate_eval": "49"}, "validator": "SSTI", "replay_required": True, "execution_bounds": {"max_requests": 3}},
    "LFI": {"experiment_id": "exp_lfi_v1", "vulnerability_class": "LFI", "action_type": "file_inclusion", "baseline": {"method": "GET", "payload": ""}, "candidate": {"method": "GET", "payload": "../etc/hostname"}, "negative_control": {"method": "GET", "payload": "nonexistent.txt"}, "expected_observation": {"candidate_file_content": True}, "validator": "LFI", "replay_required": True, "execution_bounds": {"max_requests": 3}},
    "PATH_TRAVERSAL": {"experiment_id": "exp_path_traversal_v1", "vulnerability_class": "PATH_TRAVERSAL", "action_type": "path_escape", "baseline": {"method": "GET", "payload": ""}, "candidate": {"method": "GET", "payload": "../etc/hostname"}, "negative_control": {"method": "GET", "payload": "normal.txt"}, "expected_observation": {"candidate_escaped_content": True}, "validator": "PATH_TRAVERSAL", "replay_required": True, "execution_bounds": {"max_requests": 3}},
    "COMMAND_INJECTION": {"experiment_id": "exp_command_injection_v1", "vulnerability_class": "COMMAND_INJECTION", "action_type": "command_execution", "baseline": {"method": "GET", "payload": ""}, "candidate": {"method": "GET", "payload": ";echo NONCE"}, "negative_control": {"method": "GET", "payload": "echo NONCE"}, "expected_observation": {"candidate_nonce_in_output": True}, "validator": "COMMAND_INJECTION", "replay_required": True, "execution_bounds": {"max_requests": 3}},
    "XXE": {"experiment_id": "exp_xxe_v1", "vulnerability_class": "XXE", "action_type": "xml_entity_injection", "baseline": {"method": "POST", "payload": "<root/>"}, "candidate": {"method": "POST", "payload": "<!ENTITY x SYSTEM 'file:///etc/hostname'>"}, "negative_control": {"method": "POST", "payload": "<r>normal</r>"}, "expected_observation": {"candidate_entity_resolved": True}, "validator": "XXE", "replay_required": True, "execution_bounds": {"max_requests": 3}},
    "RFI": {"experiment_id": "exp_rfi_v1", "vulnerability_class": "RFI", "action_type": "remote_file_inclusion", "baseline": {"method": "GET", "payload": ""}, "candidate": {"method": "GET", "payload": "http://127.0.0.1:1/rfi.txt"}, "negative_control": {"method": "GET", "payload": "local.txt"}, "expected_observation": {"candidate_fetched_content": True}, "validator": "RFI", "replay_required": True, "execution_bounds": {"max_requests": 3}},
}


# ---- PART 4: Canonical Observation Normalization ---------------------------

@dataclass
class NormalizedObservation:
    experiment_id: str
    role: Literal["baseline", "candidate", "negative_control"]
    status_code: int
    headers_fingerprint: str  # redacted, safe
    body_fingerprint: str
    body_size: int
    structured_fields: dict[str, Any] = field(default_factory=dict)
    reflected_input: bool = False
    principal_context: str | None = None
    target_resource: str | None = None
    parameter_diff: str | None = None
    timing_ms: float | None = None
    evidence_ref: str | None = None
    redacted_body: str = ""
    safe_headers: dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    request_url: str | None = None

    def digest(self) -> str:
        payload = json.dumps({
            "experiment_id": self.experiment_id, "role": self.role,
            "status_code": self.status_code, "headers_fingerprint": self.headers_fingerprint,
            "body_fingerprint": self.body_fingerprint, "body_size": self.body_size,
            "structured_fields": self.structured_fields, "reflected_input": self.reflected_input,
        }, sort_keys=True, default=str)
        return sha256_text(payload)[:16]


def normalize_observation(experiment_id: str, role: str, raw: dict[str, Any]) -> NormalizedObservation:
    """Canonical normalization. Secrets redacted BEFORE storage."""
    raw_body = str(raw.get("response_body", raw.get("body", "")))
    clean_body, _ = redact_sensitive(raw_body)
    headers = raw.get("headers", {}) or {}
    safe_headers = {
        str(k): redact_sensitive(str(v))[0]
        for k, v in headers.items()
        if str(k).lower() not in ("authorization", "cookie", "set-cookie", "x-api-key")
    }
    hfp = sha256_text(json.dumps(safe_headers, sort_keys=True))[:16]
    bfp = sha256_text(clean_body)[:16]
    # Sprint I-1, item 1.1: raw.get(key, default) only falls back to
    # `default` when the key is ABSENT. When the key is present with an
    # explicit None (e.g. a failed/blocked real HTTP call that never got
    # a response), status_code_raw below is None and int(None) raises
    # TypeError. Normalize explicit-None to 0 before int().
    status_code_raw = raw.get("status_code", raw.get("status", 0))
    if status_code_raw is None:
        status_code_raw = 0
    return NormalizedObservation(
        experiment_id=experiment_id, role=role,
        status_code=int(status_code_raw),
        headers_fingerprint=hfp, body_fingerprint=bfp, body_size=len(clean_body),
        structured_fields=raw.get("structured_fields", {}),
        reflected_input=raw.get("reflected_input", False),
        principal_context=raw.get("principal_context"),
        target_resource=raw.get("target_resource"),
        parameter_diff=raw.get("parameter_diff"),
        timing_ms=raw.get("timing_ms"),
        evidence_ref=f"obs_{experiment_id}_{role}_{bfp[:8]}",
        redacted_body=clean_body,
        safe_headers=safe_headers,
        request_url=str(raw.get("request_url") or ""),
    )


# ---- PART 3/5: Generic Experiment Runner + Validator Adapter ---------------

@dataclass
class ExperimentResult:
    experiment_id: str
    vulnerability_class: str
    hypothesis_id: str
    baseline: NormalizedObservation
    candidate: NormalizedObservation
    negative_control: NormalizedObservation
    execution_identity: str
    authorized: bool
    scope_decision: dict[str, Any]
    validator_result: ValidationResult | None = None

    def to_validator_input(self) -> dict[str, Any]:
        def _structured(observation: NormalizedObservation) -> dict[str, Any]:
            return {
                **dict(observation.structured_fields or {}),
                "_body_fingerprint": observation.body_fingerprint,
                "_body_size": observation.body_size,
            }
        return {
            "baseline": {"status_code": self.baseline.status_code,
                         "response_body": self.baseline.redacted_body,
                         "headers": {**self.baseline.safe_headers, "fp": self.baseline.headers_fingerprint},
                         "structured_fields": _structured(self.baseline),
                         "request_url": self.baseline.request_url},
            "candidate": {"status_code": self.candidate.status_code,
                          "response_body": self.candidate.redacted_body,
                          "headers": {**self.candidate.safe_headers, "fp": self.candidate.headers_fingerprint},
                          "structured_fields": _structured(self.candidate),
                          "request_url": self.candidate.request_url},
            "negative_control": {"status_code": self.negative_control.status_code,
                                 "response_body": self.negative_control.redacted_body,
                                 "headers": {**self.negative_control.safe_headers, "fp": self.negative_control.headers_fingerprint},
                                 "structured_fields": _structured(self.negative_control),
                                 "request_url": self.negative_control.request_url},
        }


class GenericExperimentRunner:
    """ONE reusable bounded execution abstraction. Delegates ALL authorization
    to ModernOrchestrator (ScopeLaw + ToolBoundary). No raw HTTP here."""

    def __init__(self, orchestrator):
        self.orch = orchestrator
        self._exec_count = 0

    def run(self, *, hypothesis_id: str, vulnerability_class: str,
            target_url: str, baseline_obs: dict, candidate_obs: dict,
            negative_control_obs: dict) -> ExperimentResult:
        """Run one bounded experiment through canonical execution path."""
        reg = EXPERIMENT_REGISTRY.get(vulnerability_class.upper())
        if not reg:
            raise ValueError(f"No experiment registered for {vulnerability_class}")
        bounds = reg["execution_bounds"]
        if self._exec_count >= bounds.get("max_requests", 3) * 10:
            raise RuntimeError("Experiment budget exhausted — fail closed")
        self._exec_count += 1

        # Authorized execution via orchestrator (ScopeLaw + ToolBoundary).
        exec_result = self.orch.run_bounded_experiment(
            candidate_id=f"c_{hypothesis_id}", hypothesis_id=hypothesis_id,
            tool_name="httpx_bounded", target_url=target_url,
        )
        authorized = exec_result.get("authorized", False)
        scope_decision = exec_result.get("scope_decision", {})

        # Normalize observations (secrets redacted).
        eid = reg["experiment_id"]
        b = normalize_observation(eid, "baseline", baseline_obs)
        c = normalize_observation(eid, "candidate", candidate_obs)
        nc = normalize_observation(eid, "negative_control", negative_control_obs)

        result = ExperimentResult(
            experiment_id=eid, vulnerability_class=vulnerability_class.upper(),
            hypothesis_id=hypothesis_id, baseline=b, candidate=c, negative_control=nc,
            execution_identity=f"exec_{eid}_{hashlib.sha256(target_url.encode()).hexdigest()[:8]}",
            authorized=authorized, scope_decision=scope_decision,
        )

        # Validator adapter: normalized → validator input → result.
        if authorized:
            vi = result.to_validator_input()
            try:
                result.validator_result = run_validator(
                    vulnerability_class, **vi)
            except Exception:
                result.validator_result = None  # fail visible, not silent confirm

        return result


__all__ = ["EXPERIMENT_REGISTRY", "NormalizedObservation", "normalize_observation",
           "ExperimentResult", "GenericExperimentRunner"]
