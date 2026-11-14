"""Deterministic oracle and negative-control evaluation for proof slices.

This module evaluates already-collected, redacted observations only. It never
creates requests, starts callbacks, or decides authorization. The executor and
scope gates remain the only components allowed to perform actions.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import redact_sensitive, sha256_text


class OracleFamily(str, Enum):
    """Supported proof families with explicit negative-control semantics."""

    IDOR = "idor"
    STORED_XSS = "stored_xss"
    SSRF = "ssrf"
    CSV_SQLI = "csv_sqli"
    REQUEST_SMUGGLING = "request_smuggling"
    CLOUD_STORAGE_EXPOSURE = "cloud_storage_exposure"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    JWT_KEY_CONFUSION = "jwt_key_confusion"


class CausalDecision(str, Enum):
    """Closed set of decisions emitted by the vNext causal oracle."""

    CONFIRMED = "CONFIRMED"
    CLEAN = "CLEAN"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"


_RESTRICTED_ONLY_SIGNAL_KEYS = frozenset(
    {
        "status",
        "status_code",
        "http_status",
        "redirect",
        "redirect_location",
        "route",
        "route_exists",
        "source",
        "source_presence",
        "source_code_present",
    }
)


class CausalObservation(BaseModel):
    """Typed, redacted observation used by the causal experiment contract.

    ``semantic_fingerprint`` and invariant signals are intentionally separate
    from transport metadata. A status code, redirect, route, or source marker
    can be retained as context, but cannot be the only oracle signal.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    observation_ref: str = Field(min_length=1, max_length=240)
    role: Literal["baseline", "candidate", "negative_control"]
    semantic_fingerprint: str = Field(min_length=1, max_length=240)
    request_digest: str = Field(min_length=1, max_length=71)
    response_digest: str = Field(min_length=1, max_length=71)
    signals: dict[str, Any] = Field(default_factory=dict, max_length=32)
    target_backed: bool = False
    evidence_origin: Literal["offline_fixture", "target_runtime"] = "offline_fixture"

    @field_validator("observation_ref", "semantic_fingerprint", mode="before")
    @classmethod
    def _redact_text(cls, value: Any) -> str:
        clean, _ = redact_sensitive(str(value or ""))
        return clean

    @field_validator("request_digest", "response_digest", mode="before")
    @classmethod
    def _validate_digest(cls, value: Any) -> str:
        text = str(value or "")
        if not text.startswith("sha256:") or len(text) != 71:
            raise ValueError("observation digest must be sha256:<64 hex characters>")
        int(text[7:], 16)
        return text.lower()

    @field_validator("signals", mode="before")
    @classmethod
    def _redact_signals(cls, value: Any) -> dict[str, Any]:
        clean, _ = redact_sensitive(value if isinstance(value, dict) else {})
        return clean

    @property
    def meaningful_signal_keys(self) -> tuple[str, ...]:
        """Return non-transport signal keys available to the oracle."""
        return tuple(
            sorted(
                key
                for key in self.signals
                if str(key).lower() not in _RESTRICTED_ONLY_SIGNAL_KEYS
            )
        )

    @property
    def has_meaningful_signal(self) -> bool:
        return bool(self.meaningful_signal_keys)

    @property
    def is_target_runtime(self) -> bool:
        """Return whether this observation is explicitly target-runtime evidence."""
        return self.evidence_origin == "target_runtime"


class CausalOracleContract(BaseModel):
    """Three-way causal contract: baseline, candidate, and independent control."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    family: OracleFamily
    baseline: CausalObservation
    candidate: CausalObservation
    negative_control: CausalObservation
    expected_invariant: str = Field(min_length=1, max_length=500)
    violated_invariant: str = Field(min_length=1, max_length=500)

    @field_validator("expected_invariant", "violated_invariant", mode="before")
    @classmethod
    def _redact_invariant(cls, value: Any) -> str:
        clean, _ = redact_sensitive(str(value or ""))
        return clean


class CausalOracleResult(BaseModel):
    """Deterministic, typed decision plus a redacted invariant analysis."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    family: OracleFamily
    decision: CausalDecision
    baseline: CausalObservation
    candidate: CausalObservation
    negative_control: CausalObservation
    expected_invariant: str
    violated_invariant: str
    invariant_analysis: dict[str, Any] = Field(default_factory=dict, max_length=32)
    missing: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    reason: str = Field(default="", max_length=300)

    @field_validator("expected_invariant", "violated_invariant", "reason", mode="before")
    @classmethod
    def _redact_result_text(cls, value: Any) -> str:
        clean, _ = redact_sensitive(str(value or ""))
        return clean

    @field_validator("invariant_analysis", mode="before")
    @classmethod
    def _redact_analysis(cls, value: Any) -> dict[str, Any]:
        clean, _ = redact_sensitive(value if isinstance(value, dict) else {})
        return clean

    @property
    def causal_signal(self) -> bool:
        return self.decision == CausalDecision.CONFIRMED

    @property
    def negative_control_observed(self) -> bool:
        return bool(self.invariant_analysis.get("negative_control_invariant_holds"))

    @property
    def evidence_complete(self) -> bool:
        return not self.missing

    @property
    def reviewable(self) -> bool:
        return self.decision == CausalDecision.CONFIRMED and self.evidence_complete


class OracleResult(BaseModel):
    """Legacy redacted deterministic result consumed by existing callers."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    family: OracleFamily
    causal_signal: bool = False
    negative_control_observed: bool = False
    evidence_complete: bool = False
    status: str = Field(default="inconclusive", max_length=32)
    missing: list[str] = Field(default_factory=list, max_length=8)
    reason: str = Field(default="", max_length=300)

    @property
    def reviewable(self) -> bool:
        return bool(
            self.causal_signal
            and self.negative_control_observed
            and self.evidence_complete
        )


class NegativeControlEngine:
    """Evaluate only the bounded negative-control portion of an observation."""

    @staticmethod
    def observed(family: OracleFamily | str, evidence: Mapping[str, Any]) -> bool:
        value = family.value if isinstance(family, OracleFamily) else str(family)
        if value == OracleFamily.IDOR.value:
            return bool(evidence.get("foreign_denied") or evidence.get("control_denied"))
        if value == OracleFamily.STORED_XSS.value:
            return bool(
                evidence.get("encoded_control_safe")
                and evidence.get("literal_control_safe")
            )
        if value == OracleFamily.SSRF.value:
            return bool(
                evidence.get("negative_callback_absent")
                or evidence.get("control_callback_absent")
            )
        if value == OracleFamily.CSV_SQLI.value:
            return bool(
                evidence.get("negative_control_accepted")
                or evidence.get("negative_control_rejected")
            )
        if value == OracleFamily.REQUEST_SMUGGLING.value:
            return bool(
                evidence.get("control_request_normalized")
                or evidence.get("control_request_rejected")
            )
        if value == OracleFamily.CLOUD_STORAGE_EXPOSURE.value:
            return bool(
                evidence.get("private_object_denied")
                or evidence.get("control_object_denied")
            )
        if value == OracleFamily.SUBDOMAIN_TAKEOVER.value:
            return bool(
                evidence.get("owned_alias_not_claimable")
                or evidence.get("control_alias_not_claimable")
            )
        if value == OracleFamily.JWT_KEY_CONFUSION.value:
            return bool(
                evidence.get("control_token_rejected")
                or evidence.get("symmetric_control_rejected")
            )
        return False


class OracleEngine:
    """Evaluate typed, redacted observations without performing active actions."""

    @staticmethod
    def evaluate_experiment(
        contract: CausalOracleContract | Mapping[str, Any],
    ) -> CausalOracleResult:
        """Evaluate the three-way contract deterministically.

        Confirmation requires an invariant-preserving owner baseline and
        independent negative control, a candidate invariant violation, and a
        semantic candidate delta from both controls. Transport-only or
        source-only differences result in ``BLOCKED`` rather than promotion.
        """
        parsed = (
            contract
            if isinstance(contract, CausalOracleContract)
            else CausalOracleContract.model_validate(contract)
        )
        observations = (parsed.baseline, parsed.candidate, parsed.negative_control)
        missing: list[str] = []
        if len({item.observation_ref for item in observations}) != 3:
            missing.append("observation_refs_not_independent")
        if parsed.candidate.request_digest == parsed.negative_control.request_digest:
            missing.append("negative_control_request_not_independent")
        for item in observations:
            if not item.has_meaningful_signal:
                missing.append(f"{item.role}_semantic_signal_missing")

        baseline_holds = bool(parsed.baseline.signals.get("invariant_holds"))
        candidate_holds = bool(parsed.candidate.signals.get("invariant_holds"))
        candidate_violated = bool(parsed.candidate.signals.get("invariant_violated"))
        control_holds = bool(parsed.negative_control.signals.get("invariant_holds"))

        baseline_signature = _semantic_signature(parsed.baseline)
        candidate_signature = _semantic_signature(parsed.candidate)
        control_signature = _semantic_signature(parsed.negative_control)
        candidate_differs_from_baseline = candidate_signature != baseline_signature
        candidate_differs_from_control = candidate_signature != control_signature

        analysis = {
            "baseline_invariant_holds": baseline_holds,
            "candidate_invariant_holds": candidate_holds,
            "candidate_invariant_violated": candidate_violated,
            "negative_control_invariant_holds": control_holds,
            "candidate_differs_from_baseline": candidate_differs_from_baseline,
            "candidate_differs_from_negative_control": candidate_differs_from_control,
            "transport_only_signals_rejected": True,
            "semantic_signal_keys": {
                item.role: list(item.meaningful_signal_keys) for item in observations
            },
        }

        if missing:
            decision = CausalDecision.BLOCKED
            reason = "causal_contract_structurally_blocked"
        elif (
            baseline_holds
            and control_holds
            and candidate_violated
            and candidate_differs_from_baseline
            and candidate_differs_from_control
        ):
            decision = CausalDecision.CONFIRMED
            reason = "candidate_semantically_differs_and_violates_invariant"
        elif (
            baseline_holds
            and control_holds
            and candidate_holds
            and candidate_signature in (control_signature, baseline_signature)
        ):
            decision = CausalDecision.CLEAN
            reason = "candidate_preserves_invariant_with_control_consistent_semantics"
        else:
            decision = CausalDecision.INCONCLUSIVE
            reason = "causal_predicate_not_satisfied"

        return CausalOracleResult(
            family=parsed.family,
            decision=decision,
            baseline=parsed.baseline,
            candidate=parsed.candidate,
            negative_control=parsed.negative_control,
            expected_invariant=parsed.expected_invariant,
            violated_invariant=parsed.violated_invariant,
            invariant_analysis=analysis,
            missing=tuple(dict.fromkeys(missing)),
            reason=reason,
        )

    @staticmethod
    def evaluate(
        family: OracleFamily | str,
        evidence: Mapping[str, Any] | None,
    ) -> OracleResult:
        """Backward-compatible legacy evaluator.

        New code should use :meth:`evaluate_experiment`; this method remains
        available so existing adapters and historical tests keep their prior
        ``reviewable``/``inconclusive`` semantics.
        """
        evidence = evidence if isinstance(evidence, Mapping) else {}
        parsed = family if isinstance(family, OracleFamily) else OracleFamily(str(family))
        missing: list[str] = []
        causal = False

        if parsed is OracleFamily.IDOR:
            causal = bool(
                evidence.get("owner_accessible")
                and evidence.get("foreign_accessible")
            )
            if not evidence.get("owner_accessible"):
                missing.append("owner_baseline")
            if not evidence.get("foreign_accessible"):
                missing.append("foreign_access_observation")
        elif parsed is OracleFamily.STORED_XSS:
            causal = bool(
                evidence.get("execution_marker")
                and evidence.get("fresh_session_replay")
            )
            if not evidence.get("execution_marker"):
                missing.append("browser_execution_marker")
            if not evidence.get("fresh_session_replay"):
                missing.append("fresh_session_replay")
        elif parsed is OracleFamily.SSRF:
            causal = bool(
                evidence.get("callback_received")
                and evidence.get("callback_correlated")
            )
            if not evidence.get("callback_received"):
                missing.append("oob_callback")
            if not evidence.get("callback_correlated"):
                missing.append("callback_correlation")
        elif parsed is OracleFamily.CSV_SQLI:
            causal = bool(
                evidence.get("differential_observed")
                and (
                    evidence.get("sql_error_signature")
                    or evidence.get("timing_differential")
                    or evidence.get("data_flow_effect")
                )
            )
            if not evidence.get("differential_observed"):
                missing.append("controlled_differential")
            if not (
                evidence.get("sql_error_signature")
                or evidence.get("timing_differential")
                or evidence.get("data_flow_effect")
            ):
                missing.append("causal_data_or_sql_signal")
        elif parsed is OracleFamily.REQUEST_SMUGGLING:
            causal = bool(
                evidence.get("parser_desync_observed")
                and evidence.get("smuggled_request_observed")
            )
            if not evidence.get("parser_desync_observed"):
                missing.append("parser_desync_observation")
            if not evidence.get("smuggled_request_observed"):
                missing.append("smuggled_request_observation")
        elif parsed is OracleFamily.CLOUD_STORAGE_EXPOSURE:
            causal = bool(
                evidence.get("unauthenticated_object_read")
                and evidence.get("sensitive_object_observed")
            )
            if not evidence.get("unauthenticated_object_read"):
                missing.append("unauthenticated_object_read")
            if not evidence.get("sensitive_object_observed"):
                missing.append("sensitive_object_observation")
        elif parsed is OracleFamily.SUBDOMAIN_TAKEOVER:
            causal = bool(
                evidence.get("dangling_alias_observed")
                and evidence.get("service_claimable_observed")
            )
            if not evidence.get("dangling_alias_observed"):
                missing.append("dangling_alias_observation")
            if not evidence.get("service_claimable_observed"):
                missing.append("service_claimability_observation")
        elif parsed is OracleFamily.JWT_KEY_CONFUSION:
            causal = bool(
                evidence.get("forged_token_accepted")
                and evidence.get("algorithm_substitution_observed")
            )
            if not evidence.get("forged_token_accepted"):
                missing.append("forged_token_acceptance")
            if not evidence.get("algorithm_substitution_observed"):
                missing.append("algorithm_substitution_observation")

        negative = NegativeControlEngine.observed(parsed, evidence)
        if not negative:
            missing.append("negative_control")
        complete = not missing
        status = "reviewable" if causal and negative and complete else "inconclusive"
        reason = (
            "causal_signal_and_negative_control_observed"
            if status == "reviewable"
            else "proof_requirements_missing"
        )
        return OracleResult(
            family=parsed,
            causal_signal=causal,
            negative_control_observed=negative,
            evidence_complete=complete,
            status=status,
            missing=list(dict.fromkeys(missing)),
            reason=reason,
        )


def _semantic_signature(observation: CausalObservation) -> str:
    """Create a deterministic signature from semantic fields only."""
    semantic_signals = {
        key: observation.signals[key]
        for key in observation.meaningful_signal_keys
        if key not in {"invariant_holds", "invariant_violated"}
    }
    return sha256_text(
        {
            "semantic_fingerprint": observation.semantic_fingerprint,
            "signals": semantic_signals,
        }
    )


__all__ = [
    "CausalDecision",
    "CausalObservation",
    "CausalOracleContract",
    "CausalOracleResult",
    "NegativeControlEngine",
    "OracleEngine",
    "OracleFamily",
    "OracleResult",
]
