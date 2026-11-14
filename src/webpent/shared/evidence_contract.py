"""Generic, vulnerability-agnostic evidence contracts.

A contract describes *what kind of proof* a hypothesis needs, not which
vulnerability enum should be routed.  The evaluator consumes normalized,
redacted evidence produced by replay/OOB adapters and never executes a
request itself.  Execution remains behind the existing scope, approval, and
risk gates.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class EvidencePrimitive(str, Enum):
    """Small closed vocabulary of reusable proof primitives."""

    DIFFERENTIAL_RESPONSE = "differential_response"
    OOB_CALLBACK = "oob_callback"
    TIMING_DIFFERENTIAL = "timing_differential"
    ERROR_SIGNATURE_MATCH = "error_signature_match"
    OWNER_FOREIGN_ACCESS = "owner_foreign_access"


class EvidenceRequirement(BaseModel):
    """One required proof primitive and its bounded evaluation parameters."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    primitive: EvidencePrimitive
    min_delta: float = Field(default=0.05, ge=0.0, le=1.0)
    min_delta_ms: int = Field(default=250, ge=0, le=60_000)
    signature: str | None = Field(default=None, max_length=200)
    rationale: str = Field(default="", max_length=500)


class EvidenceContract(BaseModel):
    """Proof contract attached to a hypothesis/finding.

    ``all_of`` is intentionally bounded.  A contract is advisory metadata for
    the validator, never an authorization to execute a tool or to expand
    scope.  Unknown/invalid contracts evaluate to unsatisfied.
    """

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    all_of: list[EvidenceRequirement] = Field(default_factory=list, max_length=4)
    provenance: list[str] = Field(default_factory=list, max_length=8)
    rationale: str = Field(default="", max_length=500)

    @classmethod
    def from_evidence_needed(
        cls,
        evidence_needed: list[str] | None,
        *,
        provenance: list[str] | None = None,
        rationale: str = "",
    ) -> EvidenceContract:
        """Translate legacy evidence-needed labels into generic primitives."""
        requirements: list[EvidenceRequirement] = []
        labels = [str(item).lower() for item in (evidence_needed or [])]
        for label in labels:
            primitive: EvidencePrimitive | None = None
            if "differential" in label or "response comparison" in label:
                primitive = EvidencePrimitive.DIFFERENTIAL_RESPONSE
            elif "oob" in label or "callback" in label:
                primitive = EvidencePrimitive.OOB_CALLBACK
            elif "timing" in label or "delay" in label:
                primitive = EvidencePrimitive.TIMING_DIFFERENTIAL
            elif ("owner" in label and "foreign" in label) or "idor" in label:
                primitive = EvidencePrimitive.OWNER_FOREIGN_ACCESS
            elif "error" in label or "signature" in label:
                primitive = EvidencePrimitive.ERROR_SIGNATURE_MATCH
            if primitive and primitive not in {r.primitive for r in requirements}:
                requirements.append(EvidenceRequirement(primitive=primitive))
        return cls(
            all_of=requirements,
            provenance=list(provenance or [])[:8],
            rationale=rationale[:500],
        )


def coerce_contract(value: Any, *, evidence_needed: list[str] | None = None) -> EvidenceContract:
    """Coerce checkpoint/legacy values into a safe contract.

    Invalid user/LLM-shaped values fail closed to a contract generated from
    the legacy ``evidence_needed`` list, or to an empty contract.
    """
    if isinstance(value, EvidenceContract):
        return value
    if isinstance(value, dict):
        try:
            return EvidenceContract.model_validate(value)
        except Exception:
            # Falls through to the legacy evidence_needed-derived contract
            # below (unchanged behavior) — logged so a malformed contract
            # dict silently losing its structured requirements is visible.
            logger.warning(
                "coerce_contract: malformed contract dict, falling back to "
                "evidence_needed-derived contract",
                exc_info=True,
            )
    return EvidenceContract.from_evidence_needed(evidence_needed)


def _response_delta(baseline: dict[str, Any], probe: dict[str, Any]) -> float:
    """Return a bounded normalized response difference score."""
    if not isinstance(baseline, dict) or not isinstance(probe, dict):
        return 0.0
    if baseline.get("status_code") != probe.get("status_code"):
        return 1.0
    if baseline.get("body_digest") and probe.get("body_digest"):
        return 0.0 if baseline["body_digest"] == probe["body_digest"] else 1.0
    try:
        left = int(baseline.get("body_length", 0))
        right = int(probe.get("body_length", 0))
        scale = max(1, left, right)
        return min(1.0, abs(right - left) / scale)
    except (TypeError, ValueError):
        return 0.0


def evaluate_contract(
    contract: EvidenceContract | dict[str, Any] | None,
    evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    """Evaluate a normalized evidence record without executing anything."""
    try:
        parsed = coerce_contract(contract)
    except Exception:
        return {"satisfied": False, "results": [], "reason": "invalid_contract"}
    evidence = evidence if isinstance(evidence, dict) else {}
    results: list[dict[str, Any]] = []
    for requirement in parsed.all_of:
        primitive = (
            requirement.primitive.value
            if hasattr(requirement.primitive, "value")
            else str(requirement.primitive)
        )
        satisfied = False
        observed: Any = None
        if primitive == EvidencePrimitive.DIFFERENTIAL_RESPONSE.value:
            observed = _response_delta(evidence.get("baseline", {}), evidence.get("probe", {}))
            satisfied = float(observed) >= requirement.min_delta
        elif primitive == EvidencePrimitive.OOB_CALLBACK.value:
            observed = bool(evidence.get("callback_received") or evidence.get("callbacks"))
            satisfied = bool(observed)
        elif primitive == EvidencePrimitive.TIMING_DIFFERENTIAL.value:
            try:
                observed = abs(
                    float(evidence.get("probe_elapsed_ms", 0))
                    - float(evidence.get("baseline_elapsed_ms", 0))
                )
                satisfied = observed >= requirement.min_delta_ms
            except (TypeError, ValueError):
                observed = 0.0
        elif primitive == EvidencePrimitive.ERROR_SIGNATURE_MATCH.value:
            observed = evidence.get("matched_signature") or evidence.get("error_signature")
            expected = requirement.signature
            satisfied = bool(observed) and (
                not expected or str(expected).lower() in str(observed).lower()
            )
        elif primitive == EvidencePrimitive.OWNER_FOREIGN_ACCESS.value:
            owner = evidence.get("owner")
            foreign = evidence.get("foreign")
            observed = {
                "owner_accessible": bool(isinstance(owner, dict) and owner.get("accessible")),
                "foreign_accessible": bool(isinstance(foreign, dict) and foreign.get("accessible")),
            }
            satisfied = bool(observed["owner_accessible"] and observed["foreign_accessible"])
        results.append({"primitive": primitive, "satisfied": satisfied, "observed": observed})
    primitives_satisfied = bool(parsed.all_of) and all(item["satisfied"] for item in results)
    causal_signal = bool(evidence.get("causal_signal"))
    negative_control_complete = bool(evidence.get("negative_control_complete"))
    proof_bundle_sealed = bool(evidence.get("proof_bundle_sealed"))
    proof_posture = {
        "causal_signal": causal_signal,
        "negative_control_complete": negative_control_complete,
        "proof_bundle_sealed": proof_bundle_sealed,
    }
    proof_ready = all(proof_posture.values())
    overall = primitives_satisfied and proof_ready
    if not primitives_satisfied:
        reason = "required_primitive_missing"
    elif not proof_ready:
        reason = "proof_posture_incomplete"
    else:
        reason = "all_required_primitives_and_proof_posture_satisfied"
    return {
        "satisfied": overall,
        "results": results,
        "proof_posture": proof_posture,
        "reason": reason,
        "provenance": list(parsed.provenance),
    }


def contract_required(value: Any) -> bool:
    """Return whether a value contains at least one proof requirement."""
    try:
        return bool(coerce_contract(value).all_of)
    except Exception:
        # Fail-open to "no contract required" — the caller then falls back to
        # legacy class-specific dispatch rather than this generic gate, so
        # this is not a silent confirmation; still logged for visibility.
        logger.warning(
            "contract_required: coercion failed, treating as not required", exc_info=True
        )
        return False


__all__ = [
    "EvidenceContract",
    "EvidencePrimitive",
    "EvidenceRequirement",
    "coerce_contract",
    "contract_required",
    "evaluate_contract",
]
