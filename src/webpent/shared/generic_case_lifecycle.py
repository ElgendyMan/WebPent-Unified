"""Target-neutral case lifecycle helpers.

This module adapts the existing strict replay verifier to the generic case
contract. It never performs I/O, never accepts raw evidence as case metadata,
and never promotes a case unless the verifier returned a sealed, replayable
ProofBundle.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from webpent.models.proof_bundle import proof_bundle_promotion_ready
from webpent.shared.generic_web_contracts import CaseResult
from webpent.shared.verifier import VerificationResult

_SAFE_METADATA_KEYS = frozenset(
    {
        "target_classification",
        "target_backed",
        "negative_control_independent",
        "proof_bundle_sealed",
        "replay_verified",
        "validator_id",
        "validator_version",
        "cleanup_status",
    }
)


def _bounded_refs(value: Any, *, limit: int = 20) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        return ()
    refs: list[str] = []
    for item in value:
        text = str(item).strip()
        if not text or len(text) > 240 or text in refs:
            continue
        refs.append(text)
        if len(refs) >= limit:
            break
    return tuple(refs)


def _safe_metadata(evidence: Mapping[str, Any], extra: Mapping[str, Any] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for source in (evidence, extra or {}):
        for key, value in source.items():
            name = str(key).strip()
            if name not in _SAFE_METADATA_KEYS or len(result) >= 20:
                continue
            if isinstance(value, (dict, list, tuple, set)):
                continue
            result[name] = str(value)[:240]
    return result


def case_result_from_verification(
    case_id: str,
    verification: VerificationResult,
    *,
    observation_refs: Sequence[str] = (),
    metadata: Mapping[str, Any] | None = None,
) -> CaseResult:
    """Convert one verifier pass into a generic, proof-aware case result.

    A passed verifier is still checked locally. The result is ``confirmed``
    only when the attached bundle is sealed, structurally promotion-ready, and
    its seal verifies. Any missing or invalid proof becomes ``blocked`` rather
    than an inferred finding.
    """
    if not isinstance(verification, VerificationResult):
        raise TypeError("verification_result_required")

    evidence = verification.evidence if isinstance(verification.evidence, Mapping) else {}
    refs = _bounded_refs(observation_refs)
    if not refs:
        refs = _bounded_refs(evidence.get("evidence_refs", ()))
    bundle = verification.proof_bundle
    proof_ready = bool(
        verification.passed
        and bundle is not None
        and proof_bundle_promotion_ready(bundle)
        and bundle.verify_seal()
    )
    if proof_ready:
        status = "confirmed"
        reason = "verified_replay"
        proof_ref = bundle.bundle_id
        negative_ref = next(
            (ref for ref in refs if "negative_control" in ref),
            None,
        )
    else:
        guard = evidence.get("promotion_guard", {})
        status = "blocked" if guard.get("status") == "blocked" else "inconclusive"
        reason = str(verification.reason or "verification_not_promotable")[:240]
        proof_ref = None
        negative_ref = None

    safe = _safe_metadata(evidence, metadata)
    if proof_ready:
        safe.update({"proof_bundle_sealed": "True", "replay_verified": "True"})
    return CaseResult(
        case_id=str(case_id).strip(),
        status=status,
        reason=reason,
        observation_refs=refs,
        negative_control_ref=negative_ref,
        proof_bundle_ref=proof_ref,
        metadata=dict(list(safe.items())[:20]),
    )


__all__ = ["case_result_from_verification"]
