"""Non-promoting invariant checks for observed workflow transitions."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.workflows import WorkflowObservation


class InvariantResult(BaseModel):
    """Review output; a violated invariant is only a candidate signal."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    target_id: str = Field(..., min_length=1, max_length=200)
    engagement_id: str = Field(..., min_length=1, max_length=200)
    observation_fingerprint: str = Field(..., min_length=8, max_length=128)
    invariant: str = Field(..., min_length=1, max_length=200)
    status: str = "candidate_violation"
    reason: str = Field(..., min_length=1, max_length=300)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    required_validation: list[str] = Field(
        default_factory=lambda: [
            "target_backed_causal_signal",
            "independent_negative_control",
            "sealed_replayable_proof_bundle",
        ],
        max_length=8,
    )


class InvariantChecker:
    """Check explicit, conservative workflow invariants without network I/O."""

    def check(
        self,
        observations: Iterable[WorkflowObservation],
        *,
        target_id: str,
        engagement_id: str,
    ) -> list[InvariantResult]:
        target_id = target_id.strip()
        engagement_id = engagement_id.strip()
        if not target_id or not engagement_id:
            raise ValueError("target_and_engagement_context_required")
        results: list[InvariantResult] = []
        seen: set[tuple[str, str]] = set()
        for observation in observations:
            violations: list[tuple[str, str]] = []
            if (
                observation.destructive
                and observation.from_state != "unknown"
                and observation.from_state == observation.to_state
            ):
                violations.append(
                    (
                        "state_must_progress_or_reject_replay",
                        "a destructive operation reports the same source and target state",
                    )
                )
            if observation.authorization_boundary in {"cross_identity", "role_scoped"} and not (
                observation.identity_ref or observation.identity_context
            ):
                violations.append(
                    (
                        "authorization_context_must_be_present",
                        "a role or cross-identity transition lacks identity context",
                    )
                )
            if observation.scope_decision == "denied":
                violations.append(
                    (
                        "out_of_scope_transition_must_not_be_processed",
                        "the observation was explicitly denied by scope policy",
                    )
                )
            for invariant, reason in violations:
                key = (observation.fingerprint, invariant)
                if key in seen:
                    continue
                seen.add(key)
                results.append(
                    InvariantResult(
                        target_id=target_id,
                        engagement_id=engagement_id,
                        observation_fingerprint=observation.fingerprint,
                        invariant=invariant,
                        reason=reason,
                        evidence_refs=observation.evidence_refs,
                    )
                )
        return results[:256]


__all__ = ["InvariantChecker", "InvariantResult"]
