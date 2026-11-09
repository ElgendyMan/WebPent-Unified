"""Deterministic identity-matrix projection over sanitised observations."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit

from webpent.models.authorization_matrix import AuthorizationMatrix
from webpent.shared.authorization_matrix import build_authorization_matrix

from .models import (
    IdentityActor,
    IdentityComparison,
    IdentityMatrix,
    IdentityObservation,
    IdentityRole,
)

_ROLE_VALUES = {"anonymous", "user", "premium_user", "admin", "service_account", "unknown"}


def _text(value: Any, default: str = "") -> str:
    return str(value).strip() if value is not None and str(value).strip() else default


def _role(value: Any) -> IdentityRole:
    candidate = _text(value, "unknown").lower()
    return candidate if candidate in _ROLE_VALUES else "unknown"  # type: ignore[return-value]


def _target_key(value: Any) -> str:
    return _text(value).lower()


def _same_target(raw: Mapping[str, Any], target_id: str, engagement_id: str) -> bool:
    raw_target = raw.get("target_id") or raw.get("target_ref")
    raw_engagement = raw.get("engagement_id") or raw.get("engagement_ref")
    if raw_target is not None and _target_key(raw_target) != _target_key(target_id):
        return False
    return not (
        raw_engagement is not None
        and _target_key(raw_engagement) != _target_key(engagement_id)
    )


def _to_observation(raw: Mapping[str, Any]) -> IdentityObservation:
    identity_ref = _text(raw.get("identity_ref") or raw.get("identity"), "unknown-identity")
    return IdentityObservation(
        identity_ref=identity_ref,
        role=_role(raw.get("role")),
        object_ref=_text(raw.get("object_ref") or raw.get("object_id")) or None,
        endpoint=_text(
            raw.get("endpoint") or raw.get("resource_url") or raw.get("url"),
            "unknown://endpoint",
        ),
        method=_text(raw.get("method"), "GET"),
        ownership_relation=_text(raw.get("ownership_relation"), "unknown"),
        expected_access=_text(raw.get("expected_access"), "unknown"),
        observed_access=bool(raw.get("accessible")),
        status_code=max(0, min(999, int(raw.get("status_code", 0) or 0))),
        response_fingerprint=_text(raw.get("response_fingerprint"), "unfingerprinted"),
        evidence_refs=[str(item) for item in (raw.get("evidence_refs") or []) if item][:16],
        target_backed=bool(raw.get("target_backed")),
        redacted=True,
    )


def build_identity_matrix(
    observations: Iterable[Mapping[str, Any]],
    *,
    target_id: str,
    engagement_id: str,
    max_rows: int = 500,
    max_comparisons: int = 1000,
) -> dict[str, Any]:
    """Build an isolated identity projection from already-sanitised rows.

    The existing authorization matrix remains the source of pairwise semantics;
    this layer adds explicit identity/engagement binding and typed observations.
    It never performs requests or promotes a finding.
    """
    target_id = _text(target_id)
    engagement_id = _text(engagement_id)
    if not target_id or not engagement_id:
        raise ValueError("target_id and engagement_id are required")

    selected: list[Mapping[str, Any]] = []
    gaps: set[str] = set()
    for raw in observations:
        if not isinstance(raw, Mapping):
            gaps.add("invalid_observation_shape")
            continue
        if not _same_target(raw, target_id, engagement_id):
            gaps.add("cross_target_observation_rejected")
            continue
        if len(selected) >= max(1, min(int(max_rows), 500)):
            gaps.add("identity_matrix_row_cap_reached")
            continue
        selected.append(raw)

    typed_observations: list[IdentityObservation] = []
    actors: dict[str, IdentityActor] = {}
    for raw in selected:
        try:
            observation = _to_observation(raw)
        except (TypeError, ValueError):
            gaps.add("invalid_identity_observation")
            continue
        typed_observations.append(observation)
        actors.setdefault(
            observation.identity_ref,
            IdentityActor(
                identity_ref=observation.identity_ref,
                role=observation.role,
                is_anonymous=observation.role == "anonymous"
                or observation.identity_ref == "anonymous",
            ),
        )

    authorization = build_authorization_matrix(
        selected,
        target_url=None,
        max_rows=max_rows,
        max_comparisons=max_comparisons,
    )
    # Validate the existing projection without exposing its internals as a new
    # authority. This also makes malformed upstream data fail closed.
    AuthorizationMatrix.model_validate(authorization)
    comparisons = [
        IdentityComparison(
            left_identity_ref=str(item.get("left_identity_ref") or "unknown-identity"),
            right_identity_ref=str(item.get("right_identity_ref") or "unknown-identity"),
            object_ref=item.get("object_ref"),
            endpoint=str(item.get("endpoint") or "unknown://endpoint"),
            method=str(item.get("method") or "GET"),
            comparison_kind=item.get("comparison_kind") or "same_role",
            access_differential=bool(item.get("access_differential")),
            status_differential=bool(item.get("status_differential")),
            fingerprint_differential=bool(item.get("fingerprint_differential")),
            owner_identity_ref=item.get("owner_identity_ref"),
            evidence_refs=[str(ref) for ref in (item.get("evidence_refs") or [])][:32],
            promotion_status="candidate"
            if item.get("access_differential")
            else "needs_replay",
        )
        for item in authorization.get("comparisons", [])
        if isinstance(item, Mapping)
    ][: max(1, min(int(max_comparisons), 1000))]
    gaps.update(str(item) for item in authorization.get("coverage_gaps", []))
    if len(actors) < 2:
        gaps.add("fewer_than_two_identities_observed")
    if not any(observation.target_backed for observation in typed_observations):
        gaps.add("target_backed_observation_missing")
    if not any(urlsplit(observation.endpoint).hostname for observation in typed_observations):
        gaps.add("endpoint_host_missing")

    return IdentityMatrix(
        target_id=target_id,
        engagement_id=engagement_id,
        identities=list(actors.values()),
        observations=typed_observations,
        comparisons=comparisons,
        coverage_gaps=sorted(gaps),
    ).model_dump(mode="json")


__all__ = ["build_identity_matrix"]
