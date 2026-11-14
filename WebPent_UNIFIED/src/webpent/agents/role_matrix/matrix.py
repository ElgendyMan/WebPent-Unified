# src/webpent/agents/role_matrix/matrix.py
"""Deterministic cross-role authorization matrix (PROPOSALS_ULTIMATE_V2
§4, 2026-10-30).

For every (subject role, other role's resource) pair the matrix runs the
three-probe differential that ``bac_identity_tester``'s classifier
expects — the resource's OWN session, the subject's session, and an
anonymous negative control — and feeds the rows to
``assess_access_control`` / ``build_relational_evidence`` instead of
reinventing classification. This module is the execution layer on top of
the existing BAC machinery.

Breach semantics (differential, workflow-fuzzing style): a subject's 2xx
only counts as access when its response fingerprint DIFFERS from the
anonymous negative control's fingerprint, so a resource that is simply
public for everyone is not reported as an IDOR.

Fail-closed rules: a resource whose owner has no VERIFIED session aborts
the build; exceeding ``max_pairs`` aborts the build; a failed probe is a
recorded skip, never a silent confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence

from webpent.shared.bac_identity_tester import (
    assess_access_control,
    build_relational_evidence,
    extract_object_id,
    profile_owns_resource,
    response_fingerprint,
)

from .sessions import RoleSession

__all__ = [
    "MatrixPair",
    "MatrixResource",
    "RoleMatrixError",
    "RoleMatrixResult",
    "build_role_matrix",
    "run_role_matrix",
]

DEFAULT_MAX_PAIRS = 200

# fetcher(url, cookies, headers) -> (status_code, content) | None
Fetcher = Callable[[str, Mapping[str, str], Mapping[str, str]], "tuple[int, Any] | None"]


class RoleMatrixError(ValueError):
    """Raised when the matrix cannot be built fail-closed."""


@dataclass(frozen=True)
class MatrixResource:
    """One resource with an explicit owner role (ownership provenance)."""

    url: str
    owner_role: str
    object_id: str | None = None

    @classmethod
    def from_url(cls, url: str, owner_role: str) -> "MatrixResource":
        return cls(url=str(url), owner_role=str(owner_role),
                   object_id=extract_object_id(str(url)))


@dataclass(frozen=True)
class MatrixPair:
    subject_role: str
    resource: MatrixResource


@dataclass(frozen=True)
class RoleMatrixResult:
    """Verdicts and evidence over the executed matrix."""

    verdicts: "tuple[dict[str, Any], ...]"
    skips: "tuple[dict[str, Any], ...]"
    confirmed: int
    needs_review: int
    refuted: int


def build_role_matrix(
    resources: Iterable[MatrixResource],
    sessions: Mapping[str, RoleSession],
    *,
    max_pairs: int = DEFAULT_MAX_PAIRS,
) -> list[MatrixPair]:
    """Every subject-role x foreign-owned-resource pair, deterministically.

    Fails closed when any resource owner lacks a verified session, when a
    subject role is unknown, or when the pair count exceeds ``max_pairs``.
    """
    if max_pairs < 1:
        raise RoleMatrixError("role_matrix_budget_must_be_positive")
    resource_list = list(resources)
    for resource in resource_list:
        owner = sessions.get(resource.owner_role)
        if owner is None or not owner.verified:
            raise RoleMatrixError(
                f"role_matrix_owner_session_missing_or_unverified:{resource.owner_role}"
            )
    pairs: list[MatrixPair] = []
    for role in sorted(sessions):
        session = sessions[role]
        if not session.verified:
            raise RoleMatrixError(f"role_matrix_subject_session_unverified:{role}")
        for resource in sorted(resource_list, key=lambda r: (r.url, r.owner_role)):
            if resource.owner_role == role:
                continue
            if profile_owns_resource(
                session.profile, resource.url, resource.object_id
            ):
                continue  # subject already owns it; not a cross-role probe
            pairs.append(MatrixPair(subject_role=role, resource=resource))
            if len(pairs) > max_pairs:
                raise RoleMatrixError("role_matrix_budget_exceeded")
    return pairs


def _row(
    identity: str, resource: MatrixResource, probe: "tuple[int, Any] | None",
    *, anonymous_fingerprint: str | None,
) -> dict[str, Any]:
    if probe is None:
        return {
            "identity": identity,
            "url": resource.url,
            "accessible": False,
            "status_code": 0,
            "response_fingerprint": None,
            "probe_failed": True,
        }
    status, content = probe
    fingerprint = response_fingerprint(status, content)
    accessible = 200 <= status < 300
    if identity != "anonymous" and anonymous_fingerprint is not None:
        # differential: identical-to-anonymous 2xx is a public resource,
        # not cross-role access
        accessible = accessible and fingerprint != anonymous_fingerprint
    return {
        "identity": identity,
        "url": resource.url,
        "accessible": accessible,
        "status_code": status,
        "response_fingerprint": fingerprint,
    }


def run_role_matrix(
    pairs: Sequence[MatrixPair],
    sessions: Mapping[str, RoleSession],
    *,
    fetcher: Fetcher,
) -> RoleMatrixResult:
    """Execute the three-probe differential per pair and classify it."""
    verdicts: list[dict[str, Any]] = []
    skips: list[dict[str, Any]] = []
    confirmed = needs_review = refuted = 0
    for pair in pairs:
        resource = pair.resource
        owner = sessions.get(resource.owner_role)
        subject = sessions.get(pair.subject_role)
        if owner is None or subject is None:
            skips.append({
                "subject_role": pair.subject_role,
                "url": resource.url,
                "reason": "session_missing",
            })
            continue
        anonymous = fetcher(resource.url, {}, {})
        anonymous_fp = (
            response_fingerprint(anonymous[0], anonymous[1]) if anonymous else None
        )
        owner_probe = fetcher(
            resource.url, owner.cookies, owner.headers
        )
        subject_probe = fetcher(
            resource.url, subject.cookies, subject.headers
        )
        observations = [
            _row(resource.owner_role, resource, owner_probe,
                 anonymous_fingerprint=anonymous_fp),
            _row(pair.subject_role, resource, subject_probe,
                 anonymous_fingerprint=anonymous_fp),
            _row("anonymous", resource, anonymous, anonymous_fingerprint=None),
        ]
        if any(row.get("probe_failed") for row in observations):
            skips.append({
                "subject_role": pair.subject_role,
                "url": resource.url,
                "reason": "probe_failed",
            })
            continue
        owner_identity = resource.owner_role
        verdict = assess_access_control(
            observations, owner_identity=owner_identity
        )
        edges = build_relational_evidence(
            observations, owner_identity=owner_identity,
            object_id=resource.object_id,
        )
        status = str(verdict.get("status") or "inconclusive")
        if status == "confirmed":
            confirmed += 1
        elif status == "needs_review":
            needs_review += 1
        else:
            refuted += 1
        verdicts.append({
            "subject_role": pair.subject_role,
            "owner_role": owner_identity,
            "url": resource.url,
            "object_id": resource.object_id,
            "status": status,
            "confidence_level": verdict.get("confidence_level"),
            "reason": verdict.get("reason"),
            "observations": observations,
            "relational_edges": edges,
        })
    return RoleMatrixResult(
        verdicts=tuple(verdicts),
        skips=tuple(skips),
        confirmed=confirmed,
        needs_review=needs_review,
        refuted=refuted,
    )
