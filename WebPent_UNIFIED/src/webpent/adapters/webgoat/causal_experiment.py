"""WebGoat-local causal experiment design.

The design is intentionally non-executing. It documents the bounded
preconditions for a future authorized GET-only experiment and returns a formal
blocker when the running target cannot expose the required ownership/session
fixture. It never replays the historical B2/B2.1 bootstrap flow.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

WEBGOAT_IDOR_CASE_ID = "webgoat.idor.view_other_profile.causal-vnext"
WEBGOAT_SOURCE_REQUIREMENTS = (
    "LessonSession owner identity must be controllable independently from requester identity",
    "a disposable owner-owned profile/object fixture must be provisioned and resettable",
    (
        "GET response must expose a bounded semantic object/ownership distinction "
        "without persisting a body"
    ),
    "an independent denied/nonexistent control must be observable and differ in request identity",
)


@dataclass(frozen=True)
class WebGoatCausalExperimentDesign:
    """Machine-readable design and blocker for the redesigned IDOR experiment."""

    case_id: str
    execution_mode: str
    method: str
    owner_identity_ref: str
    requester_identity_ref: str
    owner_resource_ref: str
    candidate_resource_ref: str
    negative_control_resource_ref: str
    expected_invariant: str
    violated_invariant: str
    required_observables: tuple[str, ...]
    preconditions_ready: bool
    blocker_code: str
    blocker_reason: str
    historical_flow_reused: bool = False
    target_backed_confirmation_allowed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def webgoat_idor_causal_design() -> WebGoatCausalExperimentDesign:
    """Return the bounded experiment design without contacting WebGoat."""
    return WebGoatCausalExperimentDesign(
        case_id=WEBGOAT_IDOR_CASE_ID,
        execution_mode="design_only_until_owner_fixture_capability_exists",
        method="GET",
        owner_identity_ref="synthetic-webgoat-owner",
        requester_identity_ref="synthetic-webgoat-requester",
        owner_resource_ref="synthetic-owner-profile",
        candidate_resource_ref="synthetic-owner-profile-under-requester-session",
        negative_control_resource_ref="synthetic-independent-denied-profile",
        expected_invariant=("requester session cannot read the owner-owned profile/object"),
        violated_invariant=(
            "requester session receives the owner-owned profile/object semantic identity"
        ),
        required_observables=(
            "owner baseline proves the resource exists for the owner identity",
            "candidate uses a distinct requester identity and the same owner resource",
            (
                "candidate exposes bounded semantic resource identity, not only "
                "status/redirect/route"
            ),
            (
                "negative control is independently denied or nonexistent and has a "
                "distinct request digest"
            ),
            "snapshot restore returns the same fixture state hash",
        ),
        preconditions_ready=False,
        blocker_code="WEBGOAT_LESSON_SESSION_OWNER_FIXTURE_UNAVAILABLE",
        blocker_reason=(
            "The existing WebGoat adapter is metadata-only and the historical B2/B2.1 "
            "flow did not establish two independently controllable LessonSession "
            "ownership states with an observable resource distinction. Adding login, "
            "credentials, mutation, or a new permission is outside the approved scope; "
            "therefore no target-backed causal observation or scoring ProofBundle may be created."
        ),
    )


__all__ = [
    "WEBGOAT_IDOR_CASE_ID",
    "WEBGOAT_SOURCE_REQUIREMENTS",
    "WebGoatCausalExperimentDesign",
    "webgoat_idor_causal_design",
]
