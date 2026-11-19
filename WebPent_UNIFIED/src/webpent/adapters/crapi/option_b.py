"""crAPI-specific Option B object-access profiles.

These profiles are source-backed candidates, not confirmations.  Runtime image
RepoDigests are pinned from the local Docker runtime, but all live preconditions
remain blocked because the approved boundary forbids login, tokens, and
stateful fixture creation.
"""

from __future__ import annotations

from re import compile

from webpent.adapters.local_causal_lab.option_b_contract import OptionBCase

CRAPI_ORIGIN = "http://127.0.0.1:8888"
CRAPI_SOURCE_REVISION = "73d309cc8f28bbdeed31dbb35f05dba8354de3c9"
CRAPI_RUNTIME_STATUS = "pinned"
CRAPI_RUNTIME_DIGEST = (
    "5f418d985aa610599361d861cf914acf662b9ef86e1598a076ed2cd2dad88d6f"
)
CRAPI_RUNTIME_IMAGE_DIGESTS = (
    (
        "crapi/crapi-web:latest",
        "sha256:b27d246c646bd33898e7d1d2095b6e7576c0993a7b81a73aa7386929493d7151",
    ),
    (
        "crapi/crapi-chatbot:latest",
        "sha256:36d274d54182a8baddba7ede17282035bb43ab9cb9cf87927e1fe7109901e0aa",
    ),
    (
        "crapi/gateway-service:latest",
        "sha256:97dade9daf0e758547b1686e2d3303c8c9b79838167f728a9211f0ee1f4622b0",
    ),
    (
        "crapi/crapi-workshop:latest",
        "sha256:d4d2d94d35a31e211b04d5a771881f5ae13e358e8fa0804463ae3bace05dd815",
    ),
    (
        "crapi/crapi-community:latest",
        "sha256:8ba0c7eda86ae065a673f1fa554d0109a24f25c5a8d65097ae024e5ee715c54e",
    ),
    (
        "crapi/crapi-identity:latest",
        "sha256:5d1db5b3ba8e02bc68711ec6fc4e35ed7cd8b87e63785ece9e7ff5b5e36c5260",
    ),
)
CRAPI_SERVICE_ALIGNMENT_STATUS = "attested"
CRAPI_SOURCE_FILES = {
    "profile_video": {
        "path": "services/identity/src/main/java/com/crapi/controller/ProfileController.java",
        "sha256": "80c357806f390e28d3ca8f32e12c40fa3d063efcf8038249d5ac5593043677b0",
    },
    "vehicle_location": {
        "path": "services/identity/src/main/java/com/crapi/controller/VehicleController.java",
        "sha256": "c49f5ab14aab7b80386c5e309d6e493360ab86f21d41d939002f1d2961f78789",
    },
    "community_post": {
        "path": "services/community/api/controllers/post_controller.go",
        "sha256": "65200617a05a35c89445e8977be053247dc90b37fe4ebaa060e1ce60e9cd1d3f",
        "route_file_sha256": "0c687eaf66beeb128361f9237882f5ce132472d3feca529e60cbeed29cf5fbfe",
    },
    "mechanic_report": {
        "path": "services/workshop/crapi/mechanic/views.py",
        "sha256": "037f0ebb9045b21a9ee838e5f32fa1be5da17d978f719a8a738f4bbb15426521",
        "route_file_sha256": "71827f3da6fb806172edd044349890dbe2d3e37e92d2a0657ce5f4eacf756ff9",
    },
}


def cases() -> tuple[OptionBCase, ...]:
    common_reason = (
        "Synthetic authenticated ownership state would require login or "
        "token/session injection, which is outside the current GET-only/"
        "no-credentials approval; runtime image RepoDigests are pinned."
    )
    return (
        OptionBCase(
            case_id="crapi.profile_video_object_access.v1",
            target_id="crapi",
            origin=CRAPI_ORIGIN,
            route_pattern=compile(r"/identity/api/v2/user/videos/[0-9]{1,12}"),
            approved_methods=("GET",),
            approved_query_keys=(),
            track="object_access",
            requires_auth=True,
            requires_target_fixture_injection=True,
            precondition_status="blocked",
            precondition_reason=common_reason
            + " Source service also appears owner-scoped; no live BOLA confirmation is inferred.",
            baseline_role="owner_video_control",
            candidate_role="distinct_requester_video_candidate",
            negative_control_roles=("opaque_nonexistent_video",),
        ),
        OptionBCase(
            case_id="crapi.vehicle_location_bola.v1",
            target_id="crapi",
            origin=CRAPI_ORIGIN,
            route_pattern=compile(r"/identity/api/v2/vehicle/[0-9a-fA-F-]{36}/location"),
            approved_methods=("GET",),
            approved_query_keys=(),
            track="object_access",
            requires_auth=True,
            requires_target_fixture_injection=True,
            precondition_status="blocked",
            precondition_reason=common_reason
            + (
                " The source-backed direct UUID lookup is a candidate only; "
                "no authenticated synthetic owner/requester pair is available."
            ),
            baseline_role="owner_vehicle_location_control",
            candidate_role="distinct_requester_vehicle_location_candidate",
            negative_control_roles=("opaque_nonexistent_vehicle",),
        ),
        OptionBCase(
            case_id="crapi.community_post_object_access.v1",
            target_id="crapi",
            origin=CRAPI_ORIGIN,
            route_pattern=compile(r"/community/api/v2/community/posts/[0-9]{1,12}"),
            approved_methods=("GET",),
            approved_query_keys=(),
            track="object_access",
            requires_auth=True,
            requires_target_fixture_injection=True,
            precondition_status="blocked",
            precondition_reason=common_reason
            + (
                " Source route is wrapped in authentication middleware; post "
                "creation would also be stateful and is not approved."
            ),
            baseline_role="owner_post_control",
            candidate_role="distinct_requester_post_candidate",
            negative_control_roles=("opaque_nonexistent_post",),
        ),
        OptionBCase(
            case_id="crapi.mechanic_report_object_access.v1",
            target_id="crapi",
            origin=CRAPI_ORIGIN,
            route_pattern=compile(r"/workshop/api/mechanic/mechanic_report"),
            approved_methods=("GET",),
            approved_query_keys=("report_id",),
            track="object_access",
            requires_auth=True,
            requires_target_fixture_injection=True,
            precondition_status="blocked",
            precondition_reason=common_reason
            + (
                " A report must be created before retrieval, but report "
                "creation is stateful and not approved."
            ),
            baseline_role="owner_report_control",
            candidate_role="distinct_requester_report_candidate",
            negative_control_roles=("opaque_nonexistent_report",),
        ),
    )


def validate_profile() -> list[str]:
    errors: list[str] = []
    for case in cases():
        errors.extend(f"{case.case_id}:{error}" for error in case.validate())
    return errors
