"""WebGoat-specific Option B case contract.

The profile is source-backed and carries an immutable source/build pin.  The
currently running service is not binary-attested to the newly built artifact, so
live execution remains fail-closed until alignment is independently verified.
"""

from __future__ import annotations

from re import compile

from webpent.adapters.local_causal_lab.option_b_contract import OptionBCase

WEBGOAT_ORIGIN = "http://127.0.0.1:8080"
WEBGOAT_SOURCE_REVISION = "7517acca95d9851da706452454c223dd13545ef4"
WEBGOAT_RUNTIME_DIGEST_STATUS = "pinned"
WEBGOAT_RUNTIME_DIGEST = (
    "7aafbbf408ae618ea0abe59474216950591325968ad995bfce3ed08e4f7ccf07"
)
WEBGOAT_TOOLCHAIN_DIGEST = (
    "2a41998843f23adf80ba13b1e2572a55f7a642d630c640ac561b9de8e3b2b660"
)
WEBGOAT_SERVICE_ALIGNMENT_STATUS = "not_attested"
WEBGOAT_SOURCE_FILES = {
    "idor_view": {
        "path": "src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOtherProfile.java",
        "sha256": "305cb5c0fc8d63a0b8bb4f48f4ebc6982ee332bc11c7f1dcc0ad248a3f6ac3e6",
    },
    "path_traversal_controller": {
        "path": "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java",
        "sha256": "71d8b73188716f253ffafff4de58ec4f9955b75048bf2bdb00ee07362b093ea2",
    },
    "path_traversal_source": {
        "path": "src/main/java/org/owasp/webgoat/lessons/pathtraversal/PathTraversal.java",
        "sha256": "d8298e3c3ee511969c34f7611b5047d5563021cba4a944bf09bc8b5bf0280a6d",
    },
}


def cases() -> tuple[OptionBCase, ...]:
    return (
        OptionBCase(
            case_id="webgoat.idor.view_other_profile.v1",
            target_id="owasp_webgoat",
            origin=WEBGOAT_ORIGIN,
            route_pattern=compile(r"/WebGoat/IDOR/profile/[A-Za-z0-9_-]{1,64}"),
            approved_methods=("GET",),
            approved_query_keys=(),
            track="idor",
            requires_auth=True,
            requires_target_fixture_injection=True,
            precondition_status="blocked",
            precondition_reason=(
                "GET-only approval cannot create the required LessonSession; "
                "POST login and built-in lesson credentials are not approved."
            ),
            baseline_role="requester_own_profile",
            candidate_role="requester_other_synthetic_profile",
            negative_control_roles=("opaque_nonexistent_profile",),
        ),
        OptionBCase(
            case_id="webgoat.path_traversal.v1",
            target_id="owasp_webgoat",
            origin=WEBGOAT_ORIGIN,
            route_pattern=compile(r"/WebGoat/PathTraversal/random-picture"),
            approved_methods=("GET",),
            approved_query_keys=("id",),
            track="path_traversal",
            requires_auth=False,
            requires_target_fixture_injection=True,
            precondition_status="blocked",
            precondition_reason=(
                "The live handler seeds its own lesson file and rejects raw "
                "traversal markers; no source-backed target-local disposable "
                "canary injection route is available without broad filesystem risk."
            ),
            baseline_role="approved_cat_picture_control",
            candidate_role="bounded_encoded_canary_candidate",
            negative_control_roles=("invalid_opaque_id", "sibling_file_control"),
        ),
    )


def validate_profile() -> list[str]:
    errors: list[str] = []
    for case in cases():
        errors.extend(f"{case.case_id}:{error}" for error in case.validate())
    return errors
