"""Fail-closed validation for the imported Option B owner directive.

The import is an execution-boundary record only.  It must never mutate or
implicitly approve the original pending decision packet or any official gate.

R-10 (TEAM-2 residual): the approval artifact lives OUTSIDE the repo by
policy (``raw_content_persisted_in_repo`` is required to be false), so its
location is machine-specific. ``APPROVAL_SOURCE`` may therefore be pointed
at the operator's copy via ``WEBPENT_OPTION_B_APPROVAL_SOURCE``. The
boundary itself stays fail-closed: a missing file is still
``approval_source_missing`` and a content change is still
``approval_source_hash_mismatch`` — only WHERE the artifact may live
changed, never WHAT must be proven.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
IMPORT = (
    ROOT
    / "reports/evaluation/owner_decision/LOCAL-CAUSAL-LAB-OPTION-B-OWNER-APPROVAL-IMPORT-v1.json"
)
PACKET = ROOT / "reports/evaluation/owner_decision/LOCAL-CAUSAL-LAB-OWNER-DECISION-PACKET-v1.json"
INVENTORY = ROOT / "reports/evaluation/source_inventory/SOURCE-BACKED-CANDIDATE-INVENTORY-v1.json"
# R-10: operator-configurable location of the external approval artifact.
# Default kept as the originally recorded path for provenance; deployments
# without that exact layout set WEBPENT_OPTION_B_APPROVAL_SOURCE instead.
APPROVAL_SOURCE = Path(
    os.environ.get("WEBPENT_OPTION_B_APPROVAL_SOURCE")
    or "/home/ubuntu/upload/pasted_content.txt"
)
EXPECTED_CASES = {
    "webgoat.idor.view_other_profile.v1",
    "webgoat.path_traversal.v1",
    "crapi.profile_video_object_access.v1",
    "crapi.vehicle_location_bola.v1",
    "crapi.community_post_object_access.v1",
    "crapi.mechanic_report_object_access.v1",
}
EXPECTED_TARGET_REVISIONS = {
    "owasp_webgoat": "7517acca95d9851da706452454c223dd13545ef4",
    "crapi": "73d309cc8f28bbdeed31dbb35f05dba8354de3c9",
}


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot_load:{path}:{exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"json_object_required:{path}")
    return value


def validate(
    import_path: Path = IMPORT,
    packet_path: Path = PACKET,
    inventory_path: Path = INVENTORY,
    approval_source: Path = APPROVAL_SOURCE,
) -> list[str]:
    errors: list[str] = []
    record = load(import_path)
    packet = load(packet_path)
    inventory = load(inventory_path)

    if record.get("schema") != "webpent-owner-approval-import-option-b-v1":
        errors.append("unexpected_import_schema")
    if record.get("record_type") != "owner_approval_import_execution_only":
        errors.append("import_must_be_execution_only")
    if record.get("status") != "IMPORTED_BOUNDED_DIRECTIVE":
        errors.append("import_status_must_be_bounded_directive")

    source = record.get("source_artifact", {})
    if source.get("raw_content_persisted_in_repo") is not False:
        errors.append("raw_approval_content_must_not_be_persisted")
    if not approval_source.exists():
        errors.append("approval_source_missing")
    else:
        actual_sha = hashlib.sha256(approval_source.read_bytes()).hexdigest()
        if source.get("sha256") != actual_sha:
            errors.append("approval_source_hash_mismatch")

    authority = record.get("authority", {})
    expected_false = (
        "owner_identity_provided",
        "owner_signature_provided",
        "approval_time_provided",
        "expiry_inferred",
        "human_independent_signoff_obtained",
    )
    for field in expected_false:
        if authority.get(field) is not False:
            errors.append(f"authority_{field}_must_be_false")
    if authority.get("approval_expiry") is not None:
        errors.append("approval_expiry_must_remain_unspecified")
    if authority.get("execution_scope") != "current_bounded_task_only":
        errors.append("execution_scope_must_be_current_task_only")

    if record.get("approved_option") != "B_STAGED_LOCAL_CAUSAL_LAB":
        errors.append("option_b_required")
    targets = record.get("allowed_targets", [])
    target_map = {item.get("target_id"): item for item in targets if isinstance(item, dict)}
    if set(target_map) != set(EXPECTED_TARGET_REVISIONS):
        errors.append("target_allowlist_mismatch")
    for target_id, revision in EXPECTED_TARGET_REVISIONS.items():
        if target_map.get(target_id, {}).get("source_revision") != revision:
            errors.append(f"source_revision_mismatch:{target_id}")
    if record.get("approved_case_ids") and set(record["approved_case_ids"]) != EXPECTED_CASES:
        errors.append("case_allowlist_mismatch")
    elif not record.get("approved_case_ids"):
        errors.append("case_allowlist_missing")
    if record.get("approved_methods") != ["GET"]:
        errors.append("approved_methods_must_be_get_only")

    network = record.get("network_boundary", {})
    if network.get("host_allowlist") != ["127.0.0.1"]:
        errors.append("host_allowlist_must_be_loopback_only")
    for field in (
        "same_origin_only",
        "redirect_following",
        "outbound_network",
        "dns_or_public_ip_resolution",
        "external_callbacks_or_oast",
        "external_destinations",
    ):
        expected = field == "same_origin_only"
        if network.get(field) is not expected:
            errors.append(f"network_boundary_invalid:{field}")

    fixture = record.get("fixture_and_identity_boundary", {})
    for field in (
        "synthetic_identities_only",
        "opaque_identity_ids_only",
        "disposable_fixtures_only",
        "disposable_canaries_only",
    ):
        if fixture.get(field) is not True:
            errors.append(f"fixture_boundary_required:{field}")
    for field in (
        "real_credentials_allowed",
        "login_or_session_bootstrap_allowed",
        "otp_mfa_captcha_bypass_allowed",
        "credential_or_token_persistence_allowed",
        "raw_body_header_cookie_persistence_allowed",
        "personal_data_persistence_allowed",
        "application_mutation_allowed",
        "application_reset_endpoint_allowed",
    ):
        if fixture.get(field) is not False:
            errors.append(f"fixture_boundary_forbidden:{field}")

    exclusions = set(record.get("explicit_exclusions", []))
    required_exclusions = {
        "official_p10_runs",
        "official_isolated_p10_runs_authorized_gate",
        "bug_bounty_or_external_targets",
        "webgoat.stored_xss.comments.v1",
        "webgoat.sql_injection.advanced.v1",
        "crapi mutation/auth/reset tracks",
        "real_credentials_or_login",
        "frozen_ground_truth_changes",
        "p10_vip_threshold_changes",
        "qualification_claims",
    }
    if not required_exclusions.issubset(exclusions):
        errors.append("explicit_exclusions_incomplete")

    effects = record.get("import_effect", {})
    for field in (
        "original_decision_packet_modified",
        "original_decision_packet_owner_decision_filled",
        "governance_packet_modified",
        "human_signoff_changed",
        "official_isolated_p10_runs_authorized_changed",
        "qualification_changed",
        "scoring_set_changed",
        "target_runtime_changed",
    ):
        if effects.get(field) is not False:
            errors.append(f"import_effect_must_be_false:{field}")

    invariants = record.get("global_invariants", {})
    if invariants.get("human_independent_signoff_obtained") is not False:
        errors.append("global_human_signoff_must_be_false")
    if invariants.get("official_isolated_p10_runs_authorized") is not False:
        errors.append("official_run_gate_must_be_false")
    for field in ("p10", "p9", "vip"):
        if invariants.get(field) != "NOT_QUALIFIED":
            errors.append(f"qualification_must_remain_not_qualified:{field}")
    if (
        invariants.get("bug_bounty") != "BLOCKED"
        or invariants.get("scoring_promotion_allowed") is not False
    ):
        errors.append("promotion_or_external_scope_not_closed")

    if packet.get("status") != "PENDING_OWNER_APPROVAL":
        errors.append("original_packet_must_remain_pending")
    owner_decision = packet.get("owner_decision", {})
    if any(
        owner_decision.get(field) not in (None, [], "")
        for field in (
            "decision",
            "approved_targets",
            "approved_case_ids",
            "approved_methods",
            "owner_notes",
        )
    ):
        errors.append("original_packet_contains_prefilled_approval")
    packet_state = packet.get("current_governance_state", {})
    if packet_state.get("official_isolated_p10_runs_authorized") is not False:
        errors.append("packet_official_gate_must_be_false")
    if packet_state.get("bug_bounty") != "BLOCKED":
        errors.append("packet_bug_bounty_must_be_blocked")

    inventory_targets = {item.get("target_id"): item for item in inventory.get("targets", [])}
    for target_id, revision in EXPECTED_TARGET_REVISIONS.items():
        inv = inventory_targets.get(target_id)
        if not inv or inv.get("source_revision") != revision:
            errors.append(f"inventory_source_revision_mismatch:{target_id}")
    packet_cases = packet.get("cases", {})
    packet_case_ids = {
        case.get("case_id")
        for cases in packet_cases.values()
        for case in cases
        if isinstance(case, dict)
        and case.get("lab_disposition") == "candidate_for_narrow_owner_approval"
    }
    if not EXPECTED_CASES.issubset(packet_case_ids):
        errors.append("packet_option_b_case_mapping_incomplete")

    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--import", dest="import_path", type=Path, default=IMPORT)
    parser.add_argument("--packet", type=Path, default=PACKET)
    parser.add_argument("--inventory", type=Path, default=INVENTORY)
    parser.add_argument(
        "--approval-source",
        type=Path,
        default=APPROVAL_SOURCE,
        help=(
            "Path to the external owner-approval artifact "
            "(env: WEBPENT_OPTION_B_APPROVAL_SOURCE)."
        ),
    )
    args = parser.parse_args()
    errors = validate(args.import_path, args.packet, args.inventory, args.approval_source)
    print(json.dumps({"passed": not errors, "errors": errors}, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
