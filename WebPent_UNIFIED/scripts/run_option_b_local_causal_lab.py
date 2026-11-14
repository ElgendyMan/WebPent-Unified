"""Run the bounded, fail-closed Option B local causal-lab precondition pass.

At the current authorization boundary every selected case is expected to stop
before network I/O because authentication/session or a safe disposable
fixture is unavailable.  This runner therefore emits auditable blocked
records; it does not invent target evidence and has no state-changing path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Any

try:
    from scripts.check_local_causal_lab_option_b_approval import (
        validate as validate_approval,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from check_local_causal_lab_option_b_approval import validate as validate_approval

from webpent.adapters.crapi.option_b import (
    CRAPI_RUNTIME_STATUS,
    CRAPI_SOURCE_FILES,
    CRAPI_SOURCE_REVISION,
)
from webpent.adapters.crapi.option_b import (
    cases as crapi_cases,
)
from webpent.adapters.local_causal_lab.option_b_contract import (
    OptionBCase,
    blocked_precondition,
)
from webpent.adapters.webgoat.option_b import (
    WEBGOAT_SOURCE_FILES,
    WEBGOAT_SOURCE_REVISION,
)
from webpent.adapters.webgoat.option_b import (
    cases as webgoat_cases,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = (
    ROOT / "reports/evaluation/local_causal_lab/OPTION-B-LOCAL-CAUSAL-LAB-RESULT-v1.json"
)
SOURCE_ROOTS = {
    "owasp_webgoat": Path("/tmp/webgoat-source"),
    "crapi": Path("/tmp/crapi-source"),
}


def sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def collect_java_version() -> str | None:
    try:
        result = subprocess.run(
            ["java", "-version"], capture_output=True, text=True, timeout=3, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    first_line = (result.stderr or result.stdout).splitlines()
    return first_line[0][:120] if first_line else None


def source_manifest(target_id: str, files: dict[str, dict[str, str]]) -> dict[str, Any]:
    root = SOURCE_ROOTS[target_id]
    entries: list[dict[str, Any]] = []
    for name, item in sorted(files.items()):
        path = root / item["path"]
        actual = sha256_file(path)
        entries.append(
            {
                "name": name,
                "path": item["path"],
                "expected_sha256": item["sha256"],
                "actual_sha256": actual,
                "matches_expected": actual == item["sha256"],
            }
        )
        if "route_file_sha256" in item:
            route_path = root / (
                "services/community/api/router/routes.go"
                if name == "community_post"
                else "services/workshop/crapi/mechanic/urls.py"
            )
            route_actual = sha256_file(route_path)
            entries[-1]["route_file"] = str(route_path.relative_to(root))
            entries[-1]["route_expected_sha256"] = item["route_file_sha256"]
            entries[-1]["route_actual_sha256"] = route_actual
            entries[-1]["route_matches_expected"] = route_actual == item["route_file_sha256"]
    return {
        "source_revision": WEBGOAT_SOURCE_REVISION
        if target_id == "owasp_webgoat"
        else CRAPI_SOURCE_REVISION,
        "source_root": str(root),
        "files": entries,
        "all_files_match": all(
            entry["matches_expected"] and entry.get("route_matches_expected", True)
            for entry in entries
        ),
    }


def target_provenance(target_id: str) -> dict[str, Any]:
    if target_id == "owasp_webgoat":
        source = source_manifest(target_id, WEBGOAT_SOURCE_FILES)
        return {
            "target_id": target_id,
            "origin": "http://127.0.0.1:8080",
            "source": source,
            "runtime": {
                "java_version": collect_java_version(),
                "runtime_digest_status": "source_revision_pinned_but_build_digest_unavailable",
                "runtime_digest": None,
            },
        }
    source = source_manifest(target_id, CRAPI_SOURCE_FILES)
    return {
        "target_id": target_id,
        "origin": "http://127.0.0.1:8888",
        "source": source,
        "runtime": {
            "runtime_digest_status": CRAPI_RUNTIME_STATUS,
            "runtime_digest": None,
            "reason": (
                "Docker RepoDigest could not be collected from the local runtime "
                "context; no crAPI causal evidence is admitted."
            ),
        },
    }


def case_record(case: OptionBCase, provenance: dict[str, Any]) -> dict[str, Any]:
    source_ok = provenance["source"]["all_files_match"]
    runtime_ok = provenance["runtime"]["runtime_digest"] is not None
    precondition = blocked_precondition(case)
    reason = case.precondition_reason
    if not source_ok:
        reason = "Source file digest drift prevents execution: " + reason
    if not runtime_ok:
        reason = "Runtime/build digest unavailable: " + reason
    return {
        "case_id": case.case_id,
        "target_id": case.target_id,
        "track": case.track,
        "approved_track": True,
        "runnable_precondition": {
            **precondition,
            "source_digest_ok": source_ok,
            "runtime_digest_ok": runtime_ok,
        },
        "identity_model": (
            "opaque synthetic identity model declared, but no identity/session "
            "material was created or persisted"
        ),
        "fixture_model": (
            "disposable fixture/canary declared, but no application fixture or "
            "reset endpoint was invoked"
        ),
        "baseline": {"status": "not_run", "reason": "precondition_blocked"},
        "candidate": {"status": "not_run", "reason": "precondition_blocked"},
        "independent_negative_control": {"status": "not_run", "reason": "precondition_blocked"},
        "causal_oracle": {
            "status": "not_evaluated",
            "reason": "no target-backed candidate/control observations",
        },
        "proof_bundle": {
            "status": "withheld_not_applicable",
            "seal": "not_created",
            "verify_seal": "not_run",
            "replay": "not_run",
            "reason": (
                "Proof requires target-backed baseline/candidate/control "
                "observations; none were collected."
            ),
        },
        "cleanup": {
            "status": "verified_no_mutation",
            "state_hash": None,
            "reset_invoked": False,
            "network_attempted": False,
        },
        "failure_record": {
            "failure_id": f"{case.case_id}:precondition",
            "stage": "precondition",
            "code": "OPTION_B_PRECONDITION_BLOCKED",
            "reason": reason,
        },
        "root_cause_analysis": {
            "root_cause": (
                "target_local prerequisite is unavailable under the approved "
                "GET-only/no-credentials boundary"
            ),
            "evidence": [case.precondition_reason],
            "generic_or_target_local": "target-local",
            "safety_determination": "safe_stop_before_network",
        },
        "improvement_proposal": {
            "status": "proposal_only",
            "proposal": (
                "Request a separate explicit authorization for a non-credential "
                "synthetic session/fixture injection mechanism, or retain BLOCKED; "
                "do not implement an auth bypass or broaden the generic core."
            ),
            "implementation": "not_implemented",
            "regression": "precondition blocker regression added",
        },
        "before_after": {
            "before": "blocked_under_same_precondition",
            "after": "blocked_under_same_precondition",
            "comparison": "No false improvement claimed; no network or state change occurred.",
        },
        "final_classification": "BLOCKED",
        "quality_metrics": (
            "WITHHELD_NO_ADMITTED_GROUND_TRUTH_OR_TARGET_EVIDENCE"
        ),
    }


def build_result(
    import_path: Path = ROOT
    / "reports/evaluation/owner_decision/LOCAL-CAUSAL-LAB-OPTION-B-OWNER-APPROVAL-IMPORT-v1.json",
    approval_source: Path | None = None,
) -> dict[str, Any]:
    """Build the Option-B precondition result behind the approval boundary.

    R-10 (TEAM-2 residual): ``approval_source`` optionally points at the
    operator's copy of the external owner-approval artifact (same semantics
    as ``WEBPENT_OPTION_B_APPROVAL_SOURCE`` in the validator). The boundary
    stays fail-closed: a missing or hash-mismatched artifact still aborts
    the run before any record is built.
    """
    approval_errors = validate_approval(
        import_path=import_path, approval_source=approval_source
    )
    if approval_errors:
        raise ValueError("approval_boundary_failed:" + ",".join(approval_errors))
    provenance = {
        target_id: target_provenance(target_id) for target_id in ("owasp_webgoat", "crapi")
    }
    # R-10: the authorization reference is a provenance label. Imported
    # records normally live inside the repo, but hermetic test runs (and any
    # operator-supplied copy) may pass a path outside ROOT — fall back to
    # the absolute path instead of crashing the boundary check after it
    # already passed.
    try:
        authorization_ref = str(import_path.relative_to(ROOT))
    except ValueError:
        authorization_ref = str(import_path)
    cases: Iterable[OptionBCase] = (*webgoat_cases(), *crapi_cases())
    records = [case_record(case, provenance[case.target_id]) for case in cases]
    return {
        "schema": "webpent-option-b-local-causal-lab-result-v1",
        "campaign_id": "option-b-local-causal-lab-v1-20260827",
        "generated_on": date.today().isoformat(),
        "authorization_ref": authorization_ref,
        "authorization_status": "IMPORTED_BOUNDED_DIRECTIVE",
        "scope": {
            "loopback_only": True,
            "same_origin_only": True,
            "methods": ["GET"],
            "redirect_following": False,
            "external_callbacks_or_oast": False,
            "raw_response_persistence": False,
            "official_isolated_p10_runs_authorized": False,
            "bug_bounty": "BLOCKED",
        },
        "target_provenance": provenance,
        "cases": records,
        "summary": {
            "approved_case_count": len(records),
            "blocked_case_count": len(records),
            "target_backed_causal_confirmations": 0,
            "proof_bundles_sealed": 0,
            "quality_metrics": "WITHHELD",
            "p10": "NOT_QUALIFIED",
            "p9": "NOT_QUALIFIED",
            "vip": "NOT_QUALIFIED",
        },
        "non_claims": [
            "No target-backed causal evidence was collected in this precondition pass.",
            "Blocked cases are not TP, FP, FN, clean, or confirmed.",
            (
                "This artifact is not an Official P10 run and does not change "
                "scoring or qualification state."
            ),
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--approval-import",
        type=Path,
        default=(
            ROOT
            / "reports/evaluation/owner_decision/"
            "LOCAL-CAUSAL-LAB-OPTION-B-OWNER-APPROVAL-IMPORT-v1.json"
        ),
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = build_result(args.approval_import)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "written": str(args.output),
                "cases": len(result["cases"]),
                "blocked": result["summary"]["blocked_case_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
