"""Run reproducible local quality and release-security gates."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCS = PROJECT_ROOT / "docs"
OUTPUT_PATH = DOCS / "vip_quality_gate.json"
PYTHON = sys.executable
_LOCAL_RUFF = Path(PYTHON).with_name("ruff")
RUFF = str(_LOCAL_RUFF) if _LOCAL_RUFF.is_file() else (shutil.which("ruff") or "ruff")
BANDIT = shutil.which("bandit") or "bandit"
PIP_AUDIT = shutil.which("pip-audit") or "pip-audit"
UV = shutil.which("uv")
PYTEST = [PYTHON, "-m", "pytest", "-q"]

VIP_FILES = [
    "src/webpent/models/campaigns.py",
    "src/webpent/models/application_intent.py",
    "src/webpent/models/evidence_ledger.py",
    "src/webpent/models/proof_engine.py",
    "src/webpent/models/surface_graph.py",
    "src/webpent/models/surface_security.py",
    "src/webpent/models/workflow_replay.py",
    "src/webpent/models/workflows.py",
    "src/webpent/shared/application_intent.py",
    "src/webpent/shared/application_intent_graph.py",
    "src/webpent/shared/campaign_planner.py",
    "src/webpent/shared/evidence_ledger.py",
    "src/webpent/shared/proof_engine.py",
    "src/webpent/shared/surface_evidence_graph.py",
    "src/webpent/shared/surface_security.py",
    "src/webpent/shared/validator_plugins.py",
    "src/webpent/shared/offline_validator_fixtures.py",
    "src/webpent/shared/workflow_replay.py",
    "src/webpent/shared/workflow_understanding.py",
    "src/webpent/shared/adaptive_hunt.py",
    "src/webpent/state/initial_state.py",
    "src/webpent/state/state.py",
    "src/webpent/agents/validator/agent.py",
    "scripts/capture_vip_baseline.py",
    "scripts/run_vip_quality_gate.py",
    "scripts/run_waptlab_regression.py",
    "scripts/build_release_manifest.py",
    "scripts/build_capability_report.py",
    "scripts/build_mock_qualification_report.py",
    "scripts/build_preflight_report.py",
    "tests/test_vip_application_intent_graph.py",
    "tests/test_vip_baseline.py",
    "tests/test_vip_campaign_planner.py",
    "tests/test_vip_proof_engine.py",
    "tests/test_vip_shared_reauth_vault.py",
    "tests/test_vip_surface_intent.py",
    "tests/test_vip_validator_plugins.py",
    "tests/test_vip_offline_validator_fixtures.py",
    "tests/test_vip_waptlab_regression.py",
    "tests/test_vip_workflow_replay.py",
]


def _run(name: str, command: list[str], *, timeout: int = 300) -> dict[str, Any]:
    """Run one gate and retain bounded output for machine-readable review."""
    try:
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env={**os.environ, "PYTHONPATH": "src"},
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (completed.stdout + completed.stderr).strip().splitlines()
        return {
            "name": name,
            "command": command,
            "passed": completed.returncode == 0,
            "returncode": completed.returncode,
            "tail": output[-12:],
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "name": name,
            "command": command,
            "passed": False,
            "returncode": None,
            "tail": [f"{type(exc).__name__}: {exc}"],
        }


def _artifact_safety() -> dict[str, Any]:
    path = DOCS / "waptlab_regression.json"
    if not path.is_file():
        return {"passed": False, "reason": "missing docs/waptlab_regression.json"}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"passed": False, "reason": f"invalid regression artifact: {exc}"}
    summary = payload.get("summary", {})
    passed = (
        payload.get("campaign_count") == 20
        and payload.get("target_contacted") is False
        and payload.get("waptlab_modified") is False
        and sum(summary.values()) == 20
        and summary.get("inconclusive") == 13
        and summary.get("missing-validator") == 7
    )
    return {
        "passed": passed,
        "campaign_count": payload.get("campaign_count"),
        "summary": summary,
        "target_contacted": payload.get("target_contacted"),
        "waptlab_modified": payload.get("waptlab_modified"),
    }


def _dependency_input() -> tuple[list[str], str]:
    """Prefer a lock-derived requirement export and fall back to the audit file."""
    output = PROJECT_ROOT / "docs" / "requirements-audit-release.txt"
    if UV:
        result = _run(
            "export-locked-requirements",
            [
                UV,
                "export",
                "--locked",
                "--all-groups",
                "--no-emit-project",
                "--format",
                "requirements.txt",
                "--output-file",
                str(output),
            ],
            timeout=120,
        )
        if result["passed"] and output.is_file():
            return [str(output)], "uv-exported-lock"
    fallback = PROJECT_ROOT / "requirements-audit-v63.txt"
    return [str(fallback)], "requirements-audit-v63"


def _preflight_contract() -> dict[str, Any]:
    path = DOCS / "preflight_report.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        posture = payload.get("posture", {})
        passed = (
            payload.get("schema_version") == "webpent-preflight-v1"
            and payload.get("host_evaluated") == "127.0.0.1"
            and posture.get("state") in {
                "PASS",
                "READY_WITH_WARNING",
                "DEGRADED",
            }
            and posture.get("fail_closed") is True
        )
        return {
            "name": "preflight-report-contract",
            "command": [str(path)],
            "passed": passed,
            "returncode": 0 if passed else 1,
            "tail": [] if passed else ["invalid preflight posture artifact"],
        }
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "name": "preflight-report-contract",
            "command": [str(path)],
            "passed": False,
            "returncode": None,
            "tail": [f"{type(exc).__name__}: {exc}"],
        }


def _qualification_checks() -> list[dict[str, Any]]:
    """Build and validate local qualification artifacts without live claims."""
    checks = [
        _run(
            "preflight-report",
            [PYTHON, "scripts/build_preflight_report.py", "--host", "127.0.0.1"],
            timeout=60,
        ),
        _run(
            "capability-report",
            [PYTHON, "scripts/build_capability_report.py"],
            timeout=60,
        ),
        _run(
            "mock-qualification-report",
            [PYTHON, "scripts/build_mock_qualification_report.py"],
            timeout=60,
        ),
    ]
    capability_path = DOCS / "capability_report.json"
    qualification_path = DOCS / "waptlab_qualification_report.json"
    try:
        capability = json.loads(capability_path.read_text(encoding="utf-8"))
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        capability_passed = (
            capability.get("catalog_count") == 20
            and capability.get("live_qualification") is False
            and "missing-validator" not in capability.get("validator_status_counts", {})
        )
        qualification_passed = (
            qualification.get("run_count") == 3
            and qualification.get("stable_campaign_signatures") is True
            and qualification.get("live_qualification") is False
            and qualification.get("target_contacted") is False
            and qualification.get("waptlab_modified") is False
        )
    except (OSError, json.JSONDecodeError) as exc:
        capability_passed = False
        qualification_passed = False
        checks.append(
            {
                "name": "qualification-artifact-read",
                "command": [],
                "passed": False,
                "returncode": None,
                "tail": [f"{type(exc).__name__}: {exc}"],
            }
        )
    checks.append(_preflight_contract())
    checks.extend(
        [
            {
                "name": "capability-report-contract",
                "command": [str(capability_path)],
                "passed": capability_passed,
                "returncode": 0 if capability_passed else 1,
                "tail": [],
            },
            {
                "name": "mock-qualification-contract",
                "command": [str(qualification_path)],
                "passed": qualification_passed,
                "returncode": 0 if qualification_passed else 1,
                "tail": [],
            },
        ]
    )
    return checks


def _security_checks() -> list[dict[str, Any]]:
    """Run high-severity Bandit and strict dependency/SBOM checks."""
    bandit_json = DOCS / "bandit_release.json"
    bandit_check = _run(
        "bandit-high-severity",
        [
            BANDIT,
            "-q",
            "-r",
            "src/webpent",
            "-x",
            "tests",
            "-lll",
            "-f",
            "json",
            "-o",
            str(bandit_json),
        ],
        timeout=180,
    )
    requirement_args, requirement_source = _dependency_input()
    requirement_path = requirement_args[0]
    sbom_path = DOCS / "sbom.cdx.json"
    audit_json = DOCS / "pip_audit_release.json"
    sbom_check = _run(
        "pip-audit-sbom",
        [
            PIP_AUDIT,
            "--strict",
            "--timeout",
            "15",
            "--requirement",
            requirement_path,
            "--format",
            "cyclonedx-json",
            "--output",
            str(sbom_path),
        ],
        timeout=240,
    )
    audit_check = _run(
        "pip-audit-strict",
        [
            PIP_AUDIT,
            "--strict",
            "--timeout",
            "15",
            "--requirement",
            requirement_path,
            "--format",
            "json",
            "--output",
            str(audit_json),
        ],
        timeout=240,
    )
    for check in (bandit_check, sbom_check, audit_check):
        check["requirement_source"] = requirement_source
    return [bandit_check, sbom_check, audit_check]


def main() -> int:
    checks = [
        _run("compileall", [PYTHON, "-m", "compileall", "-q", "src", "scripts"]),
        _run("ruff", [RUFF, "check", *VIP_FILES]),
        _run("pytest", [*PYTEST], timeout=420),
        _run(
            "test-function-count",
            [PYTHON, "scripts/verify_test_count.py", "--minimum", "796"],
            timeout=60,
        ),
    ]
    checks.extend(_qualification_checks())
    checks.extend(_security_checks())
    manifest_check = _run(
        "release-manifest",
        [PYTHON, "scripts/build_release_manifest.py"],
        timeout=60,
    )
    checks.append(manifest_check)
    safety = _artifact_safety()
    passed = all(check["passed"] for check in checks) and safety["passed"]
    blockers = [
        "WAPTLab regression is local contract-only; no campaign is confirmed by this gate",
        "worker critical-path qualification and live Docker qualification remain "
        "environment-blocked",
    ]
    check_by_name = {check["name"]: check for check in checks}
    if not check_by_name.get("pip-audit-strict", {}).get("passed", False):
        blockers.append(
            "pip-audit strict did not pass; dependency advisories remain a release blocker"
        )
    if not check_by_name.get("bandit-high-severity", {}).get("passed", False):
        blockers.append(
            "Bandit high-severity gate did not pass or did not produce an artifact"
        )
    if not check_by_name.get("release-manifest", {}).get("passed", False):
        blockers.append("release manifest could not be generated")
    report = {
        "schema_version": "vip-quality-gate-v2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "WebPent v61",
        "passed": passed,
        "checks": checks,
        "waptlab_artifact_safety": safety,
        "security_artifacts": {
            "bandit": "docs/bandit_release.json",
            "pip_audit": "docs/pip_audit_release.json",
            "sbom": "docs/sbom.cdx.json",
        },
        "known_blockers": blockers,
    }
    OUTPUT_PATH.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"passed": passed, "output": str(OUTPUT_PATH)}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
