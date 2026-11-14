"""M12 (Part 4 §14, UM-DR-23): release engineering — backup/restore
verification, the weekly-benchmark workflow contract, and the release
process doc.

Acceptance: "documented, safe deploy + restore; all CI gates green;
SBOM per release".

1. **Backup/restore verification** — the harness backs up every
   workspace store, restores it, and verifies byte-identity + sqlite
   integrity per store; a corrupted store FAILS the verification.
2. **The weekly workflow contract** — the ق5 enrollment exists, is
   cron-scheduled + dispatchable, runs the M11 runner, fails loudly on
   any deception false-positive, and uploads the dated artifact.
3. **The release process doc** — the 14-gate chain, the per-release
   artifact list (SBOM mandatory), the release-notes contract (known
   limitations + measured qualification labels), the rollback runbook,
   and the reproducible-build rules.
4. **The CI gates are real** — the ci.yml steps this phase's chain
   depends on exist by name (ratchet, SBOM, CVE gate, secret scan,
   bandit, evidence run).
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _workspace_with_stores(tmp_path: Path) -> Path:
    workspace = tmp_path / "ws" / "target-x"
    for sub, name in (
        ("sessions", "checkpoints.sqlite3"),
        ("databases", "decision_log.sqlite3"),
        ("ledgers", "findings.sqlite3"),
        ("ledgers", "actions.sqlite3"),
    ):
        (workspace / sub).mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(workspace / sub / name)
        connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        connection.execute("INSERT INTO t (v) VALUES ('evidence-row')")
        connection.commit()
        connection.close()
    (workspace / "reports").mkdir(parents=True, exist_ok=True)
    (workspace / "reports" / "report.md").write_text("# report\n", encoding="utf-8")
    return workspace


# ---------------------------------------------------------------------------
# 1. Backup / restore verification
# ---------------------------------------------------------------------------


def test_backup_restore_verifies_clean_workspace(tmp_path: Path) -> None:
    workspace = _workspace_with_stores(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "verify_backup_restore.py"),
            "--workspace",
            str(workspace),
            "--backup-dir",
            str(tmp_path / "backup"),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "integrity-checked" in result.stdout
    manifest = Path(tmp_path / "backup" / "BACKUP_MANIFEST.json")
    assert manifest.is_file()
    import json

    entries = json.loads(manifest.read_text(encoding="utf-8"))
    assert len(entries) == 5  # 4 stores + 1 report


def test_backup_restore_detects_corruption(tmp_path: Path) -> None:
    workspace = _workspace_with_stores(tmp_path)
    backup_dir = tmp_path / "backup"
    result = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "verify_backup_restore.py"),
            "--workspace",
            str(workspace),
            "--backup-dir",
            str(backup_dir),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=120,
    )
    assert result.returncode == 0

    # Corrupt one restored store — the verification must fail.
    restored = backup_dir / "_restored" / "ledgers" / "findings.sqlite3"
    restored.write_bytes(b"this is not a database")
    sys.path.insert(0, str(REPO / "scripts"))
    import verify_backup_restore

    failures = verify_backup_restore.verify(backup_dir / "_restored", backup_dir)
    assert any("sqlite_open_failed" in f or "integrity" in f for f in failures)


def test_backup_restore_detects_missing_files(tmp_path: Path) -> None:
    workspace = _workspace_with_stores(tmp_path)
    backup_dir = tmp_path / "backup"
    subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "verify_backup_restore.py"),
            "--workspace",
            str(workspace),
            "--backup-dir",
            str(backup_dir),
        ],
        capture_output=True,
        cwd=str(REPO),
        timeout=120,
        check=True,
    )
    (backup_dir / "_restored" / "reports" / "report.md").unlink()
    sys.path.insert(0, str(REPO / "scripts"))
    import verify_backup_restore

    failures = verify_backup_restore.verify(backup_dir / "_restored", backup_dir)
    assert any("missing_after_restore" in f for f in failures)


# ---------------------------------------------------------------------------
# 2. The weekly workflow contract (the ق5 enrollment)
# ---------------------------------------------------------------------------


def test_weekly_workflow_exists_and_enrolls_the_m11_runner() -> None:
    workflow = REPO / ".github" / "workflows" / "weekly-benchmarks.yml"
    assert workflow.is_file()
    text = workflow.read_text(encoding="utf-8")
    assert "run_weekly_benchmarks" in text
    assert 'cron: "0 3 * * 1"' in text  # scheduled
    assert "workflow_dispatch" in text  # manually dispatchable
    assert "false_positives\"] == 0" in text  # fails loudly on FP regression
    assert "actions/upload-artifact" in text  # the dated artifact upload
    # Deterministic/offline posture (mirrors nightly.yml).
    assert 'EMBEDDINGS_OFFLINE: "true"' in text
    assert 'LLM_ENABLED: "false"' in text


# ---------------------------------------------------------------------------
# 3. The release process doc
# ---------------------------------------------------------------------------


def test_release_process_doc_carries_the_required_contracts() -> None:
    doc = REPO / "docs" / "engineering" / "RELEASE_PROCESS.md"
    assert doc.is_file()
    text = doc.read_text(encoding="utf-8")
    for required in (
        "verify_backup_restore",      # the restore runbook step
        "SBOM",                        # the per-release artifact
        "coverage-ratchet",            # gate 12
        "check_deps_gate",             # gate 9 (CVE)
        "Known limitations",           # the release-notes contract
        "qualification",               # the measured-labels contract
        "Rollback",                    # the runbook
        "uv sync --locked",            # reproducible builds
        "frozen_modules",              # the manifest pinning
    ):
        assert required in text, required


# ---------------------------------------------------------------------------
# 4. The CI gate chain is real
# ---------------------------------------------------------------------------


def test_ci_workflow_carries_the_gate_chain() -> None:
    ci = REPO / ".github" / "workflows" / "ci.yml"
    assert ci.is_file()
    text = ci.read_text(encoding="utf-8")
    for step in (
        "check_state_contract.py",
        "check_orchestrator_construction_authority.py",
        "check_isolation_denylist.py",
        "check_vault_import_authority.py",
        "verify_test_count.py",
        "check_build_info_honesty.py",
        "check_ruff_ratchet.py",
        "check_deps_gate.py",
        "check_secrets.py",
        "bandit",
        "make coverage-ratchet",
        "CycloneDX",  # the SBOM step
        "run_tests_with_evidence.py",
    ):
        assert step in text, step


def test_nightly_canary_workflow_remains_enrolled() -> None:
    nightly = REPO / ".github" / "workflows" / "nightly.yml"
    assert nightly.is_file()
    assert "cron:" in nightly.read_text(encoding="utf-8")
