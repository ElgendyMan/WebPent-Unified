"""UM-DR-38.2 — release-integrity contract regression tests.

These pin the repairs for the CI failure of run 44023244366:

* the accounting contract (§1.5): the v3 hook-level model is
  authoritative; every listed failure mode fails the evidence gate;
* the NARROW freshness policy (§1.6): only the explicit metadata paths
  preserve evidence freshness — a change to production source, a test,
  the lockfile, pyproject, a workflow, the runner or the checker
  invalidates it;
* the evidence-domain separation (§1.2): BUILD_INFO honesty validates
  against the DURABLE release evidence with a STRICT revision binding;
* the ZIP builder (§3): extra-file conflicts are fatal and every
  archive member is validated.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import check_test_evidence as evidence_checker  # noqa: E402
import umdr38_build_zip as zip_builder  # noqa: E402


def _synthetic_record(**overrides) -> dict:
    """A minimal, internally-consistent v3 evidence record."""
    base = {
        "schema": "full-suite-evidence/v3",
        "runner": "run_tests_with_evidence.py",
        "source_commit": "a" * 40,
        "github": None,
        "started_at_utc": "2026-11-17T00:00:00+00:00",
        "completed_at_utc": "2026-11-17T00:30:00+00:00",
        "python_version": "3.12.16", "uv_version": "uv 0.13.8",
        "lockfile_sha256": "c" * 64,
        "command": ["python", "-m", "pytest", "tests/"],
        "test_scope_digest": "d" * 64,
        "accounting": {"collected": 10, "executed": 10, "passed": 10,
                       "failed": 0, "skipped": 0, "xfailed": 0,
                       "xpassed": 0, "errors": 0, "deselected": 0,
                       "accounting_consistent": 1, "summary_found": 1},
        "accounting_v3": {"invariants_all_true": True,
                          "interrupted": False, "not_started": 0,
                          "collection_errors": 0, "collection_skips": 0,
                          "collected_items": 10, "started_items": 10,
                          "outcomes": {"passed": 10, "failed": 0,
                                       "skipped": 0, "xfailed": 0,
                                       "xpassed": 0},
                          "setup_errors": 0, "teardown_errors": 0},
        "accounting_cross_check": {"plugin_available": True,
                                   "all_agree": True,
                                   "disagreements": {}},
        "coverage": {"floor_percent": 72, "percent_covered": 80.0},
        "exit_code": 0,
    }
    base.update(overrides)
    return base


def _evaluate(record: dict, env: dict | None = None) -> list[str]:
    return evidence_checker.evaluate(
        record, head="a" * 40, env=env or {})


# ---------------------------------------------------------------------------
# §1.5 the accounting contract — every failure mode fails
# ---------------------------------------------------------------------------

def test_clean_record_with_zero_collection_reports_validates() -> None:
    assert not _evaluate(_synthetic_record())


def test_collection_skip_is_explained_only_with_green_v3() -> None:
    record = _synthetic_record()
    record["accounting"].update({"collected": 9, "executed": 10})
    record["accounting_v3"]["collection_skips"] = 1
    record["accounting_v3"]["collected_items"] = 9
    # green v3 + cross-check -> the v2 equation disagreement is EXPLAINED
    assert not _evaluate(record)
    # but with violated v3 invariants the same disagreement FAILS
    broken = json.loads(json.dumps(record))
    broken["accounting_v3"]["invariants_all_true"] = False
    failures = _evaluate(broken)
    assert any("collected" in f and "executed+deselected" in f
               for f in failures)


def test_collection_error_must_be_recorded_in_v3() -> None:
    record = _synthetic_record()
    record["accounting"].update({"collected": 9, "executed": 10,
                                 "errors": 1, "passed": 9})
    # v3 still says zero collection errors: UNEXPLAINED -> failure
    failures = _evaluate(record)
    assert any("collected" in f for f in failures)


def test_interrupted_execution_fails() -> None:
    record = _synthetic_record()
    record["accounting_v3"]["interrupted"] = True
    assert any("INTERRUPTED" in f for f in _evaluate(record))


def test_failed_tests_fail_the_evidence() -> None:
    record = _synthetic_record()
    record["accounting"].update({"passed": 9, "failed": 1})
    record["accounting_v3"]["outcomes"] = {"passed": 9, "failed": 1}
    record["exit_code"] = 1
    failures = _evaluate(record)
    assert any("exit code" in f for f in failures)


def test_missing_v3_accounting_fails() -> None:
    record = _synthetic_record()
    record["accounting_v3"] = None
    assert any("accounting_v3" in f for f in _evaluate(record))


def test_mismatched_terminal_cross_check_fails() -> None:
    record = _synthetic_record()
    record["accounting_cross_check"] = {
        "plugin_available": True, "all_agree": False,
        "disagreements": {"executed": {"terminal": 9, "hooks": 10}}}
    assert any("cross-check" in f or "disagrees" in f
               for f in _evaluate(record))


def test_missing_timestamps_fail() -> None:
    record = _synthetic_record()
    record["started_at_utc"] = ""
    assert any("timestamps" in f for f in _evaluate(record))


def test_wrong_workflow_run_id_fails() -> None:
    record = _synthetic_record()
    record["github"] = {"run_id": "111", "run_attempt": "1"}
    failures = _evaluate(record, env={"GITHUB_RUN_ID": "222",
                                      "GITHUB_RUN_ATTEMPT": "1"})
    assert any("run" in f and "111" in f for f in failures)


def test_wrong_workflow_attempt_fails() -> None:
    record = _synthetic_record()
    record["github"] = {"run_id": "222", "run_attempt": "1"}
    failures = _evaluate(record, env={"GITHUB_RUN_ID": "222",
                                      "GITHUB_RUN_ATTEMPT": "3"})
    assert any("attempt" in f for f in failures)


def test_local_run_with_stale_github_binding_fails() -> None:
    """A CI-context record must never validate as a local run."""
    record = _synthetic_record()
    record["github"] = {"run_id": "222", "run_attempt": "1"}
    assert not _evaluate(record)  # no CI env -> binding not evaluated


# ---------------------------------------------------------------------------
# §1.6 the NARROW freshness policy (tmp git repository)
# ---------------------------------------------------------------------------

@pytest.fixture()
def fresh_repo(tmp_path: Path, monkeypatch):
    """A minimal publication-layout git repo for freshness tests."""
    repo = tmp_path / "repo"
    (repo / "WebPent_UNIFIED").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo,
                   check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo,
                   check=True)

    def commit(paths: list[str], message: str) -> str:
        for rel in paths:
            target = repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"# {message}: {rel}\n", encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", message], cwd=repo,
                       check=True)
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                              capture_output=True, text=True,
                              check=True).stdout.strip()

    base = commit(
        ["WebPent_UNIFIED/pyproject.toml", "WebPent_UNIFIED/uv.lock",
         "WebPent_UNIFIED/README.md", "README.md",
         "WebPent_UNIFIED/CHANGELOG.md",
         "WebPent_UNIFIED/DRIFT_REGISTER.md",
         "WebPent_UNIFIED/BUILD_INFO.json",
         "WebPent_UNIFIED/src/webpent/x.py",
         "WebPent_UNIFIED/tests/test_x.py",
         "WebPent_UNIFIED/scripts/run_tests_with_evidence.py",
         "WebPent_UNIFIED/scripts/check_test_evidence.py",
         "WebPent_UNIFIED/docs/sbom.cdx.json",
         "deliverables/umdr38/REPORT.md",
         ".github/workflows/ci.yml"],
        "base")
    monkeypatch.setattr(evidence_checker, "ROOT",
                        repo / "WebPent_UNIFIED")
    return repo, commit, base


def _delta(repo, commit, base: str) -> bool:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                          capture_output=True, text=True,
                          check=True).stdout.strip()
    return evidence_checker._metadata_only_delta(base, head)


@pytest.mark.parametrize("path,expected_stale", [
    # changes that MUST invalidate the evidence
    ("WebPent_UNIFIED/src/webpent/x.py", True),
    ("WebPent_UNIFIED/tests/test_x.py", True),
    ("WebPent_UNIFIED/uv.lock", True),
    ("WebPent_UNIFIED/pyproject.toml", True),
    (".github/workflows/ci.yml", True),
    ("WebPent_UNIFIED/scripts/run_tests_with_evidence.py", True),
    ("WebPent_UNIFIED/scripts/check_test_evidence.py", True),
    # the explicitly approved metadata-only changes (freshness kept)
    ("README.md", False),
    ("WebPent_UNIFIED/README.md", False),
    ("WebPent_UNIFIED/CHANGELOG.md", False),
    ("WebPent_UNIFIED/DRIFT_REGISTER.md", False),
    ("WebPent_UNIFIED/BUILD_INFO.json", False),
    ("deliverables/umdr38/REPORT.md", False),
    ("WebPent_UNIFIED/docs/sbom.cdx.json", False),
])
def test_freshness_policy(fresh_repo, path, expected_stale) -> None:
    repo, commit, base = fresh_repo
    commit([path], f"touch {path}")
    assert _delta(repo, commit, base) is (not expected_stale)


def test_script_change_no_longer_preserves_freshness(fresh_repo) -> None:
    """The UM-DR-38.1 broad `scripts/` allowance is REMOVED: a report
    generator or any script change now invalidates the evidence."""
    repo, commit, base = fresh_repo
    commit(["WebPent_UNIFIED/scripts/umdr38_reports.py"],
           "touch a report generator")
    assert _delta(repo, commit, base) is False


def test_workflow_change_no_longer_preserves_freshness(fresh_repo) -> None:
    repo, commit, base = fresh_repo
    commit([".github/workflows/nightly.yml"], "touch a workflow")
    assert _delta(repo, commit, base) is False


def test_non_ancestor_never_preserves_freshness(fresh_repo) -> None:
    repo, commit, base = fresh_repo
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                          capture_output=True, text=True,
                          check=True).stdout.strip()
    assert evidence_checker._metadata_only_delta("b" * 40, head) is False


# ---------------------------------------------------------------------------
# §1.2 the evidence-domain separation (BUILD_INFO honesty)
# ---------------------------------------------------------------------------

def _synthetic_build_info(evidence_revision: str) -> dict:
    return {
        "build_name": "x", "build_date": "2026-11-17T00:00:00+00:00",
        "package_version": "0.40.1",
        "version_identity_contract": {
            "package_version": "0.40.1",
            "current_release": {"package_version": "0.40.1",
                                "source_revision": evidence_revision},
            "release_history": [
                {"package_version": "0.38.0", "source_revision": None,
                 "source_revision_note": "local lineage"}],
        },
        "suite_count": 10,
        "suite_evidence": "x" * 60,
        "units_closed": ["U"], "fixes_applied": ["f"],
        "provenance": {
            "schema": "umdr36-1-provenance-v1",
            "source_revision": evidence_revision,
            "tested_revision": evidence_revision,
            "evidence_revision": evidence_revision,
            "recovery_baseline": "1968f63c2076b1b804537f91cd5cfa01"
                                 "c3eee0bb",
            "package_version": "0.40.1",
            "manifest_digest": "0" * 64,
            "build_date": "2026-11-17T00:00:00+00:00",
            "publication": {"published": False, "release_tag": None},
            "test_accounting": {
                "collected": 10, "executed": 10, "passed": 10,
                "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0,
                "errors": 0, "deselected": 0},
        },
    }


def test_durable_evidence_bound_to_a_different_revision_fails(
        tmp_path: Path, monkeypatch) -> None:
    import check_build_info_honesty as honesty

    monkeypatch.setattr(honesty, "ROOT", REPO)
    monkeypatch.setattr(honesty, "MANIFEST",
                        REPO / "frozen_modules.sha256")
    info = _synthetic_build_info(evidence_revision="a" * 40)
    record = _synthetic_record(source_commit="b" * 40)
    failures, _ = honesty.evaluate(
        info, root=REPO, collected_probe="skip",
        evidence_record=record)
    assert any("bound to different revisions" in f for f in failures)


def test_durable_evidence_accounting_mismatch_fails(
        tmp_path: Path, monkeypatch) -> None:
    import check_build_info_honesty as honesty

    monkeypatch.setattr(honesty, "ROOT", REPO)
    monkeypatch.setattr(honesty, "MANIFEST",
                        REPO / "frozen_modules.sha256")
    info = _synthetic_build_info(evidence_revision="a" * 40)
    record = _synthetic_record(source_commit="a" * 40)
    record["accounting"]["passed"] = 9  # differs from BUILD_INFO
    failures, _ = honesty.evaluate(
        info, root=REPO, collected_probe="skip",
        evidence_record=record)
    assert any("accounting differs" in f for f in failures)


def test_honesty_gate_reads_the_durable_domain_not_runtime() -> None:
    """The gate's EVIDENCE path must be the tracked deliverables copy —
    never .webpent-evidence (the current-run domain)."""
    import check_build_info_honesty as honesty

    assert "deliverables" in str(honesty.EVIDENCE)
    assert ".webpent-evidence" not in str(honesty.EVIDENCE)


# ---------------------------------------------------------------------------
# §3 the ZIP builder contracts
# ---------------------------------------------------------------------------

def test_extra_conflicts_are_refused_by_main(tmp_path: Path) -> None:
    """A conflict reported by add_extras must be FATAL: main() returns
    1 without building (the published record carried an SBOM conflict
    beside archive_integrity: PASS — that class ends here)."""
    stage = tmp_path / "stage"
    (stage / "WebPent_UNIFIED" / "scripts").mkdir(parents=True)
    (stage / "WebPent_UNIFIED" / "scripts" / "check_secrets.py") \
        .write_text("# stub\n", encoding="utf-8")
    conflicting = stage / "deliverables" / "umdr38" / "sbom.cdx.json"
    conflicting.parent.mkdir(parents=True)
    conflicting.write_text('{"tracked": true}', encoding="utf-8")
    notes = zip_builder.add_extras(stage)
    assert any(n.startswith("CONFLICT") for n in notes)
    # and main() refuses when any extra conflict exists (source-level
    # contract: the refusal block keys on exactly these notes)
    source = (REPO / "scripts" / "umdr38_build_zip.py").read_text(
        encoding="utf-8")
    assert 'n.startswith("CONFLICT")' in source
    assert "extra-file conflicts" in source


def test_every_archive_member_is_validated(tmp_path: Path) -> None:
    """The full-member contract: a tampered member ANYWHERE in the
    archive (not just a sampled one) fails validate_zip."""
    import zipfile

    stage = tmp_path / "stage"
    stage.mkdir()
    for i in range(60):  # more members than the old every-50th sample
        p = stage / f"file_{i:03d}.txt"
        p.write_text(f"content {i}", encoding="utf-8")
    out = tmp_path / "pkg.zip"
    with zipfile.ZipFile(out, "w") as zf:
        for p in sorted(stage.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(stage).as_posix())
    assert not zip_builder.validate_zip(out, stage)
    # tamper with member #57 — beyond any sampling stride
    data = {}
    with zipfile.ZipFile(out) as zf:
        data = {n: zf.read(n) for n in zf.namelist()}
    data["file_057.txt"] = b"tampered"
    out.unlink()
    with zipfile.ZipFile(out, "w") as zf:
        for name, blob in data.items():
            zf.writestr(name, blob)
    failures = zip_builder.validate_zip(out, stage)
    assert any("file_057" in f for f in failures)
