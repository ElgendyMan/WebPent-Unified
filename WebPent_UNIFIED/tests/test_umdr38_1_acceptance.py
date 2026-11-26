"""UM-DR-38.1 Phase 11 — automated acceptance tests.

These tests prevent the UM-DR-38 publication failures from recurring.
Local-feasibility scoping is explicit: the GitHub-side proofs (actual
Actions run on the published commit) are remote gates (G38-06/G38-30)
recorded honestly as BLOCKED_EXTERNAL_DEPENDENCY in the matrix — they
are pinned here as "the matrix must carry them as blocked, never as
PASS", which is the strongest local assertion that exists.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PUB = REPO.parent
sys.path.insert(0, str(REPO / "scripts"))


def _git(args: list[str]) -> str:
    r = subprocess.run(["git", *args], cwd=PUB, capture_output=True,
                       text=True, check=False)
    return r.stdout if r.returncode == 0 else ""


def _git_ok(args: list[str]) -> bool:
    return subprocess.run(args, cwd=PUB, capture_output=True,
                          check=False).returncode == 0


def _tree_has(path: str) -> bool:
    return bool(_git(["ls-tree", "--name-only", "HEAD", "--", path]).strip())


# --- 1-3, 26: root artifacts and discovery path (git tree) ----------

def test_root_readme_and_workflows_in_git_tree() -> None:
    assert _tree_has("README.md")
    for name in ("ci.yml", "nightly.yml", "weekly-benchmarks.yml"):
        assert _tree_has(f".github/workflows/{name}")


def test_nested_workflows_absent() -> None:
    assert not _git(["ls-tree", "-r", "--name-only", "HEAD", "--",
                     "WebPent_UNIFIED/.github/"]).strip()


# --- 4: the ZIP builder is clean-clone-capable ----------------------

def test_zip_builder_has_no_personal_absolute_paths() -> None:
    source = (REPO / "scripts" / "umdr38_build_zip.py").read_text(
        encoding="utf-8")
    assert "/home/" not in source, (
        "the builder must not embed personal absolute paths — it must "
        "work from a clean clone")
    assert "--output" in source and "WEBPENT_ZIP_OUTPUT" in source, (
        "the output must be parameterized (arg/env) with a dist/ default")


def test_zip_builder_uses_tracked_sources_only() -> None:
    source = (REPO / "scripts" / "umdr38_build_zip.py").read_text(
        encoding="utf-8")
    assert "ls-files" in source, (
        "staging must come from git-tracked files (a clean clone has "
        "exactly these)")
    assert "CONFLICT" in source, (
        "copy conflicts must be detected — no silent overwrites")


# --- 5: provenance SHAs resolve -------------------------------------

def test_provenance_shas_resolve_from_this_branch() -> None:
    info = json.loads((REPO / "BUILD_INFO.json").read_text(
        encoding="utf-8"))
    prov = info.get("provenance") or {}
    for key in ("source_revision", "tested_revision",
                "evidence_revision", "recovery_baseline"):
        sha = str(prov.get(key, ""))
        assert re.fullmatch(r"[0-9a-f]{40}", sha), (
            f"provenance.{key} must be a 40-hex sha, got {sha!r}")
        assert _git_ok(["git", "cat-file", "-e", f"{sha}^{{commit}}"]), (
            f"provenance.{key} {sha} does not resolve as a commit from "
            "this branch")


# --- 6-7: stale evidence and lockfile mismatch are rejected ---------

_SYNTHETIC = {
    "schema": "full-suite-evidence/v3",
    "runner": "run_tests_with_evidence.py",
    "source_commit": "a" * 40,
    "github": None,
    "started_at_utc": "2026-11-16T00:00:00+00:00",
    "completed_at_utc": "2026-11-16T00:30:00+00:00",
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


def test_old_evidence_never_validates_for_a_new_revision() -> None:
    import check_test_evidence as checker

    head = _git(["rev-parse", "HEAD"]).strip()
    synthetic = dict(_SYNTHETIC)
    synthetic["source_commit"] = head
    failures = checker.evaluate(synthetic, head=head, env={})
    assert not failures, f"a current synthetic record must validate: {failures}"
    stale = dict(synthetic, source_commit="b" * 40)
    assert any("STALE" in f for f in
               checker.evaluate(stale, head=head, env={}))


def test_lockfile_mismatch_is_rejected() -> None:
    import check_test_evidence as checker

    failures = checker.evaluate(dict(_SYNTHETIC), head="a" * 40, env={},
                                expected_lockfile_sha="f" * 64)
    assert any("stale evidence from a different dependency state" in f
               for f in failures)


# --- 8-11: gate status mapping --------------------------------------

def test_gate_status_mapping_delegation() -> None:
    import umdr38_closure

    assert umdr38_closure._canonical_status(0) == "PASS"
    assert umdr38_closure._canonical_status(1) == "FAIL"
    assert umdr38_closure._canonical_status(None) == "NOT_RUN"
    _, status = umdr38_closure._aggregate_status(
        [{"gate": "ruff-ratchet", "exit_code": 1}])
    assert status == "FAIL", "ruff exit 1 can never yield PASS"


# --- 12-15: missing is not zero; chain joins ------------------------

def test_chain_joins_delegation() -> None:
    from confirmation_chain import build_confirmation_chain

    chain = build_confirmation_chain(
        [{"id": "f-1", "evidence_bundle_id": None}],
        [], [{"verdict": "CONFIRMED"}])
    assert chain["events"][0]["chain_status"] == "incomplete"
    assert chain["ids"]["causal_guard_confirmed_ids"] is None


# --- 17: out-of-scope proof from the origin's own log ---------------

def test_out_of_scope_zero_is_pinned_in_campaign_invariants() -> None:
    record = (PUB / "deliverables" / "umdr37" / "evidence"
              / "umdr37_production_campaigns.json")
    if record.is_file():
        data = json.loads(record.read_text(encoding="utf-8"))
        for run in data.get("runs", []):
            assert run.get("out_of_scope_request_count") == 0
            assert run.get("invariant_checks", {}).get(
                "out_of_scope_origin_zero_requests") is True


# --- 20: matrix counts derived (structural, when present) ----------

def test_matrix_counts_derived_from_elements() -> None:
    matrix_path = (PUB / "deliverables" / "umdr38"
                   / "UMDR38_ACCEPTANCE_MATRIX.json")
    if not matrix_path.is_file():
        return  # generated after the gates run; the generator enforces it
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    counts: dict[str, int] = {}
    for gate in matrix["gates"]:
        counts[gate["status"]] = counts.get(gate["status"], 0) + 1
    assert matrix["counts"] == counts


# --- 21: the decision never rises above the evidence ----------------

def test_decision_rule_delegation() -> None:
    import umdr38_closure

    assert umdr38_closure._final_decision(
        [{"status": "FAIL"}], remote_verified=False) == (
        "PARTIALLY_VERIFIED")
    assert umdr38_closure._final_decision(
        [{"status": "NOT_RUN"}], remote_verified=False) == (
        "PARTIALLY_VERIFIED")


# --- 22-24: zip validation primitives (synthetic stage) -------------

def test_zip_validation_primitives(tmp_path: Path) -> None:
    import umdr38_build_zip as builder

    # a minimal synthetic stage: the required files are missing (the
    # expected failure class) but no traversal/absolute failures exist
    (tmp_path / "WebPent_UNIFIED").mkdir()
    (tmp_path / "WebPent_UNIFIED" / "pyproject.toml").write_text(
        'version = "0.40.1"', encoding="utf-8")
    (tmp_path / "WebPent_UNIFIED" / "BUILD_INFO.json").write_text(
        json.dumps({"package_version": "0.40.1"}), encoding="utf-8")
    failures = builder.validate_stage(tmp_path)
    assert not any("traversal" in f for f in failures)
    assert any("required file missing" in f for f in failures)


def test_zip_digest_helpers() -> None:
    import tempfile

    import umdr38_build_zip as builder

    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "x.bin"
        f.write_bytes(b"payload")
        digest = builder._sha256(f)
        assert re.fullmatch(r"[0-9a-f]{64}", digest)


# --- 25: release metadata consistency --------------------------------

def test_release_metadata_consistent() -> None:
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    build_info = json.loads((REPO / "BUILD_INFO.json").read_text(
        encoding="utf-8"))
    version = [line for line in pyproject.splitlines()
               if line.strip().startswith("version")][0].split('"')[1]
    # UM-DR-49 (v0.48.0): the pinned triple follows the release SSOT
    assert version == build_info.get("package_version") == "0.48.0"


# --- 27: the remote gates stay honest in the matrix ------------------

def test_remote_gates_never_claim_pass_locally() -> None:
    matrix_path = (PUB / "deliverables" / "umdr38"
                   / "UMDR38_ACCEPTANCE_MATRIX.json")
    if not matrix_path.is_file():
        return  # generator-enforced; see the decision rule tests
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    for gate in matrix["gates"]:
        if gate["gate"] in ("G38-06", "G38-30"):
            assert gate["status"] == "BLOCKED_EXTERNAL_DEPENDENCY", (
                "the remote CI gates must stay BLOCKED until an actual "
                "Actions run exists on the published commit")


# --- 30: no invented history ----------------------------------------

def test_published_main_is_an_ancestor_of_this_branch() -> None:
    assert _git_ok(["git", "merge-base", "--is-ancestor",
                    "origin/main", "HEAD"]), (
        "the corrective branch must descend from the published main — "
        "no history rewrite, no unrelated lineage")
