#!/usr/bin/env python3
"""Fail closed unless complete, CURRENT-run, provenance-bound test evidence exists.

UM-DR-36.1 §4 — the previous checker only verified that a text file
existed and contained a few markers, which meant an evidence file left
behind by an earlier workflow (or a local run months old) passed as
proof of a current test run. This checker validates that the evidence

  1. exists as a machine-readable record with the expected schema,
     produced by scripts/run_tests_with_evidence.py;
  2. records a COMPLETE accounting (collected, executed, passed,
     failed, skipped, xfailed, xpassed, errors, deselected) whose math
     verifies: executed == passed+failed+errors+skipped+xfailed+xpassed
     and the collected == executed+deselected terminal equation ONLY
     when no collection-phase reports exist (§3.6: the hook-level v3
     model is authoritative; a v2 equation disagreement explained by
     recorded collection errors/skips, with green v3 invariants and a
     green terminal cross-check, does not fail);
  3. belongs to the CURRENT source revision — the recorded commit must
     equal this checkout's HEAD (a stale evidence file from another
     commit fails);
  4. belongs to the CURRENT workflow execution when running under
     GitHub Actions — the recorded run id and attempt must match the
     GITHUB_RUN_ID / GITHUB_RUN_ATTEMPT environment values;
  5. records a successful run (exit code 0) — evidence of a failed or
     skipped test run never validates green;
  6. records sane timestamps (completion not before start).

A missing evidence file fails. An old evidence file fails. Evidence
from the right commit but a different workflow run fails in CI. There
is no path where a run that did not execute (or failed) validates.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = Path(os.environ.get("WEBPENT_EVIDENCE_DIR")
                    or (ROOT / ".webpent-evidence"))
EVIDENCE_JSON = EVIDENCE_DIR / "FULL_SUITE_EVIDENCE.json"
EVIDENCE_TXT = EVIDENCE_DIR / "FULL_SUITE_EVIDENCE.txt"
EXPECTED_SCHEMA = "full-suite-evidence/v3"
LEGACY_SCHEMA = "full-suite-evidence/v2"
EXPECTED_RUNNER = "run_tests_with_evidence.py"
REQUIRED_COUNTS = ("collected", "executed", "passed", "failed", "skipped",
                   "xfailed", "xpassed", "errors", "deselected")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _git_head() -> str:
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                       capture_output=True, text=True, check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


def _current_lockfile_sha() -> str:
    """SHA-256 of the CURRENT uv.lock (empty when absent) — the freshness
    anchor for §6.3: evidence recorded against a different lockfile is
    stale and must not validate."""
    import hashlib

    lockfile = ROOT / "uv.lock"
    if not lockfile.is_file():
        return ""
    h = hashlib.sha256()
    with open(lockfile, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# UM-DR-38.2 §1.6 — the NARROW, explicit, reviewed path-level policy.
# Every entry carries its rationale. Anything NOT listed invalidates the
# evidence: src/, tests/, scripts/ (runner, checkers, gates, report
# generators), .github/ (workflows), pyproject.toml, uv.lock, Makefile,
# configuration. The previous broad directory allowances (scripts/,
# .github/, docs/) were REMOVED — a change to the test runner, an
# evidence checker, a gate or a workflow can affect the validity of the
# test evidence and must fail freshness.
_METADATA_ALLOW = (
    # repository entrypoint documentation (no executable effect)
    "README.md",
    # project documentation / release notes (no executable effect)
    "WebPent_UNIFIED/README.md",
    "WebPent_UNIFIED/CHANGELOG.md",
    # the declared-drift ritual register (documentation)
    "WebPent_UNIFIED/DRIFT_REGISTER.md",
    # DERIVED release metadata — the BUILD_INFO re-baseline is the
    # documented metadata-only follow-up to a green evidence run
    "BUILD_INFO.json",
    "WebPent_UNIFIED/BUILD_INFO.json",
    # generated mission deliverables + the durable evidence copies
    "deliverables/",
    "WebPent_UNIFIED/deliverables/",
    # generated SBOM + non-executable historical engineering reports
    "WebPent_UNIFIED/docs/",
)


def _metadata_only_delta(commit: str, head: str) -> bool:
    """UM-DR-38.1: True when commit is a real ancestor of head and
    every path changed since touches METADATA only — the documented
    test-commit vs metadata-commit relationship (BUILD_INFO
    re-baselines and generated deliverables follow the evidence; they
    never invalidate it). Any src/tests/pyproject/uv.lock change keeps
    the evidence STALE."""
    if not commit or not head or commit == head:
        return commit == head
    anc = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, head],
        cwd=ROOT, capture_output=True)
    if anc.returncode != 0:
        return False
    diff = subprocess.run(
        ["git", "diff", "--name-only", commit, head],
        cwd=ROOT, capture_output=True, text=True)
    for line in diff.stdout.splitlines():
        if not line:
            continue
        if not any(line == a or line.startswith(a)
                   for a in _METADATA_ALLOW):
            return False
    return True


def evaluate(record: dict, *, head: str, env: dict[str, str],
             expected_lockfile_sha: str = "") -> list[str]:
    """Return the list of failures (empty list == evidence validates)."""
    failures: list[str] = []

    if record.get("schema") not in (EXPECTED_SCHEMA, LEGACY_SCHEMA):
        failures.append(f"schema is {record.get('schema')!r}, "
                        f"expected {EXPECTED_SCHEMA!r} or {LEGACY_SCHEMA!r}")
    if record.get("runner") != EXPECTED_RUNNER:
        failures.append(f"runner is {record.get('runner')!r}, expected "
                        f"{EXPECTED_RUNNER!r} (hand-written evidence is not "
                        "accepted)")

    commit = str(record.get("source_commit", ""))
    if not _HEX40.match(commit):
        failures.append(f"source_commit is not a 40-hex sha: {commit!r}")
    elif head and commit != head and not _metadata_only_delta(
            commit, head):
        failures.append(
            f"evidence belongs to commit {commit}, but this checkout "
            f"is {head} — STALE evidence from a different source "
            "revision (an ancestor is accepted ONLY when every change "
            "since it is in the NARROW metadata policy: BUILD_INFO, "
            "deliverables, README/CHANGELOG/DRIFT_REGISTER, docs — "
            "scripts/workflows/src/tests/lockfile changes invalidate)")
        # else: an ancestor with a metadata-only delta — the documented
        # test-commit vs metadata-commit relationship; the evidence
        # stays fresh

    run_env_id = env.get("GITHUB_RUN_ID")
    recorded = record.get("github")
    if run_env_id:
        if not isinstance(recorded, dict):
            failures.append("running under GitHub Actions but the evidence "
                            "records no workflow identity")
        else:
            if str(recorded.get("run_id")) != run_env_id:
                failures.append(
                    f"evidence workflow run {recorded.get('run_id')!r} != "
                    f"current run {run_env_id!r}")
            attempt = env.get("GITHUB_RUN_ATTEMPT")
            if attempt and str(recorded.get("run_attempt")) != attempt:
                failures.append(
                    f"evidence workflow attempt "
                    f"{recorded.get('run_attempt')!r} != current attempt "
                    f"{attempt!r}")

    accounting = record.get("accounting")
    if not isinstance(accounting, dict):
        failures.append("accounting block missing")
        return failures
    missing = [k for k in REQUIRED_COUNTS
               if not isinstance(accounting.get(k), int)]
    if missing:
        failures.append(f"accounting missing integer counts: {missing}")
    else:
        a = accounting
        # §3.6 contract (same as the runner's evidence_gate_ok): the
        # hook-level v3 accounting is AUTHORITATIVE. The legacy v2
        # terminal equation (collected == executed + deselected) is
        # only well-formed with ZERO collection-phase reports; when the
        # v3 block records collection errors/skips, its disagreement
        # (and the runner's accounting_consistent=False) is EXPLAINED —
        # provided the v3 invariants hold and the terminal cross-check
        # agrees. Never bypassed: an UNEXPLAINED v2 disagreement, a
        # missing/violated v3, or a disagreeing cross-check still
        # fails.
        v3 = record.get("accounting_v3")
        v3 = v3 if isinstance(v3, dict) else {}
        collection_phase_reports = (
            int(v3.get("collection_errors") or 0)
            + int(v3.get("collection_skips") or 0)
        )
        v3_green = (
            bool(v3)
            and bool(v3.get("invariants_all_true"))
            and bool((record.get("accounting_cross_check") or {}).get(
                "all_agree"))
        )
        v2_explained = v3_green and collection_phase_reports > 0

        total = (a["passed"] + a["failed"] + a["errors"] + a["skipped"]
                 + a["xfailed"] + a["xpassed"])
        if a["executed"] != total:
            failures.append(
                f"executed {a['executed']} != passed+failed+errors+skipped"
                f"+xfailed+xpassed {total}")
        if a["collected"] != a["executed"] + a["deselected"] \
                and not v2_explained:
            failures.append(
                f"collected {a['collected']} != executed+deselected "
                f"{a['executed'] + a['deselected']}"
                + ("" if not v2_explained else
                   " (explained by collection-phase reports; v3 governs)"))
        if not accounting.get("accounting_consistent") \
                and not v2_explained:
            failures.append("runner could not verify the accounting against "
                            "the pytest session summary")
    if not accounting.get("summary_found"):
        failures.append("no pytest session summary line was captured — the "
                        "test run did not produce a final summary")

    exit_code = record.get("exit_code")
    if exit_code != 0:
        failures.append(f"recorded test exit code is {exit_code!r}, not 0 — "
                        "evidence of a failed run never validates")

    # ---- UM-DR-38 §6.3: provenance completeness + freshness ----------
    for key in ("python_version", "uv_version", "command",
                "test_scope_digest"):
        if not record.get(key):
            failures.append(f"provenance field {key!r} missing")
    lockfile_sha = str(record.get("lockfile_sha256") or "")
    if not lockfile_sha:
        failures.append("lockfile_sha256 missing — evidence without the "
                        "lockfile digest cannot prove its environment")
    elif expected_lockfile_sha and lockfile_sha != expected_lockfile_sha:
        failures.append("lockfile_sha256 does not match the CURRENT "
                        "uv.lock — stale evidence from a different "
                        "dependency state")
    cov = record.get("coverage") or {}
    if cov.get("floor_percent") is not None:
        percent = cov.get("percent_covered")
        if percent is None or float(percent) < float(cov["floor_percent"]):
            failures.append(f"coverage {percent!r} does not satisfy the "
                            f"required floor {cov['floor_percent']!r}")
    # NOTE: the GitHub workflow run/attempt identity checks (§6.3) live
    # earlier in evaluate() — they predate UM-DR-38 and already reject a
    # missing or mismatched workflow identity under CI.

    # ---- v3: hook-level accounting invariants + terminal cross-check ----
    if record.get("schema") == EXPECTED_SCHEMA:
        v3 = record.get("accounting_v3")
        if not isinstance(v3, dict):
            failures.append("v3 evidence requires the hook-level "
                            "accounting_v3 block (pytest_accounting_plugin)")
        else:
            if not v3.get("invariants_all_true"):
                failures.append(
                    f"v3 accounting invariants violated: {v3.get('invariants')}")
            if v3.get("interrupted"):
                failures.append("v3 accounting records an INTERRUPTED run")
            if v3.get("not_started"):
                failures.append(
                    f"v3 accounting records {v3['not_started']} collected "
                    "items that never started")
            outcomes = v3.get("outcomes") or {}
            if v3.get("started_items") != (
                    sum(outcomes.values()) + v3.get("setup_errors", -1)):
                failures.append("v3 started_items != outcomes + setup_errors")
        cross = record.get("accounting_cross_check")
        if not isinstance(cross, dict) or not cross.get("plugin_available"):
            failures.append("v3 evidence missing the hook-level/terminal "
                            "cross-check")
        elif not cross.get("all_agree"):
            failures.append(
                f"hook-level accounting disagrees with the terminal summary: "
                f"{cross.get('disagreements')}")

    started = str(record.get("started_at_utc", ""))
    completed = str(record.get("completed_at_utc", ""))
    if not started or not completed:
        failures.append("start/completion timestamps missing")
    elif completed < started:
        failures.append("completion timestamp precedes start timestamp")

    return failures


def main() -> int:
    if not EVIDENCE_JSON.is_file():
        print(f"FAIL: missing machine-readable evidence {EVIDENCE_JSON}")
        print("The evidence is generated by "
              "scripts/run_tests_with_evidence.py; a run that did not "
              "execute produces no acceptable evidence.")
        return 1
    try:
        record = json.loads(EVIDENCE_JSON.read_text(encoding="utf-8"))
    except ValueError as exc:
        print(f"FAIL: evidence JSON unparseable: {exc}")
        return 1
    if not EVIDENCE_TXT.is_file():
        print(f"FAIL: human-readable transcript missing ({EVIDENCE_TXT})")
        return 1

    failures = evaluate(record, head=_git_head(), env=dict(os.environ),
                        expected_lockfile_sha=_current_lockfile_sha())
    if failures:
        print(f"test_evidence: GATE FAILURE ({len(failures)})")
        for f in failures:
            print(f"  - {f}")
        return 1
    a = record["accounting"]
    print("test_evidence: PASS — current-run evidence verified "
          f"(commit {record['source_commit'][:12]}, "
          f"collected {a['collected']}, executed {a['executed']}, "
          f"passed {a['passed']}, failed {a['failed']}, "
          f"skipped {a['skipped']}, xfailed {a['xfailed']}, "
          f"xpassed {a['xpassed']}, errors {a['errors']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
