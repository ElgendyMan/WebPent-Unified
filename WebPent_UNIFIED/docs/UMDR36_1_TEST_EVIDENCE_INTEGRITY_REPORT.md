# UM-DR-36.1 Test Evidence Integrity Report

Generated: 2026-11-14T11:14:05.953756+00:00 | HEAD: `0d9511f325a215a6fc7dd6228b966f710dd4fc7d`

## The eliminated defect (§4)

The published `docs/FULL_SUITE_EVIDENCE.txt` was dated **2026-10-28**, from a retired workspace path, reporting **6,713 collected** tests, and `check_test_evidence.py` accepted it because it only checked that a file existed and contained six text markers — an old evidence file passed as proof of a current run while CI failed before the tests even started.

## The new contract (implemented)

- `scripts/run_tests_with_evidence.py` (rewritten): deletes any pre-existing evidence BEFORE the run (a failed/interrupted run cannot leave an old green file behind); parses pytest's own final session summary (never progress lines); verifies the accounting mathematically (`executed == passed+failed+errors+skipped+xfailed+xpassed`, `collected == executed+deselected`); writes BOTH the human transcript and a machine record `docs/FULL_SUITE_EVIDENCE.json` carrying: source commit, tree clean/dirty state, GitHub run id/attempt, UTC start/completion, Python/uv versions, lockfile SHA-256, exact command, test-scope digest, full outcome counts, coverage result + floor, exit code. Unparseable/inconsistent accounting fails the run (fail-closed).
- `scripts/check_test_evidence.py` (rewritten): validates schema, complete accounting + math, **evidence commit == current HEAD** (stale evidence fails), **workflow run id/attempt == current run** when under GitHub Actions, recorded exit code 0, sane timestamps. There is no path where a run that did not execute (or failed) validates.
- `.github/workflows/ci.yml`: new explicit "Remove stale test evidence" step before the suite; the `if: always()` checker step is now safe because it validates provenance, not existence.
- Adversarial suite: `tests/test_umdr36_1_test_evidence_integrity.py` (17 tests — stale commit, wrong workflow run/attempt, hand-written evidence, failed-run evidence, collected-as-executed, unverified accounting, reversed timestamps, …) — **all passed** in this environment (with the provenance suite, 40 of 40 new tests green).

## Full-suite run state (honest)

- Suite state at handoff: **completed_with_failures**.
- Collected 9141, executed 9142, passed 9019, failed 101, skipped 12, xfailed 3, xpassed 0, errors 7, exit 1, at commit b3997c9158df.
- The committed stale 2026-10-28 evidence is superseded: the runner deletes it at start; the repo carries only run-generated evidence from now on.

## BUILD_INFO / provenance (§3)

- `scripts/check_build_info_honesty.py` redesigned around the genuine baseline `1968f63` (the old `v15.2-audit-baseline` tag does not exist in the public repository and could never pass). New machine-readable provenance schema (`umdr36-1-provenance-v1`): source/tested/evidence revisions (must be resolvable commits), recovery baseline, manifest digest (must equal the ACTUAL sha256 of `frozen_modules.sha256`), package version, full test accounting, build date, publication metadata; release-history sanity (history strictly older; unresolvable local lineage only with an explicit null+note); stability discipline (one declared re-baseline, then qualifying re-freezes only).
- Adversarial suite: `tests/test_umdr36_1_build_info_provenance.py` — **23/23 passed**.
- The BUILD_INFO.json re-baseline commit itself is **pending the completed full-suite run** (its provenance block must carry the real measured accounting). It was intentionally not fabricated.
