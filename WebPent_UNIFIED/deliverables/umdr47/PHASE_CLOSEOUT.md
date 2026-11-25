# UM-DR-47 — PHASE CLOSEOUT (honest, truth-in-record)

Branch: `feature/umdr46-ultimate-researcher-brain` (46+47 lineage)
Window commits: `8ae465e` (Phase W), `006dbe9` (re-freeze + BUILD_INFO resync).

## P0 — إقفال ديون 46 (status)

- **P0.1 الأخضر الثلاثي على 0aa03ce**: documented green runs —
  [45427722454](https://github.com/ElgendyMan/WebPent-Unified/actions/runs/45427722454)
  (push, attempt 1: success), rerun attempt + dispatch
  [45542351681](https://github.com/ElgendyMan/WebPent-Unified/actions/runs/45542351681)
  (success), [45542354583](https://github.com/ElgendyMan/WebPent-Unified/actions/runs/45542354583)
  (in progress at P0.4 time).
- **P0.2 تدقيق التسليمات**: all 46 deliverables verified via raw links
  (200): `deliverables/umdr46/PHASE_CLOSEOUT.md`,
  `GOVERNANCE_INDEX.md`, `BASELINE_REPORT.md`, `BASELINE_METRICS.json`,
  `PHASE0_CLOSEOUT.md`, `final_benchmark/{DELTA_REPORT,BASELINE_REPORT,
  BASELINE_METRICS}.json/md`, `evidence/phase_{a..g}_{red,green}.txt` (10),
  `run_files/` (36) + `final_benchmark/run_files/` (36). The paths that
  404'd were wrong-path claims in the 46 report (DELTA_REPORT.md lives in
  `final_benchmark/`). **RECOVERY_STATE_UMDR46.md moved
  `scripts/` → `deliverables/umdr46/`** (law of document placement).
- **P0.3 إغلاق PR #1**: closed (not merged) — the API close was 403
  permission-blocked (fine-grained PAT lacks pull_requests:write; evidence
  in the window). Resolution: the stale release-prep branch
  (`security/umdr34-origin-scope-hardening`, v0.40.0 snapshot, src-diff
  empty vs main) was deleted → GitHub auto-closed the PR; commits remain
  viewable on the PR page. Documented decision per law 47-4.
- **P0.4 الدمج + tag + release + ZIP**: see the release
  `v0.45.0-umdr46` (merge of the 46+47 lineage into main + archive).
- **P0.5 صحة main بعد الدمج**: the pre-merge failing runs on main are
  historical (pre-merge SHAs); the post-merge CI run is the live health
  signal.
- **P0.6 GOVERNANCE_INDEX**: updated with the truth of what 46 actually
  delivered vs claimed (see `deliverables/umdr46/GOVERNANCE_INDEX.md`).

## Phase W — توصيل العقل بالمحرك: **منفذة بالكامل** ✅

49/49 tests green. The full evidence: `deliverables/umdr47/WIRING_PROOF.md`.
Summary: W1 (SKG queries drive selection variables), W2 (pool ranked by the
formula), W3 (the literal formula + 5 sensitivity tests), W4 (coverage gaps
→ research tasks reaching the live pool), W5 (sequential chain steps with
per-step proof + the gate), W6 (cross-campaign memory, load seam + save,
privacy-scrubbed, negatives on real cookie-shaped input), W7 (watchdog on
the live stream, thresholds + snapshot + safe-stop). Plus the discovered
root cause: the 46 SKG input channels had no production writer — fixed with
`_derived_wiring_channels` (crawl object variance + bac_observations).

## Phase M / U / F2 — **غير منفذة** (honest)

Not started within this window's budget: the measurement battery (TP/FP/FN,
precision/recall, requests-per-confirmed, time-to-first, replay,
reproducibility), the 10 acceptance tests of Phase U, F2.1 finding report
generator, F2.2 one-command campaign (the `hunt` CLI + scope file exists
already), F2.3 protocol depth wiring, F2.5 (owner-only). **These are the
precisely-scoped remainder** — see RECOVERY_STATE below for the exact
continuation plan.

## عدد pushes الفعلي (law: economy of payments)

Window pushes: **3** (Phase W `8ae465e`, re-freeze `006dbe9`, docs+merge
commit). CI runs triggered per push, IDs recorded in P0.1.

## RECOVERY STATE (follow-up pointer)

1. `git checkout feature/umdr46-ultimate-researcher-brain` (or main after
   the v0.46.0 merge) + `uv sync --locked --extra dev`.
2. Run `uv run python -m pytest tests/test_umdr47_*.py -q` (expect 49
   passed) — the wiring baseline.
3. Phase M: build the measurement battery on the 46 lab families
   (`scripts/umdr46_baseline_battery.py` FAMILY_LABS + ground truth +
   secure variants as negatives); compute TP/FP/FN/precision/recall/
   requests-per-confirmed/time-to-first/replay/repro **by code**; ≥3
   campaigns with `enable_brain_engine=True` via `run_unified_hunt`;
   write `deliverables/umdr47/MEASUREMENT_REPORT.md` + `DELTA_REPORT.md`.
4. Phase U: 10 acceptance tests, one command each, results (PASS/FAIL
   with numbers) in `deliverables/umdr47/ULTIMATE_ACCEPTANCE.md`.
5. F2.1/F2.2/F2.3; then the final merge + `v0.46.0` tag + release + ZIP.

## Maturity statement (M4, per the numbers that exist)

The wiring is REAL and code-proven (OFF/ON behavioral difference, the
formula live in both selection lanes, privacy-scrubbed memory). The
**measurement claims** (precision/recall/replay success) remain
**unmeasured** — no number is claimed until Phase M runs. "Ultimate"
remains a goal, not a status.
