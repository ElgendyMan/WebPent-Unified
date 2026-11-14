# Round-3 War Games — the Verdict package (WG1, WG2, WG3, WG5)

_Date: 2026-10-18. PoC: `docs/reviews/round3_poc/wg_verdict.py`, transcript
in `docs/reviews/round3_poc/run.log`. Every attack below was executed
against a real workspace, not argued on paper._

## WG1 — Submission bypass

Could the tool submit anything without the operator's hands?

- **WG1.1** `submit F-1 --auto` → `exit=2  Error: No such option '--auto'.`
  The flag does not exist.
- **WG1.2** planted `auto_submit: true` in `state.json`, retried `--auto`
  → same `exit=2`. The CLI does not read planted flags.
- **WG1.3** external script importing `SubmissionPipeline` with every
  socket method monkeypatched to raise: pipeline exposes `generate_report`,
  `get_tracker`, `preview`, `record_submission`, `state`, `write_report`,
  `ws` — **network-capable methods: NONE**.

**Result: BLOCKED.** The pipeline is a notebook, as claimed. No fix needed.

## WG2 — Pre-registration rewrite

- **WG2.1 (baseline)** `predict` then `done` → `exit=0`,
  `pre_registration.md hash: 492d20c403676cee…` (hash recorded by us, not
  the tool).
- **WG2.2 ATTACK** re-predict after the freeze → **`exit=0` — allowed.**
  Predictions read `[1, 2]`, `[0.9, 1.0]` after results were known.
  → **F-2 CONFIRMED (HIGH).**
- **WG2.3 ATTACK** edit `pre_registration.md` after the freeze → file
  hash moved to `4b85f14d72b980b8…`; detection: **NONE** — the tool never
  recorded the file hash and the `pre_registered` flag stayed true.
  → **F-3 CONFIRMED (HIGH).**

## WG3 — FP laundering

- **WG3.1** reclassify an FP back to confirmed → `exit=1  Error: finding
  F-6 is already classified as false_positive; classifications are
  immutable.` **BLOCKED** at the classifier level.
- **WG3.2 ATTACK** fresh id + evidence path that does not exist →
  **`exit=0` — confirmed.** `RESULT: evidence path NOT verified —
  laundering possible.` The evidence list is free text.
  → **F-4 CONFIRMED (MEDIUM-HIGH).**
- **WG3.3** duplicate `finding_id` → `exit=1`, dedup enforced. **BLOCKED.**

## WG5 — Metrics manipulation

- **DET (baseline)** same state → report 3× → hashes `534935b16b506e31`,
  same, same. **Deterministic.**
- **WG5.3 (baseline)** one legitimate accept → `final verdict: IMPROVE —
  1 accepted — focus on core quality`.
- **WG5.4 ATTACK** hand-edit `state.json`, forge 3 accepted watch entries
  → **`final verdict: GO — 3+ accepted findings — tool is validated`**
  from a forged file, while the honest path said IMPROVE. Tamper
  detection: **NONE.** → **F-1 CONFIRMED (CRITICAL).**
- **WG5.5 ATTACK** delete the FP entry from `state.json` → GO again; the
  FP silently leaves the FP-rate computation. Same root cause as F-1.

## Findings carried out of this document

| ID | Severity | One line |
|---|---|---|
| F-1 | CRITICAL | state.json has zero tamper detection; a forged file issues GO |
| F-2 | HIGH | predictions can be rewritten after the freeze |
| F-3 | HIGH | pre_registration.md has no recorded hash; edits are invisible |
| F-4 | MEDIUM-HIGH | classify() never verifies evidence paths exist |
| F-5 | MEDIUM | selection can be re-frozen with a different set (verified in the axis sweep, fixed with F-1..F-7) |

Fixes and their red-first tests: `tests/test_round3_fixes.py` in the
verdict package; see round3_verdict.md for the before/after re-run.
