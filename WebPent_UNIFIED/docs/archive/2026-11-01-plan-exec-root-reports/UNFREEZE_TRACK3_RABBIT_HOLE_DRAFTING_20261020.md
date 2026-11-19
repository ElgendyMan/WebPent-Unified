# Unfreeze Applied — Parallel Rabbit Hole LLM-Drafting (Track 3)
**Date:** 2026-10-20
**Scope:** 2 frozen files unfrozen and live-wired to draft each approved Rabbit Hole
branch's "what to do next" LLM description concurrently instead of sequentially, in
`rabbit_hole_node` (`src/webpent/agents/rabbit_hole/agent.py`). All changes additive,
default-off. No behavior change when `enable_parallel_rabbit_hole_drafting` (default
`false`) is absent or false.

This follows the exact process and contract style of `UNFREEZE_TRACK2_PARALLEL_RECON_20261019.md`
(2026-10-19 Track 2 unfreeze) and `UNFREEZE_ARJUN_TRACK1_20261018.md` (2026-10-18 Track 1
unfreeze): documented diff review, manifest regeneration restricted to the touched paths,
real-code verification, and an explicit rollback path.

## 0. Why this file, and not `prioritization.py` or `curiosity_engine.py`

Per the handoff's Track 3 brief, this session read `src/webpent/shared/prioritization.py`
(1005 lines, in full), `src/webpent/agents/curiosity_engine.py` (152 lines, in full), and
`src/webpent/agents/strategist/agent.py` (737 lines, in full) before touching anything, to
find a *real* parallel-evaluation opportunity without breaking the deterministic-selection
philosophy `prioritization.py`'s own docstring states explicitly ("the actual comparison,
sorting, and selection of what to work on next is 100% deterministic arithmetic. No LLM
ever directly picks 'what happens next'").

Findings:

- **`prioritization.py`** (`score_hypothesis`, `rank_open_hypotheses`, `recommend_action`):
  every input (`_VULN_CLASS_TO_SEVERITY_RANK` lookup, `_evidence_quality_score`,
  `compute_novelty_bonus`, Mental Model criticality lookup) is a local dict lookup / pure
  computation — **no network I/O, no LLM call anywhere in the scoring or ranking path**.
  The sort itself is already a single `list.sort()` call on already-computed scores —
  there is nothing to parallelize; the entire pass is sub-millisecond for realistic
  hypothesis-pool sizes. Parallelizing CPU-only, already-fast local lookups would add
  thread-pool overhead for no measurable benefit, and risks race conditions on nothing
  (there's no shared mutable state inside the scoring path to begin with — see
  `_write_decision_log_entry`, which is already called sequentially per-decision from
  `strategist_node`, not from inside this module).
- **`curiosity_engine.py`**: explicitly documented as "This module observes only bounded
  route/event metadata. It never performs I/O." Confirmed by reading it in full — it is a
  single pass over already-collected route/event lists with `statistics.median` and string
  comparisons. Nothing to parallelize; it is not I/O-bound, and the full pass is bounded
  and cheap (no comparable LLM-latency problem Track 2's recon fan-out or Track 3's drafting
  step solve).
- **`strategist/agent.py`**: confirmed by grep — zero `llm.invoke`/`try_get_llm` call sites
  anywhere in the file. It is a pure consumer of `rank_open_hypotheses`'s already-scored,
  already-sorted output, iterating once to call `promote_hypothesis_to_finding` per
  threshold-cleared hypothesis. Matches its own docstring: "The LLM is NEVER asked to pick
  the action." Nothing to parallelize.
- **`rabbit_hole/agent.py`**: the ONE real I/O-bound, per-candidate-independent operation
  across all three files: `rabbit_hole_node`'s main loop calls `_draft_next_step_description`
  — a blocking `llm.invoke([...])` network round-trip — once per gate-approved candidate,
  bounded by `_MAX_BRANCHES_PER_PASS = 3`. Each draft call depends only on that one
  candidate's `(artifact_type, action_type, url, branch_depth)` — never on another
  candidate's draft, and (critically) the draft result influences nothing about which
  candidates get approved or in what order (it only becomes `Hypothesis.statement` text).
  This is exactly the same I/O-bound-and-independent shape Track 2 exploited for
  `subdomain_takeover_node`/`cloud_storage_node` — the opportunity Track 3 implements.

## 1. Files modified (2)

| # | File | Change | Default-off gate |
|---|------|--------|-------------------|
| 1 | `src/webpent/config/settings.py` | Added one new field, `enable_parallel_rabbit_hole_drafting: bool = Field(default=False, description=...)`, alongside `enable_parallel_recon` (Track 2) in the V55 additive-architecture flag block. Purely additive field declaration. | `enable_parallel_rabbit_hole_drafting` default `False` |
| 2 | `src/webpent/agents/rabbit_hole/agent.py` | (a) New import: `from concurrent.futures import ThreadPoolExecutor` (stdlib). (b) `rabbit_hole_node`'s single per-candidate loop is split into three phases — **Phase A** (sequential, UNCHANGED gate logic: Risk Manager check, scope re-check, forced-HITL check, in the same candidate order, mutating `current_branches`/`branches_entered` at the exact same logical point as before — immediately once a candidate clears every gate — instead of after Hypothesis construction; this is a bookkeeping-position move only, not a behavior change, since nothing reads `current_branches`/`branches_entered` between the old and new increment points) now appends an `approved` context dict (candidate + derived `branch_depth`/`parent_artifact_identity`/`in_scope`) per approved candidate instead of drafting inline; **Phase B** (new) drafts `_draft_next_step_description` for every approved candidate — sequentially, in original order, by default; when the flag is on, dispatches all of them to a `ThreadPoolExecutor` (`max_workers=min(len(approved), 3)`) and joins results back in the *original submission order* (`[future.result() for future in futures]`, matching the exact pattern already used by `src/webpent/shared/autonomous_controller.py`'s existing parallel-execution path); **Phase C** (the original Hypothesis/ledger/Goal-Tree/Decision-Log construction logic, byte-for-byte unchanged) now iterates `zip(approved, drafts)` instead of doing everything inline in Phase A. (c) Settings resolution for the flag is fail-closed, mirroring `_parallel_recon_enabled()` from Track 2: any `AttributeError`/`ImportError`/`KeyError`/`OSError`/`RuntimeError`/`TypeError`/`ValueError` while reading `get_settings().enable_parallel_rabbit_hole_drafting` resolves to `False` (sequential). | `enable_parallel_rabbit_hole_drafting=False` — when off, Phase B calls `_draft_for(entry)` in a plain list comprehension, one at a time, in the same order Phase A approved them — the exact same sequence of `llm.invoke()` calls, in the same order, that the pre-Track-3 single-pass loop made |

## 2. Why these 2 and not more

No other file was touched for Track 3. `curiosity_engine.py` and `strategist/agent.py`
were read in full (see §0) and found to have no I/O-bound, independent-per-item operation
worth parallelizing — touching them would have been complexity for no real benefit, exactly
the case the handoff's own Track 3 brief asked this session to rule out before implementing
anything ("يحدد هل فيه فرصة حقيقية لـ parallel evaluation... ولا الموضوع مش يستاهل
التعقيد ده").

`settings.py` is already in `TRACK1_ARJUN_THAW_PATHS` (Track 1's `arjun_*` fields) and
`TRACK2_PARALLEL_RECON_THAW_PATHS` (Track 2's `enable_parallel_recon` field). This is a
THIRD, separate edit (`enable_parallel_rabbit_hole_drafting`) on top of both — the
frozen-file gate pins file content by hash, not by field, so `settings.py`'s hash must be
regenerated again, exactly as it was for Track 2 on top of Track 1.

The same 10 agent/CLI/shared files already failing `test_frozen_file_byte_identical`
before this session (`agents/api_testing/agent.py`, `agents/business_logic_fuzzer/agent.py`,
`agents/cloud_storage/agent.py`, `agents/payload_generator/agent.py`,
`agents/subdomain_takeover/agent.py`, `agents/validator/active_checks.py`,
`agents/validator/postp0_checks.py`, `agents/validator/structural_checks.py`,
`cli/git_source.py`, `shared/jwt_deep_testing.py`) — the same group called out in
`UNFREEZE_ARJUN_TRACK1_20261018.md` §2 and `UNFREEZE_TRACK2_PARALLEL_RECON_20261019.md` §2 —
remain untouched and out of scope.

## 3. Why this is safe to parallelize without breaking determinism

The project's prioritization philosophy (`prioritization.py`'s module docstring, quoted in
§0) and Rabbit Hole's own design (`rabbit_hole/agent.py`'s module docstring: "the LLM's
only job is to draft a short description of what to do next — it does not decide whether
to proceed") both establish the invariant this change preserves: **the LLM never decides
anything; it only produces text after a decision has already been made deterministically.**
Track 3 changes nothing about *that* invariant — it only changes *when in wall-clock time*,
and on *which thread*, the already-decided candidates' draft text gets produced.

Concretely:

- **Which candidates are approved, and in what order they consume the branch/risk budget,
  is decided ENTIRELY by Phase A**, which is untouched sequential logic reading and
  mutating `current_branches`/`curiosity_budget_consumed` in the same per-candidate order
  as before. Phase B/C never influence this.
- **No candidate's draft depends on another candidate's draft or on call order.**
  `_draft_next_step_description` is a pure function of
  `(artifact_type, action_type, url, branch_depth, llm)` — none of which are shared mutable
  state across candidates.
- **The join-back is order-preserving, not first-come-first-served.** `zip(approved, drafts)`
  pairs each approved candidate with its own draft by list position, not by which thread
  finished first — `[future.result() for future in futures]` blocks on each future in
  submission order, exactly like the existing `autonomous_controller.py` pattern, so a
  slower candidate never gets a faster candidate's draft.
- **Decision Log / Goal Tree / ledger entries are still written sequentially, in the same
  order, by Phase C** — this change touches ONLY the wall-clock timing of the `llm.invoke()`
  network calls, nothing about audit-trail ordering or content.

## 4. Verification results

### 4.1 Real-code behavioral verification (no mocking of the gate/construction logic)

A standalone verification script (and the pytest suite in §4.2, which supersedes it) builds
a synthetic `PentestState` with 3 followable `archive`-type Mental Model artifact nodes on
the target's own host (so the scope-host-recheck branch is a no-op — `in_scope=True` from
the start) and calls the ACTUAL, unmodified `rabbit_hole_node` — not a reimplementation —
with a deterministic fake LLM stand-in (`_FakeLLM`) that records which thread invoked it
and sleeps 0.05s per call to simulate real network latency.

Results:
- **Sequential** (`enable_parallel_rabbit_hole_drafting=False`): 3 `llm.invoke()` calls, all
  on `MainThread`, **zero overlapping time intervals** (strictly serial), total wall time
  ≈0.183s (≈3 × 0.05s + overhead) — confirms the flag-off path is unchanged, one-at-a-time
  drafting.
- **Parallel** (`=True`): 3 `llm.invoke()` calls, each on its own
  `webpent-rabbit-hole-draft_N` pool thread, **intervals provably overlap** (confirmed by
  interval-overlap check, not just "it ran"), total wall time ≈0.064s — a ≈2.9× speedup,
  consistent with 3 calls of 0.05s running concurrently instead of serially.
- **Content equivalence**: both runs produced the SAME 3 Hypothesis statements (sorted,
  compared), the SAME 3 target URLs, the SAME ledger keys, the SAME Goal Tree branch count
  (3), and the SAME set of Decision Log `rule_fired` strings — the only difference between
  the two runs is wall-clock time and which thread executed each draft call, exactly as
  §3 argues it should be.

### 4.2 New pytest suite

`tests/test_vip_rabbit_hole_parallel_drafting.py` — **7/7 PASS**:
1. `test_parallel_drafting_disabled_by_default_runs_sequentially` — flag off: 3 calls, zero
   overlap, all on `MainThread`.
2. `test_parallel_drafting_enabled_runs_concurrently_and_faster` — flag on: 3 calls on 3
   distinct pool threads, intervals overlap, total time `< 0.15s` (vs. 3×0.05s serial).
3. `test_parallel_drafting_fails_closed_on_settings_error` — `get_settings()` raising
   `RuntimeError` still produces 3 non-overlapping (sequential) calls — confirms the
   fail-closed settings read never silently enables concurrency.
4. `test_sequential_and_parallel_produce_equivalent_results` — statements, URLs, ledger
   keys, Goal Tree node count, and Decision Log rule set are identical between the two
   modes.
5. `test_parallel_drafting_respects_max_branches_per_pass_cap` — 10 followable artifacts
   offered, only 3 branches entered/drafted either way (the cap is enforced in the
   untouched Phase A loop, before Phase B ever runs).
6. `test_no_followable_artifacts_skips_drafting_entirely` — zero candidates -> zero LLM
   calls, `approved` stays empty, Phase B's `ThreadPoolExecutor` branch is never entered
   (guarded by `len(approved) > 1`).
7. `test_hypothesis_construction_failure_propagates_like_legacy_code` — **added after an
   adversarial self-review** (2026-10-21) flagged that moving
   `branches_entered`/`current_branches` from the end of the original single-pass loop
   (after `Hypothesis(...)` succeeded) to immediately after Phase A's gates (before Phase
   C's `Hypothesis(...)` call) could theoretically change behavior if construction ever
   failed. Monkeypatches `Hypothesis` to raise `ValueError`, and asserts the same
   `ValueError` propagates all the way out of `rabbit_hole_node` — proving, not just
   arguing from a code read, that neither the old nor the new code has a try/except
   around `Hypothesis(...)` construction, so a construction failure crashes the whole
   node identically in both versions (no partial state, no swallowed exception) and the
   moved counters are never observed by anything before that crash.

### 4.3 Frozen hash gate

Before this regeneration, `tests/test_frozen_module_gate.py::test_frozen_file_byte_identical`:
**11 failed** (10 pre-existing, unrelated — see §2 — plus `src/webpent/config/settings.py`,
newly drifted by the `enable_parallel_rabbit_hole_drafting` field), 699 passed.
(`src/webpent/agents/rabbit_hole/agent.py` was NOT masked by any pre-existing skip list —
unlike `graph/builder.py` in Track 2 — so it failed outright, exactly as expected for an
undocumented frozen-file edit; this is the gate working correctly.)

After regeneration (manifest hashes updated for exactly `src/webpent/agents/rabbit_hole/agent.py`
and `src/webpent/config/settings.py`, plus this file's own thaw-set addition to
`tests/test_frozen_module_gate.py`): both files return to byte-identical status against the
regenerated manifest; the same 10 pre-existing failures are unchanged — **10 failed, 700
passed, 0 skipped**.

Verified with both `sha256sum --check --ignore-missing frozen_modules.sha256` (direct
manifest check) and `pytest tests/test_frozen_module_gate.py` — same result from both.

### 4.4 Zero behavior change when disabled

- `enable_parallel_rabbit_hole_drafting` defaults to `False` — Phase B's
  `if _parallel_drafting and llm is not None and len(approved) > 1:` branch is never taken;
  `drafts = [_draft_for(entry) for entry in approved]` runs the exact same sequence of
  `llm.invoke()` calls, in the exact same order, that the pre-Track-3 inline-drafting code
  made inside the single loop.
- The `ThreadPoolExecutor` import and construction only execute when the flag is explicitly
  on AND more than one candidate was approved (`len(approved) > 1` — a single approved
  candidate gains nothing from a thread pool and runs the plain sequential path instead).
- Settings resolution fails closed: any error reading
  `get_settings().enable_parallel_rabbit_hole_drafting` resolves to `False` (sequential),
  mirroring Track 2's `_parallel_recon_enabled()` fail-closed contract exactly — confirmed
  by `test_parallel_drafting_fails_closed_on_settings_error`.
- `full build_graph(auto_approve=True)` compiles to the same **48 nodes** as before (Track 3
  does not touch graph topology at all — `rabbit_hole_node`'s function signature and
  return-dict shape are unchanged; only its internal implementation was restructured).

## 4.5 Adversarial self-review (2026-10-21)

After the initial implementation and verification (§4.1–§4.4), this work was independently
re-reviewed — explicitly looking for bugs, not confirming the implementer's own claims. The
review covered: the `rabbit_hole_node` diff line-by-line; whether `approved`/`drafts` could
ever desync in length or position under `ThreadPoolExecutor`; whether moving
`branches_entered`/`current_branches` from the end of the old single-pass loop to the end of
Phase A changes observable behavior; whether this unfreeze doc's claims match the code;
whether the test suite actually covers the scenario the review was most worried about; the
frozen-gate state; and whether `graph/builder.py` depends on any assumption about
`rabbit_hole_node`'s return shape that changed.

Findings:

- **`approved`/`drafts` length/order mismatch under concurrency — ruled out, not a bug.**
  `pool.submit()` calls happen sequentially on the main thread while building the `futures`
  list (only the submitted work runs concurrently); `[future.result() for future in futures]`
  then blocks on each future in that same fixed list order regardless of which one finishes
  first. `len(approved) == len(drafts)` and positional correspondence via `zip(approved,
  drafts)` are therefore guaranteed in every case, including the empty-`approved` case.
- **Bookkeeping-position move (`branches_entered`/`current_branches`) — PLAUSIBLE concern,
  ruled out after inspection, then converted into an executable test.** Neither the
  pre-Track-3 nor the post-Track-3 code wraps `Hypothesis(...)` construction (Phase C) in a
  `try`/`except`, and `graph/builder.py`'s `_trace_wrap` calls the node function with no
  protective `try`/`except` either — so a construction failure propagates all the way out of
  `rabbit_hole_node` identically in both versions, with no partial return in either case.
  The moved counters are local variables never observed by anything before that crash. This
  conclusion was initially reached by manual code reading only; `test_hypothesis_construction_
  failure_propagates_like_legacy_code` (added to `tests/test_vip_rabbit_hole_parallel_
  drafting.py`, §4.2 item 7) now proves it by monkeypatching `Hypothesis` to raise and
  asserting the exception reaches the caller unmodified, rather than leaving it as an
  unverified claim.
- **Frozen gate and `graph/builder.py` — no issue.** Re-ran both `sha256sum --check
  --ignore-missing frozen_modules.sha256` and `pytest tests/test_frozen_module_gate.py` after
  the review; same 10 pre-existing failures only, 700 passed, 0 skipped. `graph/builder.py`
  has exactly one call site for `rabbit_hole_node` (via the standard `_trace_wrap`), and does
  not inspect or depend on any particular shape of its return dict beyond the keys it already
  documented (`hypotheses`, `rabbit_hole_ledger`, `goal_tree`, `mental_model`,
  `decision_log`, `messages`, `current_phase`) — all unchanged.
- **This document's claims — re-checked against the code, no inaccuracies found.** In
  particular, "Phase C... byte-for-byte unchanged" (§1, row 2) refers to the construction
  logic inside the loop body, not the position of the `branches_entered`/`current_branches`
  increments (which are explicitly called out as moved, in the same row) — re-read for
  ambiguity and left as-is since the distinction is already explicit in the text.

## 5. Rollback

Remove the `enable_parallel_rabbit_hole_drafting` field from `settings.py`; in
`rabbit_hole/agent.py`, remove the `ThreadPoolExecutor` import, collapse Phase A/B/C back
into the single original loop (move the Hypothesis/ledger/Goal-Tree/Decision-Log
construction block back inside the gate-checking loop, immediately after the inline
`_draft_next_step_description` call, and move the `branches_entered += 1` /
`current_branches += 1` increments back to the end of that single loop); remove the
`TRACK3_RABBIT_HOLE_DRAFTING_THAW_PATHS` entry from `tests/test_frozen_module_gate.py`;
regenerate `frozen_modules.sha256` for both files against that reverted content. No data
migration, no persistent state, no DB schema change — this is a pure control-flow
restructuring plus one new settings field.
