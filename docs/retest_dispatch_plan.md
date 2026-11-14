# Round-5 Execution Plan — Re-test Dispatch Engine

_Date: 2026-10-19. Executed step by step in this order; each step gates the next._

## Step 1 — Red tests (write first, watch them fail)

In `tests/test_verdict_bridge.py`, add `TestReplayRecipeCapture` and
`TestDispatchRetest` (~12 tests):

1. `test_evidence_payload_carries_replay_recipe` — a promoted finding with
   a `request_sequence` registers with a `replay_recipe` in its evidence
   JSON: the three roles (baseline, candidate, negative_control), each with
   method and url, plus experiment_id and vulnerability_class.
2. `test_evidence_without_request_sequence_has_null_recipe` — no sequence →
   `replay_recipe is None`; registration still succeeds.
3. `test_dispatch_retest_reads_recipes_from_workspace_evidence` — after
   `register_campaign_findings`, `dispatch_retest` with no in-memory result
   finds the finding from `evidence/` alone (day-14 reality).
4. `test_dispatch_retest_blocks_real_target_without_frozen_prereg` — real
   target + unfrozen workspace → `VerdictGateError` (fail-closed, same gate
   as the campaign).
5. `test_dispatch_retest_loopback_exempt` — loopback target dispatches with
   the frozen workspace; gate recorded as `exempt_loopback`.
6. `test_dispatch_retest_executes_triple_via_executor` — a stub executor
   sees exactly the recipe's (method, url) calls in recipe order; per-role
   status codes and SHA-256 response digests land in the retest evidence.
7. `test_dispatch_retest_writes_retest_evidence_file` —
   `evidence/<id>.retest.json` exists, `source == "retest_dispatch"`, and
   carries the observations plus `candidate_differs_from_baseline`.
8. `test_dispatch_retest_missing_recipe_is_typed_blocker` — a registered
   finding without a recipe lands in `blocked`, others still dispatch.
9. `test_dispatch_retest_executor_failure_is_typed_blocker` — executor
   raises → blocked with the reason; no retest evidence file left behind.
10. `test_dispatch_retest_never_invokes_classify` — source-level: the
    bridge contains no `classify` invocation; and the retest evidence JSON
    contains no classification/confirmed keys — observations only.
11. `test_dispatch_retest_summary_carries_operator_handoff` — per finding,
    a ready-to-run `findings classify` command string with `-e` paths for
    the retest + original evidence and classification/severity/impact left
    for the operator.
12. `test_dispatch_retest_requires_target_and_executor` — missing target_url
    or executor → clear `ValueError` (caller error, fail-fast).

## Step 2 — Green: implement in `verdict_bridge.py` only

- `_replay_recipe(finding)` extractor (roles method/url, experiment id,
  vulnerability class; `None` when unusable) wired into `_evidence_payload`.
- `dispatch_retest(*, workspace, target_url, executor, finding_ids=None)`:
  gate via `verdict_preflight(target_url)`; read evidence files (validated
  ids only); per finding: recipe → triple execution → observations →
  digests → signal → retest evidence write; typed blockers elsewhere;
  operator handoff strings. No new imports beyond the file's current set
  (hashlib already present; no network code of its own).

## Step 3 — Wiring-free verification

- Bridge suite green (15 old + 12 new = 27).
- Core checksums UNMOVED: `modern_spine.py` `ef551212…`, `profile.py`
  `30fd86c6…` (proof of zero touch).
- Direct-I/O inventory drift test: expected NO drift (no new I/O sites —
  executor is injected; no new imports).
- Full suite, `verify_all.py` 145/145, package suites verdict 60 /
  emulator 17+16 skips / rehearsal 10.
- Lint clean on every touched file.

## Step 4 — Docs + delivery

- `docs/verification_round5.md`: execution record with the red→green log.
- `docs/reviews/round4_seal_update.md` gains a one-line pointer (seals
  unchanged by Round 5).
- Known Unknowns register: unchanged (no unknown retired — the re-test
  DISPATCH now exists; the re-tests themselves still need the pilot).
- Rebuild the ZIP from a clean tree, verify from fresh extraction
  (checksums + bridge suite), deliver to `/mnt/user-data/outputs/`.
