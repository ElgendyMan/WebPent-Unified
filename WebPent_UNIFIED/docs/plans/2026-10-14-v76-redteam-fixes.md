# Plan: v76 — red-team remediation for the discovery engine

Date: 2026-10-14. Source: `2026-10-14-v75-redteam.md` (findings R0-R25).
Every task lands in advisory-only code, tests, or docs. No new execution
authority, no change to promotion/prom/planner gates.

Governing invariants (unchanged): discovery is advisory-only; candidates
dedup across rounds; discovery-only quiet rounds converge to
`NO_NEW_EVIDENCE`; thresholds are paired with floors; the report stays
machine-derived and redaction-safe.

Environment: venv `/home/thaura/venv`; tests
`cd /home/thaura/work && PYTHONPATH=src /home/thaura/venv/bin/python -m pytest`;
ruff `/opt/thaura/tools/venv/bin/ruff check`; browser tests need
`PLAYWRIGHT_BROWSERS_PATH=/home/thaura/pw-browsers`.

---

### Task 1: `_stringify_strings` real nesting depth (R1)
Files: `src/webpent/autonomous/hunt_discovery.py`, `tests/test_autonomous_hunt_discovery.py`.
1. Failing tests: (a) a flat record with 10 string fields yields all 10
   strings; (b) a nested record 8 levels deep with one string per level
   yields the string at depth 8 when under the 200 cap; (c) more than 200
   strings yields exactly 200.
2. Implement: walk `(value, depth)` pairs from a stack; push children with
   `depth + 1`; break when a popped depth exceeds `_MAX_STRINGIFY_DEPTH = 8`;
   stop appending when `len(found) >= _MAX_STRINGS_PER_RECORD = 200`.
3. Done when: the three tests pass and the pipeline shape test is unchanged.

### Task 2: absolute floors beside relative thresholds (R2)
Files: same as Task 1.
1. Failing tests: sizes 3 vs 4 (divergence 0.25) fires NOTHING; timings
   10 vs 20 ms fire NOTHING; sizes 1000 vs 1900 and timings 900 vs 1400
   still fire (existing tests keep passing).
2. Implement: `_SIZE_ABSOLUTE_FLOOR = 64` bytes and
   `_TIMING_ABSOLUTE_FLOOR_MS = 150` ms; an anomaly requires
   `(high - low) >= floor` AND `divergence >= threshold`. Constants named
   beside the existing thresholds with the same pairing comment.
3. Done when: old threshold tests green, new floor tests green.

### Task 3: status-divergence confidence derived from evidence (R3)
Files: same as Task 1.
1. Failing test: two distinct statuses → confidence 0.75; three → 0.85;
   five → 0.9 (capped).
2. Implement: `confidence = round(min(0.9, 0.55 + 0.1 * (len(statuses) - 1)), 2)`.
   Two statuses land exactly on the strong gate (0.75), preserving tier
   behavior for existing tests.
3. Done when: new test green, `test_two_rounds_of_same_signal_reach_strong`
   and the orchestrator convergence test unchanged and green.

### Task 4: route variants fixed (R5, R5b, R6)
Files: same as Task 1.
1. Failing tests: (a) an `/api/items/{id}` template mints
   `/api/v2/items/1` and NEVER `/api/v2/api/...`; (b) no minted candidate
   contains `{id}`; (c) `/admin` variant is minted only when the string
   `admin` appears in the observed evidence; without it, no admin variant.
2. Implement in `infer_route_patterns`: `base = template.replace("{id}", "1")`;
   variants = [base] + [`"/api/v2" + template[4:].replace("{id}", "1")` if
   template.startswith("/api/") else nothing] + [`"/admin" + base` only if
   `allow_admin`]; add keyword `admin_evidence: bool = False` (True when the
   caller saw "admin" in records); skip any variant containing `{id}`
   defensively.
3. Update the pinned test `test_route_variants_are_minted_for_id_templates`
   to assert the corrected paths. `discover_from_records` computes
   `admin_evidence` by scanning the round's strings once.
4. Done when: variants correct, admin gated, old dedup/cap tests green.

### Task 5: endpoint mining stops minting URL fragments (R12)
Files: same as Task 1.
1. Failing test: a record whose url is `https://lab.example/api/items/177`
   mints no candidate for `/lab.example` and none for `//host`; a
   metadata string like `redirect -> /dashboard/settings` still mints
   `/dashboard/settings`.
2. Implement: switch to `finditer`; skip a match whose preceding two
   characters are `:` or whose preceding character is `/` (i.e. the match
   is a URL scheme/host fragment). Keep static filter, length filter, caps.
3. Done when: new tests green; traceability wording corrected in Task 8.

### Task 6: budget semantics + param signature scope + hybrid dedup (R14, R11, R8b)
Files: `hunt_discovery.py`, `hunt_orchestrator.py`, tests.
1. Failing tests: (a) budget: `documented` region has
   `unexplained_anomalies == 0` when only noise exists; `anomalous` region
   counts interesting+strong, never noise; (b) params: `uid` minted from
   `user_id` after `uid` was already minted from `id` on another source;
   (c) hybrids: running the pipeline twice with the same records mints the
   hybrid once (signature remembered).
2. Implement: (a) `unexplained_anomalies` = count of
   interesting+strong on the anomalous region, 0 on documented; (b) param
   signature `_seen_signature("param", f"{key}->{sibling}")`; (c) in
   `_phase_discover`, also harvest `hybrids` scenario signatures (strip the
   `discovery:` prefix, use the `discovery:` string itself) into
   `state.discovery_signatures`.
3. Done when: the three tests green; convergence test still green.

### Task 7: merge-gate + report fixes (R10, R16, R17, R26)
Files: `hunt_orchestrator.py`, `hunt_state.py`, tests.
1. Failing tests: (a) a discovery seed whose anomaly probe is
   `http://target.example/api/item/177` (same origin as the hunt target)
   merges with `target_url` = that probe; a foreign-origin probe keeps the
   generic target pin; (b) `to_report_json` hypothesis entry for a merged
   discovery seed has `pattern_id` starting `gap:`; (c) the ok-path
   discovery phase record has `reason == "discovery_candidates"`.
2. Implement: (a) in `_merge_discovery_hypotheses`, parse
   `seed["anomaly"]["probe"]` with the same-origin helper; same origin →
   `item["target_url"] = probe` (truncated 500); (b) extend the report
   fallback chain with `hypothesis_id`/`gap_id`; (c) set the reason; (d)
   name the per-round seed cap `_MAX_DISCOVERY_SEEDS_PER_ROUND = 8` and
   reuse a `_SEED_KEY_MAX = 160` constant.
3. Done when: the three tests green; convergence/dedup tests unchanged.

### Task 8: honesty pass — docs and non-claims (R7, R19, R24, R9)
Files: `hunt_discovery.py` docstrings, `docs/vip_autonomous_bug_hunter_traceability.md`, plan doc.
1. Module docstring: state explicitly that route/endpoint/param/hybrid
   candidates are ADVISORY INVENTORY with no consumer in the current loop;
   only strong-anomaly seeds enter re-hypothesis. State that endpoint
   mining is metadata-only with no origin claim. State that repetition is
   judged across CONSECUTIVE rounds (one-round-deep history).
2. `classify_anomalies` docstring: history noise can never reach strong
   (confidence < 0.5 < gate) — state it.
3. Traceability row: reword to "same-origin route/parameter candidates;
   endpoint candidates mined from recorded metadata (no origin claim);
   routes/endpoints/params/hybrids are advisory inventory without a
   consumer in the current loop (explicit non-claim)".
4. Done when: no doc sentence claims more than the code does.

### Task 9: full verification and release
1. `pytest` full suite with the Playwright path override: 0 failures
   required; record the exact count.
2. Ruff clean on every touched file.
3. Regenerate `docs/direct_io_inventory.json` from `scan_direct_io(src)`
   if line shifts moved records; verify the `not_approved` pin stays 20;
   zero hand-edits.
4. Append the Task 11 verification record to
   `docs/plans/2026-10-14-autonomous-bug-hunter.md`; update the
   traceability release-gate evidence.
5. Rebuild the deliverable ZIP (v76), caches excluded, and present it.
6. Done when: 0 failures, ruff clean, inventory byte-matches the live
   scan, ZIP built and presented.

## Execution order
Tasks 1-3 (engine floors and depth) → 4-5 (candidate correctness) → 6
(semantics + dedup) → 7 (wiring + report) → 8 (docs) → 9 (verify + ship).
Each task ends with its own tests green before the next starts.
