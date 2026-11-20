# Plan: WebPent as an Autonomous Bug Hunter

Date: 2026-10-14. Scope: turn the framework from "components under
construction" into one autonomous hunt loop that plans, executes through the
audited gates, proves, and reports — without adding any new execution
authority.

## Governing invariants (hold in every phase)

1. The orchestrator is orchestration only. It never creates a transport
   client and never executes without an injected `ActionExecutor` and task
   handler. A missing dependency is a typed stop, never a fallback to raw
   HTTP.
2. Promotion stays in the deterministic validators + sealed `ProofBundle`
   path. A bundle without `negative_control_digest`, with a failed seal, or
   from a foreign `engagement_id` is refused, never reported as a finding.
3. Controller contract: outcomes are read from `campaign_task_outcomes`
   (with `task_outcomes` as a scripted-test fallback) and stop reasons from
   `stop_decision.reason` (with `stop_reason` / `smart_replanning.stop_reason`
   as fallbacks).
4. Learning memory is hint-only, capped at 0.75, isolated by
   `engagement:target`, tamper-evident via the `SmartMemory` signature
   scheme, and never learns from governance stops.
5. Direct-IO inventory drift is resolved only by deliberate regeneration
   from `scan_direct_io(SRC_ROOT)`, never by hand-editing the artifact.
6. Every phase lands with a fresh test run; no completion claim without a
   green command in the same message.

## Task 1 — Orchestrator loop and contracts (Phase 1)

Files: `src/webpent/autonomous/hunt_contracts.py`,
`src/webpent/autonomous/hunt_state.py`,
`src/webpent/autonomous/hunt_orchestrator.py`,
`tests/test_autonomous_hunt_orchestrator.py`.

1. Contracts: `HuntPhase` (recon→hypothesis→rank→execute→observe→prove→
   learn→report), `HuntStopReason` (typed, closed set), `HuntOutcome`
   (confirmed/blocked/inconclusive), `PhaseRecord`.
2. `AutonomousHuntState`: additive state wrapping existing controller/planner
   payloads, redaction-safe `summary()`, bounded ledgers.
3. `AutonomousHuntOrchestrator.run(state)`: bounded loop, each phase
   fail-closed, stop reasons mapped 1:1 from the real controller's
   `StopDecision`.
4. Done when: `tests/test_autonomous_hunt_orchestrator.py` green and the
   full regression at 0 failures.

Status: implemented. Evidence: 17 orchestrator tests; baseline 2135/0.

## Task 2 — Real execution wiring (Phase 2)

Files: `src/webpent/autonomous/hunt_runtime.py`,
`tests/test_autonomous_hunt_runtime.py`.

1. `build_hunt_runtime` builds a production `RuntimeContext` via
   `RuntimeFactory.create` (scope policy, `ActionAuthority` with
   `require_g02=True`, budget, idempotency, ledger, proof store), then
   registers the canonical `smart_http` adapter with the full G-02 contract.
2. The handler is the existing `build_smart_campaign_handler`; mode gates
   come from the audited action authority (POST denied in `safe-smart`,
   allowed in `authorized-active` under the approval policy).
3. `wire_orchestrator` binds the wired executor + handler;
   `run_wired_hunt` calls `runtime.require_valid()` before anything runs.
4. Done when: out-of-scope is denied without calling the handler, POST is
   denied in `safe-smart`, missing G-02 metadata is denied, and a wired
   end-to-end hunt stops with a typed reason.

Status: implemented. Evidence: 10 runtime tests, all fail-closed paths
exercised through the real executor.

## Task 3 — Proof promotion hardening (Phase 3)

Files: `src/webpent/autonomous/hunt_orchestrator.py` (`_phase_prove`),
`tests/test_autonomous_hunt_orchestrator.py`.

1. `_phase_prove` refuses bundles that fail `verify_seal`, lack
   `negative_control_digest`, or carry a foreign `engagement_id`.
2. Verified bundles are linked into `state.findings` deduped by
   `seal_digest`, sourced `proof_bundle`.
3. Done when: the three refusal tests and the linking test are green.

Status: implemented. Evidence: orchestrator suite 17/17.

## Task 4 — Scoped learning memory (Phase 4)

Files: `src/webpent/autonomous/hunt_memory.py`,
`tests/test_autonomous_hunt_memory.py`.

1. `ScopedHuntMemory` stores signed `MemoryEntry` records keyed
   `engagement:target::pattern`; tampered entries raise on store.
2. `hint()` returns capped (±0.75) advisory hints; governance stops
   (`policy_denied` etc.) are never learned from.
3. Offline replay: after sqli confirms and idor is clean, the next hunt's
   ranking reorders sqli to the top while a large deterministic gap survives.
4. Done when: memory suite green and reordering proven by replay.

Status: implemented. Evidence: 7 memory tests.

## Task 5 — One-command CLI (Phase 5)

Files: `src/webpent/cli/commands.py` (`hunt-auto`),
`tests/test_autonomous_hunt_cli.py`.

1. `hunt-auto --url ... [--mode safe-smart|authorized-active]
   [--engagement-id] [--campaign-id] [--max-iterations] [--dry-run]`.
2. The mode is validated against `ScanMode` before anything is built (the
   CLI is the validation boundary; `model_copy` does not validate).
3. `--dry-run` wires the real runtime, runs `require_valid()`, reports
   readiness JSON, and executes nothing.
4. Exit codes: 0 confirmed, 1 blocked at startup, 2 blocked hunt, 3
   inconclusive bounded stop. Output is the redaction-safe
   `state.summary()` JSON.
5. Done when: 4 CLI tests green, new code ruff-clean, direct-IO inventory
   regenerated (624 records).

Status: implemented. Evidence: `tests/test_autonomous_hunt_cli.py` 4/4;
`ruff check` clean on the new region; governance tests 4/4.

## Task 6 — Verification and release gates (Phase 6)

1. Full regression: 0 failures required; report the exact count.
2. Ruff clean on all new/touched code (pre-existing findings out of scope).
3. Honest qualification report: `docs/autonomous_bug_hunter_qualification.md`
   with per-claim evidence and explicit non-claims (no live-target
   qualification, no Docker/worker claim).
4. Traceability rows appended to
   `docs/vip_autonomous_bug_hunter_traceability.md`; README section added.
5. Deliverable: updated ZIP of the whole tree.

Status: this task completes with the release report and the ZIP.

## Task 7 — Post-delivery self-critique fixes (closed perception loop)

Follow-up from the post-delivery critique: a wired hunt from zero
knowledge produced 0 hypotheses and 0 actions. Four stacked root causes,
all fixed at source and verified end-to-end:

1. F1 — `hunt_knowledge.surface_map_to_knowledge` emitted relations with
   no `evidence_refs` and non-existent `source_observation` ids, so
   `AttackGraphEngine.build` dropped every edge and the real
   `HypothesisGenerator` had nothing to match. Fixed: per-route
   `has_endpoint`/`exposes`/`accepts` relations now carry a real
   observation id plus the crawler digest. Test:
   `test_autonomous_hunt_knowledge.py` (6).
2. F2 — research hypotheses label assets with canonical keys
   ("GET /login"), which the planner's same-origin filter drops. Fixed:
   `_resolve_hypothesis_targets` in `hunt_orchestrator.py` joins them
   onto the hunt origin without inventing hosts.
3. F3 — the planner reads the target from `state["target"]["url"]`; the
   hunt state projected neither `target` nor `scan_mode`, so the planner
   had an empty origin and the `legacy` profile disabled it. Fixed in
   `hunt_state.as_controller_state`; `run_wired_hunt` now defaults to
   `ScanMode.SAFE_SMART`.
4. F4 — event emission used enum reprs and skipped the recon/hypothesis
   phases. Fixed: plain phase values emitted after recon, hypothesis,
   and rank.

Verification evidence (2026-10-14): 44/44 autonomous hunt tests,
`test_g02_direct_io_inventory.py` 4/4 after a deliberate inventory
regeneration (624 -> 631 records, reviewable line-shift diff, pin
unchanged), full suite 2167 passed / 0 failed on a fresh re-run
(a single earlier failure was a live-socket flake: passed in isolation
and on the full re-run), ruff clean on all touched files.

## Task 8 — Autonomous convergence (suggestion 1 of 3) + test false positive

Suggestion 1 executed: **gap-driven re-hypothesis**. The hunt previously
generated hypotheses once, before the execute loop, so every iteration
after the first replayed the same planned tasks until a governance stop
fired. `hunt_replanning.synthesize_gap_hypotheses` now converts
unresolved knowledge gaps (gap_id/description/severity/required_evidence)
into bounded advisory seeds (max 8/round, priority = 0.35 + 0.4 *
severity clamped to 0.75, deduped against held hypotheses, target
pinned to the hunt's own origin), and the orchestrator calls
`_phase_rehypothesize` before declaring `NO_NEW_EVIDENCE`: gaps get one
chance to become new work; a hunt with neither evidence nor gaps stops
cleanly with the same typed reason.

Side finding, root-caused and fixed: the intermittent full-suite failure
in `test_replan_is_explicit_and_capped_at_three_after_inconclusive` was
NOT flaky infrastructure. The redaction assertion matched the reason
string "401" against all event fields including the numeric
`at_monotonic` uptime timestamp; reproduction with the real graph
showed the failing payload was `{"at_monotonic": 1053.283401}`. The
test now checks only content fields.

Verification (2026-10-14): replanning tests 6/6; autonomous suite 51/51;
G-02 4/4 after deliberate regeneration (631 -> 632 records: one new
`getattr` site in the orchestrator); ruff clean on all touched files;
full suite 2173 passed / 0 failed.

## Task 9 — Self-critique fixes (C1-C7) + validator coverage engine (suggestion 2 of 3)

### Phase A: critique of the delivered v73 work

C1 (critical): suggestion 1 was ineffective against the real controller.
The AutonomousController's result assembly emits ``coverage_ledger`` (and
task outcomes, lifecycle/recovery events, attack graph) — it never emits a
``knowledge_gaps`` key, so the orchestrator's ``_phase_observe`` read always
came up empty and the re-hypothesis phase never fired on real hunts. Worse,
the synthesizer could not parse the real ledger shapes even if they had
arrived. Fixed in both halves: ``_phase_observe`` now derives normalized gap
records from ``update["coverage_ledger"]`` via the new
``gaps_from_coverage_ledger`` (status-severity ordered, bounded at 16,
open-statuses only — tool_confirmed/candidate/clean never become gaps), and
``_normalize_gap`` accepts the controller's raw/projected entry shapes
(``key``/``attempts``/``last_status``/``reason``/``gaps``) alongside the
legacy synthetic shape. 7 new tests in test_autonomous_hunt_replanning.py
pin the real shapes end to end (13/13 pass).

C2: ``CoverageIntelligence.gaps()`` omitted ``missing-validator`` from its
status selector, so registry-missing classes never surfaced as coverage
gaps. Fixed (one-line selector addition with explanatory comment).

C3: honest scope statement for the validator work. Only three classes
remained parked as offline fixtures (cloud_storage_exposure,
elasticsearch_snapshot_traversal, xslt_injection) — not SSTI/XXE/SSRF as
earlier notes loosely claimed. All three got live deterministic validators;
two of the three still have no live producer agent, which is tracked in
docs rather than hidden.

C4: no regression tests existed for the controller's real result shapes.
Added (see C1 tests + coverage-engine tests below).

C5: the redaction test's whole-JSON plaintext check was the wrong
approach (it matched opaque digests and numeric timing). Replaced with a
``_string_leaves`` helper that checks only string leaves.

C6: the quiet-iteration phase-trace record could repeat every iteration;
now recorded once (dedup against existing phase_trace entries).

C7: ``to_report_json()`` now emits ``hypothesis_origins`` (counts by
origin) so reports show where hypotheses came from.

### Phase B: validator coverage engine (suggestion 2)

Live deterministic validators in ``postp0_checks.py`` (section 6) for the
three remaining offline-fixture classes, each with explicit
confirm/explicit-negative/inconclusive outcomes and sealed verifier
promotions (LLM can never sole-confirm):

* ``validate_cloud_storage_exposure`` — fresh GET of the bucket URL plus a
  random-object negative control; confirm requires listing markers on the
  bucket path and a marker-free control (provider-aware markers via the
  producer's ``_listing_evidence``, with a provider-agnostic
  ``<listbucketresult>+<key>`` fallback for custom-domain buckets);
  transport failure is an explicit negative on the candidate, control
  ambiguity is inconclusive.
* ``validate_elasticsearch_snapshot_traversal`` — requires BOTH
  repository/snapshot listing keys AND cluster identity keys
  (``cluster_name``/``cluster_uuid``) in the response; a nonexistent-handler
  control path must return ES errors without those markers; echo servers
  that mark the control are inconclusive by design.
* ``validate_xslt_injection`` — same-parameter replay differential with a
  benign literal-string stylesheet canary (no ``document()``, no file/URL
  reads, no extension functions); confirm requires the canary in the
  candidate replay and absent from both the baseline and the inert-value
  control; findings without a replayable request template fail closed to
  inconclusive.

Wiring: registry promotes all three to ``tested``/``deterministic`` (the
offline-fixture parking lot is now empty), validator-agent dispatch routes
the classes to the new validators, and ``CAMPAIGN_HUMAN_REVIEW`` is empty
(producer gaps stay visible as tracked gaps, not fake human-review
posture).

Critique of my own new code, found by its own tests before delivery:

* the ``VulnClass`` enum could not even represent
  ``elasticsearch_snapshot_traversal``/``xslt_injection`` — no producer or
  test could construct such a Finding without a ValidationError. Both
  members added to ``models/findings.py``.
* the cloud/ES negative-control evidence entries were not
  verifier-conformant (missing ``target_backed``/``observation_role``/
  ``response_digest``); both now match the subdomain-takeover shape and
  pass ``verify_replay_evidence``.
* two ``_body_digest`` call sites passed the Replay object instead of the
  body string.

Verification (2026-10-14): coverage-engine tests 16/16; Phase 5 validator
tests pass (registry test updated for the promotions); plugin-registry test
updated for the two promoted classes; replanning 13/13; principal
provisioning 11/11; G-02 inventory deliberately regenerated (632 -> 637
records, reviewable line-shift diff, unapproved pin unchanged at 20);
full suite 2196 passed / 0 failed; ruff: new/touched files clean (the 38
findings in test_principal_provisioning_completion.py are pre-existing
baseline E501s, none on lines added in this task).

## Task 10 — Adaptive discovery engine (suggestion 3 of 3)

Critique first (see 2026-10-14-v74-critique.md, A1-A4 + B1-B8), then map the
suggested "adaptive scenario generator + unknown-path exploration" onto the
real hunt loop as ONE deterministic, advisory-only module.

### Files
* create `src/webpent/autonomous/hunt_discovery.py` — the whole engine, pure
  functions, no I/O, bounded outputs:
  1. anomaly monitoring: group outcome/observation records by probe identity;
     signals = status-code divergence, content-length divergence (>20%),
     elapsed-ms divergence (>30%), unexpected error-text shifts — each gated
     by a minimum sample count (>=2) before classification
  2. classification: noise / interesting / strong from repetition + consistency
  3. hypothesis generation: strong anomalies become advisory hypothesis seeds
     (`origin="discovery-anomaly"`) in the same dict shape the re-hypothesis
     phase already consumes
  4. route-pattern inference: generalize recorded paths (numeric/literal
     segments) into same-origin candidate variants, deduped against seen
     action signatures, capped
  5. parameter inference: sibling parameter names for recorded query params
  6. endpoint mining: path-like strings extracted from recorded response
     metadata only (no body retention), static-asset filtered, capped
  7. hybrid scenario generation: evidence-backed capability pairs -> scenario
     hypotheses (`origin="discovery-hybrid"`), never findings
  8. uncertainty allocation: time-share weights that rise with ignorance
  9. agenda builder: bounded, priority-ordered next-round agenda
* wire `hunt_orchestrator.py`: `_phase_learn` runs discovery over the round's
  records and stores the result on `state.discovery`; `_phase_rehypothesize`
  merges discovery seeds through the existing dedup/caps; discovery-only
  rounds converge normally.
* `hunt_state.py`: `discovery` field + `discovery_summary` in `to_report_json`.
* `registry.py` + tests: machine-readable `producer_gap` in `coverage_gap()`.
* tests: `tests/test_autonomous_hunt_discovery.py` — every signal threshold,
  classifier tier, dedup/scope guard, cap, convergence behavior, and the
  report section.

### Done when
full suite green, discovery candidates never execute outside the existing
planner/executor gates, and a discovery-only round with no new evidence still
converges.

### Task 10 — verification record (2026-10-14)

Implemented as specified, with one design correction found BY THE TESTS:

* `tests/test_autonomous_hunt_discovery.py` (32 tests) exposed that the
  repetition rule could never fire: within one round each (probe, kind)
  pair appears at most once, so `repeat_count` was always 1 and the
  `strong` tier (and therefore every hypothesis seed) was dead code in
  the one-call pipeline. Fixed: `classify_anomalies` now takes the prior
  rounds' classified anomalies as `history`, and
  `discover_from_records` takes `prior_anomalies`; the orchestrator
  passes `state.discovery["anomalies"]` forward. Repetition is judged
  across rounds, which is the only place repetition is real.
* Wiring: `_phase_discover` runs after `_phase_learn` each round,
  stores the bounded result on `state.discovery`, and harvests minted
  candidate signatures into `state.discovery_signatures` (cross-round
  dedup, critique B6). `_phase_rehypothesize` now merges two seed
  sources through the same bounded path: discovery seeds (deduped by
  stable `gap_id`, targets pinned to the hunt's own scoped target) and
  the existing knowledge-gap seeds.
* Convergence (B3): with a fixed controller update, round 1 classifies
  `interesting`, round 2 reaches `strong` and mints a seed, the stall
  round merges it, the next stall round dedups to zero and the hunt
  stops with `NO_NEW_EVIDENCE`. Pinned by
  `test_discovery_seeds_dedup_across_rounds_and_loop_converges`.
* Report (B7/C7): `to_report_json` carries `discovery_summary` with
  machine-derived counts (anomaly tiers, candidates, agenda) and
  `hypothesis_origins` already attributes `discovery-anomaly` seeds.
* Registry (A1/C8): `coverage_gap()` returns `producer_gap=True`
  exactly for `elasticsearch_snapshot_traversal` and `xslt_injection`.
* Canary (A4/C9): `test_validator_coverage_engine.py` imports
  `_XSLT_CANARY` from `postp0_checks` instead of re-declaring it.
* Verification: full suite 2228 passed, 0 failures (ruff clean on all
  touched files). Two test-side environment notes: (1) browser-hunter
  tests needed `PLAYWRIGHT_BROWSERS_PATH` pointed at a symlinked
  chromium_headless_shell build (tool-image browser build moved 1243 ->
  1248 mid-session; code untouched); (2) the direct-IO inventory was
  deliberately regenerated (line shifts only; record count 637 and the
  unapproved-site pin of 20 unchanged; the coverage field's
  `unapproved_raw_transport` was first miscounted as 22 by including
  `approved_with_expiry` records, corrected to `not_approved`-only).

## Task 11 — v76 red-team remediation (self-red-team of suggestion 3)

Critique: `2026-10-14-v75-redteam.md` (findings R0-R25, severity-ordered).
Plan: `2026-10-14-v76-redteam-fixes.md` (Tasks 1-9). Both executed in full.

Fixed in the engine (`hunt_discovery.py`): the string-walk depth cap now
tracks real nesting depth (`_MAX_STRINGIFY_DEPTH = 8`, string cap 200,
R1); size/timing divergence now requires an absolute floor beside the
relative threshold (`64` bytes / `150` ms, R2); status-divergence
confidence is evidence-derived (2 distinct statuses = 0.75 = the strong
gate, +0.1 each, capped 0.9, R3); the `/api/v2` variant no longer doubles
the `/api` prefix and no `{id}` placeholder path is ever minted (R5,
R5b); the `/admin` sibling is minted only on observed admin evidence
(R6); endpoint mining skips URL scheme/host fragments via match positions
(R12); the uncertainty budget counts only interesting/strong as
unexplained (R14); parameter signatures are scoped to (source, sibling)
(R11); hybrid scenarios dedup against seen signatures (R8b);
`classify_anomalies` documents the consecutive-round repetition semantics
and the noise-can't-become-strong invariant (R9, R21); the module
docstring carries the explicit non-claim that route/endpoint/param/hybrid
candidates are advisory inventory with no consumer in the current loop
(R7, R24).

Fixed in the wiring and report: merged discovery seeds aim at the
divergent same-origin probe instead of the generic target (R17); the
report's hypothesis projection falls back to hypothesis_id/gap_id so
discovery seeds no longer render a blank pattern_id (R10); the
discovery phase record carries `reason="discovery_candidates"` on the
productive path (R16); the seed cap and key truncations are named
constants `_MAX_DISCOVERY_SEEDS_PER_ROUND` / `_SEED_KEY_MAX` (R26).

Tests: 17 new red-team tests (49 total in
`test_autonomous_hunt_discovery.py`), covering every fixed behavior
including the skip-round repetition pin, the agenda-shape redaction
contract, and the corrected route-variant math (the old test pinned the
doubled-`/api` bug; red-team R18a/R25b). Traceability row reworded to
match what the code actually does (R19).

Verification: full suite 2245 passed, 0 failures (119.32s,
`PLAYWRIGHT_BROWSERS_PATH=/home/thaura/pw-browsers`); ruff clean on all
touched files; direct-IO inventory deliberately regenerated — 6 line
shifts only (hunt_discovery.py/hunt_orchestrator.py grew), record count
637, unapproved pin 20 records / 17 identities unchanged, coverage
`unapproved_raw_transport` = 20, zero hand-edits (approval statuses
re-applied by (file, kind, normalized_symbol) identity).
