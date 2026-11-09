# UM-DR-31.1 SECURITY REGRESSION REPORT

Scope: prove that the UM-DR-31.1 changes preserve every security invariant (directive §3, Gate B). Verification date: 2026-11-08, on the tagged release tree `v0.37.1-umdr31.1`.

## 1. Confirmation authority (invariant 3.1)

- `git diff a2e05a3..HEAD -- webpent/WebPent_UNIFIED/src/webpent/cqa_v2` → **empty** (CausalGuard untouched — the same verification the UM-DR-31 audit used, re-run through this window's HEAD).
- The research loop's output vocabulary is unchanged: the node returns only `hypotheses` + `research_loop` telemetry (pinned by `test_node_update_never_confirms`, `test_stateful_hints_change_order_not_authority`); telemetry names `cqa_v2.guarded_causal_evaluate (unchanged)` as the authority.
- The new hint machinery is ordering-only: it never writes to findings, never sets `deterministic_match`, never touches `confidence_score`/severity/info_gain of any hypothesis. Verified by code inspection of `stateful_research_hints`/`run_stateful_discovery` (the sort key reads hint priorities only) and by the four-arm ablation (zero false positives in every arm — the guard confirmed exactly the ground truth and nothing else).

**Result: PASS — CausalGuard remains the sole confirmation authority; no new confirmation path exists.**

## 2. Evidence integrity (invariant 3.2)

- ProofBundle generation and the replay requirements: untouched (no file under `cqa_v2/`, `memory/proof*`, or the replay verifier changed; the frozen gate's 641 byte-identical pins include the evidence chain modules).
- The traceable relationship (target/scope ↔ identity ↔ request sequence ↔ state ↔ response ↔ causal comparison ↔ confirmation) is unchanged; the §6.2 journey is joinable by hypothesis id (documented in the bottleneck report).
- The R4 fingerprint change makes evidence retention STRONGER (query identity preserved — the audited over-merge used to suppress a distinct object probe).

**Result: PASS — evidence requirements unchanged or strengthened; never weakened.**

## 3. Authorization and scope (invariant 3.3)

- **Out-of-scope rejected before requests**: the ablation re-run shows 2 scope refusals in every hinted arm with zero `/internal/*` confirmations and zero internal requests (asserted in `test_ablation_matrix_measures_each_input_contribution`).
- **Foreign-host hypotheses cannot reach executable scope**: the new admission filter rejects foreign hosts BEFORE the hypothesis pool (`test_foreign_host_rejected_before_hypothesis_pool` — zero hypotheses generated), plus scheme and port checks, plus malformed-URL fail-closed, plus no-origin fail-closed. Rejections are RECORDED in `scope_violations` (observable, not silent).
- The execution-time scope gate (`CampaignProberClient` allowed-prefixes, per-request scope validation, fail-closed authorization) is untouched — the admission filter is defense in depth, not a replacement.
- Rate/request budgets, kill-switches, HITL: untouched (no file in `safety/`, `shared/engagement_scope.py`, or the executor changed).

**Result: PASS — fail-closed authorization preserved; no new execution path bypasses scope.**

## 4. Bounded execution (invariant 3.4)

- Research loop bounds unchanged: 3×12 defaults, hard-clamped 16×64, invalid/missing limits → no-op (existing suite green).
- **Malformed loop state cannot increase budgets** (F18 fix): a non-Mapping `research_loop` channel → fail-closed no-op with the counter flooded to the cap; a subsequent pass is capped, never re-armed (`TestCorruptedChannelFailClosed` — string/list/int/bool channels, cross-pass re-arm prevention, non-integer counter). Corruption can only consume remaining research budget, never create it.
- Stateful discovery budget unchanged (default 360, operator-capped 1..3600); the ablation arms hit exactly the 36-request ceiling.

**Result: PASS — all loops remain bounded; corrupted state cannot reset or extend any budget.**

## 5. Targeted negative/safe controls (directive §9)

| Requirement | Verification |
|---|---|
| Out-of-scope targets rejected before requests | ablation: 2 refusals/arm, 0 internal requests |
| Foreign-host hypotheses cannot reach executable scope | R3 suite: zero hypotheses from foreign-host observations |
| Research priorities do not change vulnerability confidence | hints never touch Hypothesis confidence fields (code path + `test_stateful_hints_change_order_not_authority`) |
| Safe controls remain unconfirmed | ablation: safe records/vaults never confirmed in any arm (both runs) |
| Decoys remain unconfirmed | the fixture's clean-looking trap (attacker-owned vlt_3 pre-seal) is never confirmed; only the post-seal ownership differential confirms (ground-truth-only, both runs) |
| Rejected hypotheses do not reappear incorrectly | dedup suite green (suppressed_closed semantics unchanged) |
| Malformed loop state cannot increase budgets | R7 fault-injection suite |
| Only CausalGuard confirms | cqa_v2 diff empty; promotion path unchanged |
| ProofBundle/replay intact | frozen gate byte-identical pins; no evidence-chain file changed |
| Authorization/rate controls effective | no file in the safety/executor surface changed; frozen gate green |

## 6. Security-relevant behavior CHANGE (disclosed, positive)

1. **Foreign-host / non-http(s) / malformed workflow observations** previously produced pool hypotheses (the audit's F05 defense-in-depth gap); now they produce none, with an observable rejection record. This is a deliberate tightening — the execution gate's verdicts are unchanged.
2. **Unrecognized ledger statuses** previously normalized to actionable `not_scanned` (F20); now they are fail-closed non-gaps with an observable marker. Deliberate tightening.
3. **A corrupted research-loop channel** previously re-armed the iteration cap (F18); now it consumes the remaining budget. Deliberate tightening.

No security control was loosened anywhere in this window.

## 7. Test evidence

Security-critical suites re-run on the final tree: frozen module gate 641 ✅; UM-DR-31 research suites (60 unit + 16 integration + 8 e2e/ablation) ✅; coverage/gap-report suites ✅; broad-exception register gate ✅; compliance gates (release/deployment) ✅; full chunked suite **8,735 passed / 0 failed / 6 skipped / 3 xfailed** (exact accounting in `UMDR31_1_TEST_ACCOUNTING.json`).
