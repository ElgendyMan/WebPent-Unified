# M10 Recall Forensics — the blind_v3 Measurement Genealogy and FN RCA

**Window:** UM-DR-27 (2026-11-07). **Authority:** the operator's Ultimate
Transformation Directive (Phase 2 — M10 Recall Forensics, the highest
priority) + the standing recall-program mandate.

This document is the evidence-based answer to four questions: (1) what
exactly is the 0.137; (2) why did every miss happen; (3) what the 1.0
replica result does and does not prove; (4) what was done about it this
window and what remains.

---

## 1. The measurement genealogy (never merge these numbers)

| # | Measurement | Corpus | Producer | Recall | Precision | Evidence |
|---|---|---|---|---|---|---|
| 1 | **The recorded blind baseline** | original blind_v3 (120 cases; 73 vuln / 47 safe) | deterministic 3-GET differential, LLM OFF | **0.1370** | 0.6667 | `reports/goed_v1_8_4/differential_v184.json` (mode_a_llm_off) |
| 2 | The LLM-on differential (same run) | original blind_v3 | causal-feedback LLM loop (GOED v1.8.4) | 0.3425 | 0.5556 | same file (mode_b_llm_on) |
| 3 | The scorer's blind_v3 run (GOED) | original blind_v3 | LLM router | 0.3425 | 0.5556 | `reports/goed_v1_8_4/blind_v3_score.json` |
| 4 | The M3 Charter-gate baseline replay | original blind_v3 (replayed constants) | recorded constants cross-checked | 0.1370 | 0.6667 | `docs/engineering/M3_PHASE_REPORT.md` §2.7 |
| 5 | The replica reproduction (UM-DR-25) | same-spec replica | 3-GET methodology | 0.3425 | 1.0000 | `reports/qualification/blind_v3_replica_*.json` (mode_a) |
| 6 | The replica stateful prober (UM-DR-25) | same-spec replica | name-grammar stateful prober | 1.0000 | 1.0000 | same reports (mode_a2), 13.2 req/case |
| 7 | **The generalization fixture (UM-DR-27, this window)** | same-spec fixture, UNGUESSABLE token routes | observed-surface stateful prober | **1.0000** | **1.0000** | `reports/qualification/blind_v3_generalization_*.json` (mode_a3), 8.9 req/case |

**The 0.137 defined (numerator/denominator):** micro recall over the 120
manifest cases = TP / (TP + FN) = **10 / (10 + 63)** — 10 true positives
against 73 ground-truth-vulnerable cases; 48 false negatives were
state-transition cases, 15 were read-only oracle misses (§2). Precision
10/(10+5) = 0.6667. The metric implementation:
`goed_v1_8_4/blind_v3_scorer.py` (predicted = verdict `CONFIRMED`;
actual = ground-truth `expected_label == "vulnerable"`).

**Why measurements 5/6/7 can never replace 1:** the original blind_v3
target server was never committed (blind-benchmark discipline — the
runtime must never read the server source). 5/6/7 run against
repo-resident fixtures reconstructed from the committed ground-truth
SPEC. They measure the same behavior grammar through the same causal
guard, but they are author-known corpora. The production_qualified label
still requires operator-deployed holdout corpora (M11 ladder).

---

## 2. False-negative root-cause analysis (the 63 misses of the 0.137)

Method: joined the recorded per-case verdicts
(`differential_v184.json` → mode_a_llm_off.per_case) with the committed
ground truth; classified every FN through the detection pipeline.
Machine-readable register: `reports/qualification/fn_rca_mode_a.json`.

### 2.1 The verdict distribution of the misses

`INCONCLUSIVE 44 / BLOCKED 19` — the guard refused to confirm without
the required observable differential. No miss was a scoring/reporting
error: every FN is an *observability* failure upstream of the guard.

### 2.2 Root-cause classes (quantified)

| Class | Count | Share | Pipeline stage that failed | Root cause |
|---|---|---|---|---|
| **State-transition unobservable (methodology)** | 48 | 76.2% | request execution / stateful exploration | the 3-GET methodology never triggers any transition: reasoning (23 vulns) need ONE transition, compositional (25 vulns) need TWO composed transitions; pre-transition, both present the *clean-looking* trap response (owner=attacker, granted) |
| **Read-only oracle weakness** | 15 | 23.8% | response interpretation (differential comparator) | `representation_equivalence`/alias (8) + `ownership_bypass` (7) cases where the differential EXISTS read-only but the deterministic comparator returned INCONCLUSIVE; the LLM mode recovered the alias family semantically (mode_b +0.2055 recall came precisely from these + 15 reasoning cases its tool loop could reach) |

### 2.3 Per-mechanism breakdown of the 63 FNs

| mechanism / class | FNs | state-transition? |
|---|---|---|
| state_transition_violation / stateful_business_logic | 13 | yes |
| delayed_effect / side_effect_dependency | 10 | yes |
| workflow_invariant / multi_step_business_logic | 10 | yes |
| representation_equivalence / alias_bypass | 8 | **no** |
| business_logic_constraint / counter_flag_bypass | 8 | yes |
| ownership_bypass / direct_auth_mismatch | 7 | **no** |
| cross_resource_auth / indirect_relationship | 7 | yes |

### 2.4 The non-state 15 (read-only reachable misses) — full list

All family `simple`, difficulty 1, verdict INCONCLUSIVE, status OK:
`bv3_016, 017, 019, 020, 022, 023, 025` (ownership_bypass) and
`bv3_026, 028, 030, 032, 034, 036, 038, 040` (representation_equivalence
/ alias_bypass). These are **comparator-oracle** misses, not methodology
misses. Note: the replica's simple family (same spec) yields 25/25 under
the same guard — the recorded original-target misses therefore also
reflect target-specific response shapes the original differential
comparator could not separate. The original target is absent, so this
class cannot be re-measured in-repo; it is recorded as an owner-assigned
residual (§5).

---

## 3. What the 1.0 replica result proved — and did not

**Proved (measurement 6):** given the ability to *apply* the right
transitions, the two-phase pattern (read differential → bounded
transition → re-read) plus the causal guard detects 73/73 with 0 FP at
13.2 requests/case. The methodology ceiling is the dominant term of the
0.137.

**Did NOT prove (the confound UM-DR-27 removed):** the UM-DR-25 prober
*found* the transition endpoints by guessing names from a fixed grammar
(`state_<n>` / `transition_<n>` / `activate_<n>` / `flag_<n>`) — which
happens to be the replica's own naming convention. On a target with
different route names the grammar is content-discovery luck. The replica
also has no discovery surface at all (root = 404), so no in-repo corpus
could demonstrate *discovery* generalization — until this window.

**Leakage/overfitting audit (directive §4.3):** no ground-truth channel
leaks (the prober reads the manifest only; the scorer reads ground truth
after both runs; the fixtures never read ground truth at runtime; the
leakage-audit tests grep source + runtime for truth vocabulary). The
remaining bias is author-known corpora — recorded as the honesty
boundary, not fixable in-repo.

---

## 4. The UM-DR-27 generalization window (executed)

**The experiment.** A new fixture
(`benchmarks/blind_v3_replica/generalization_target.py`): same committed
ground-truth spec, but transition routes carry unguessable sha256-token
names (`/bv3/rsng/sda18_46`), and the target advertises its surface the
way real applications do — a root route index (the sitemap / OpenAPI /
GraphQL-introspection posture), plus one global decoy transition
(`reset_all`) that flips nothing.

**The capability.** `src/webpent/production/transition_sources.py`:
a `TransitionSource` protocol; `ObservedSurfaceSource` (candidates from
an observed endpoint inventory in the `family_feeds` vocabulary —
explicit `stateful` flag wins over the method heuristic; case-scoped by
directory + resource-id token; dedup; stable first-observed order);
`NameGrammarSource` (the EXACT legacy grammar, byte-pinned by test);
`CompositeTransitionSource`; and the production adapter
`observed_source_from_campaign_state()` (campaign state →
`family_feeds.endpoint_inventory_from_state` → source). The prober
(`production/stateful_probe.py`) gained a source-driven phase 2:
singles (accumulating, full application-order evidence) then bounded
unordered pairwise composition; a transition answered ≥400 is skipped
without re-evaluation (budget honesty); DELETE is refused (a transition
trigger must never destroy evidence); the causal guard remains the only
confirmation authority; the legacy no-source path is byte-compatible
(the 20 UM-DR-25 replica tests pass unchanged).

**The measured result (measurement 7):**

| mode | recall | precision | avg req/case | reading |
|---|---|---|---|---|
| mode_a (recorded 3-GET methodology) | 0.3425 | 1.0000 | 3.0 | the simple family only |
| mode_a2 (legacy name grammar) | 0.3425 | 1.0000 | 17.67 | **+0.0000 — the control: grammar-guessing does not generalize** |
| mode_a3 (observed-source) | **1.0000** | **1.0000** | 8.9 | 73/73 TP, 0 FP, 47/47 TN; discovery cost: 1 request total |

**What this establishes:** the stateful-detection capability generalizes
to unknown route grammars when (and only when) the transition candidates
come from an observed surface instead of name-guessing — and it is
*cheaper* than the grammar fallback (8.9 vs 17.67 req/case) because
scoped candidates don't waste budget on 404s. The regression pin:
`tests/test_transition_sources.py` (27 tests) freezes this end-to-end,
including the grammar control and the full-corpus 73/0/0/47 assertion.

**Production wiring delivered:** `observed_source_from_campaign_state()`
is the real-state seam (OpenAPI routes → crawl surface records → forms
→ JS shadow endpoints → endpoint lists, the documented family_feeds
precedence). Any campaign component holding real state can construct the
source. The remaining step — invoking the prober from inside a frozen
campaign node behind a feature flag — needs a thaw window (frozen-node
seam discipline) and is owner-assigned below.

---

## 5. Remaining blockers and owners (honest ledger)

| Item | Owner | Completion criterion |
|---|---|---|
| Frozen-node campaign wiring of the source-driven prober (flag-gated, fail-soft) | next builder thaw window | a real campaign path constructs the source from live crawl state and the prober's outcomes feed the hypothesis/finding channels with provenance |
| The read-only comparator-oracle misses (§2.4, 15 cases on the absent original target) | recall-program next window | a semantic-normalization differential (representation equivalence) validated on a fixture whose simple family reproduces the original miss shapes |
| Independent holdout corpora | operator (external dependency) | production_qualified per the M11 ladder requires operator-deployed, author-independent corpora; the M10 gate stays closed until then |
| Per-family metrics on the generalization corpus (this window measured aggregate + family recall via the runner) | M11 weekly canary extension | the weekly runner gains the generalization fixture as a standing benchmark |

**The M10 gate remains closed** (recall ≥ 0.5 ∧ precision ≥ 0.7 on an
independent holdout — Charter §4.1). This window moved the *capability*
(the methodology ceiling is lifted and the generalization confound is
measured away); the *label* still waits on independent corpora.

---

## 6. The UM-DR-28 follow-up window (executed, 2026-11-07)

The two owner-assigned blockers of §5 are CLOSED; the third
(operator corpora) remains.

### 6.1 Campaign integration (§5 row 1 — CLOSED)

`production/stateful_discovery.py` + a declared 4-file refreeze
(`scripts/refreeze_manifest_umdr28_stateful_discovery.py`, DR-009):
the wired `family_execution` node invokes the source-driven discovery
behind the fail-closed `enable_stateful_discovery` flag — structural
read-triple case mining from the observed inventory (no naming
assumptions), scope enforced before any request leaves the process,
bounded budgets (≤24 cases / ≤360 requests per run), outcomes on the
declared `stateful_discovery` PentestState channel, CONFIRMED outcomes
promoted as findings that pass the SAME adversarial review +
self-verify as every other finding. Proven at three levels on a
structurally DIFFERENT live target (`benchmarks/campaign_stateful_target.py`
— ledger/OpenAPI grammar, unguessable hex tokens, cross-directory
decoy, out-of-scope area): node-level (3/3 ground-truth vulns — IDOR,
alias-escalation, compositional; 4/4 safe unconfirmed), LangGraph
runtime level (the real `wire_family_execution` inside a compiled
StateGraph), builder level (the spine flag adds the node). Evidence:
`reports/qualification/umdr28_campaign_e2e.json`,
`tests/test_umdr28_campaign_stateful_e2e.py` (10 tests).

### 6.2 The comparator-oracle repair (§5 row 2 — CLOSED on the miss class)

`cqa_v2/representation_oracle.py` (canonical JSON normalization with a
pinned volatile-key rule set + body-represented authorization semantics
through a documented alias vocabulary, headers always winning, parse
failures falling back to the exact legacy behavior) + the frozen
guard's four header-only channels gaining the standard top-level
fallback (the ONLY frozen change inside the guard — verdict branches
and thresholds untouched). The miss class is reproduced on the new
equivalence fixture (`benchmarks/blind_v3_replica/equivalence_target.py`
— same spec, body-represented semantics, rotating field names, volatile
churn, rotated key order) and fully recovered:

| mode | recall | precision | reading |
|---|---|---|---|
| E1 legacy observations + grammar fallback | 0.0 | — | the miss class reproduced |
| E2 legacy observations + observed source | 0.0 | — | THE COMPARATOR GAP — transitions apply, guard blind |
| E3 oracle observations + observed source | **1.0** | **1.0** | 73/73, 0 FP, 47 TN |

The exact original 15-miss bytes remain unrecoverable (the original
target was never committed) — the honesty boundary, recorded. The
adversarial pin: a one-character owner difference breaks canonical
equivalence (no over-normalization); authorization fields are never in
the volatile set. Evidence:
`reports/qualification/umdr28_equivalence_measurement.json`,
`tests/test_umdr28_representation_oracle.py` (23 tests).

### 6.3 Evidence sequencing (hardened)

Every probe outcome now carries the ordered `evidence_trace`
(reads with digests/verdicts/observed context; transitions with
method/path/status); the source-driven path records the FULL
cumulative application log (singles stay applied under pairs — a
confirming pair cites every transition applied since probe start);
bounded control rotation (≤2 alternatives) finds an enforced negative
control when the structural first guess is itself a trap. The legacy
grammar path stays byte-compatible (measurement comparability) — its
known under-reporting asymmetry is documented in Document A §7.

### 6.4 M10 status after this window

Capability: campaign-integrated, lab_qualified on three fixture
populations (replica, generalization, equivalence) + one live E2E
target class. Label: **still closed** — the gate requires an
INDEPENDENT HOLDOUT (operator-deployed, author-independent corpora);
none exists in-repo. `INDEPENDENT HOLDOUT: NOT AVAILABLE`.

— End of M10_RECALL_RCA.md —
