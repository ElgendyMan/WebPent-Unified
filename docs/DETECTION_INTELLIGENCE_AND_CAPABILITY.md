# WebPent — Detection Intelligence and Capability

**Document B** (per the Ultimate Transformation Directive §14). Status
date: 2026-11-07 (post UM-DR-28). Companion to Document A
(`docs/PROJECT_ARCHITECTURE_AND_ENGINEERING.md`). Every performance
number below is a MEASURED value with an evidence path; no percentages
without numerator/denominator; capability status uses the defined
ladder (Proven / Partial / Implemented-Unverified / Planned / Absent).

---

## 1. How WebPent understands a target

Progressively, evidence-first, through real channels: the crawl
(robots-gated, browser farm for JS-heavy targets), JS AST reversing
(`jsintel/js_reversing.py` — multi-level constant propagation,
call-site-verified sinks), OpenAPI/schema intake (`stateful_api/`),
observed-surface consolidation (`shared/family_feeds.py` — the
precedence: explicit inventory → OpenAPI routes → crawl surface
records → forms → JS shadow endpoints → endpoint lists), the appmodel
(`appmodel/` — Organization→…→Observation with discovery confidence),
and the identity ladder (anonymous → authenticated → roles, with
resource-SEED semantics). Facts carry provenance; the model separates
observed facts, inferred relationships (labelled `inferred`), and
unverified hypotheses (never findings).

## 2. How it discovers identities, roles and authorization boundaries

`recon/identity_discovery.py` (r6c two-branch S1: jwt_claims /
login_body_mining; bid/cart-style keys are RESOURCE SEEDS never
identity; email-matched keys resolve with zero probes) →
`recon/principal_provisioning.py` (rollup with alias→winner map,
honest exhaustion) → `recon/login_executor.py` (r9 D1–D4: the
validation-surface walk, five verdicts, rejected-operator-token
fall-through) → `auth/worker_session_factory.py` (strict own-role
matching, provenance-attached results). Authorization boundaries come
from differential testing between authorized test identities (M5's
two-identity BOLA/IDOR plans; fewer than two distinct operator
identities = honest refusal). Multi-tenant signal:
`shared/family_feeds.multi_tenant_from_state`.

## 3. How it reconstructs workflows and state

Two complementary mechanisms:
1. **The M5 stateful_api engine** — contract ingestion (OpenAPI routes
   + observed surface), the deterministic creator→consumer dependency
   model (every edge labelled `inferred`), double-bounded replayable
   sequence plans with preconditions/expected effects/randomized-id
   negative controls/cleanup plans, and two-identity differential
   plans with causal evidence specs.
2. **The UM-DR-27 stateful prober** (`production/stateful_probe.py` +
   `production/transition_sources.py`) — the bounded two-phase pattern:
   read differential through the causal guard → if inconclusive and
   state-suspected, apply transition candidates (from an OBSERVED
   surface via the `TransitionSource` protocol — grammar-free; the
   legacy name grammar remains as fallback) → re-read → the guard
   decides. Singles accumulate (full application-order evidence);
   bounded unordered pairwise composition covers two-transition
   (compositional) bugs; ≥400 answers skip re-evaluation; DELETE
   refused (evidence-preserving); ≤30 requests/case enforced.
   UM-DR-28 adds: the ordered `evidence_trace` on every outcome
   (reads with digests/verdicts/observed context; transitions with
   method/path/status — nothing silently disappears), the cumulative
   application log on the source-driven path, and bounded control
   rotation (≤2 alternatives × 2 reads — an enforced negative control
   is REQUIRED evidence, so when the structural first guess is itself
   a clean-looking trap, the prober adaptively searches for the
   enforcement reference; the guard stays the authority).
3. **The UM-DR-28 campaign integration**
   (`production/stateful_discovery.py`) — the production path: the
   wired `family_execution` node (behind fail-closed
   `enable_stateful_discovery`) derives the inventory from live
   campaign channels, STRUCTURALLY mines read-triple cases (grouped by
   resource directory, id-token scoped, no naming assumptions),
   probes them through the same executor the family plans use with
   scope enforced BEFORE any request leaves the process (case
   pre-filter + client-level refusal, both counted), promotes
   CONFIRMED outcomes as findings with full provenance, and reports
   on the declared `stateful_discovery` PentestState channel. Hard
   bounds: ≤24 cases, ≤360 requests per campaign run. Proven
   end-to-end on a structurally different live target (3/3
   ground-truth vulns confirmed — IDOR, alias-escalation,
   compositional; safe cases and decoy never confirmed; out-of-scope
   refused).

## 4. Hypotheses, prioritization, attack paths, refutation

Hypotheses are evidence-backed records (M3 contract: preconditions,
alternatives, expected_behavior, negative_control, info_gain, risk)
projected through stable UUIDv5 ids into the hypothesis channel —
advisories, never findings. The planner prioritizes by info-gain
factors; the replan contract (`agents/hunter_graph.py`) routes
first-attempt REFUTED to replan-once with the real verdict, never
re-exploiting the refuted item. Refutation learning
(`production/validators.py::maybe_record_validator_outcome`) records
REFUTED/CONFIRMED outcomes and feeds the planner advisory. The attack
graph (`attack_graph/`) enriches edges with evidence_status — honest
backfill only from real evidence; unbacked edges are accounted as
unbacked.

## 5. The confirmation authority (how a finding is born)

`webpent.cqa_v2.guarded_causal_evaluate` — the deterministic causal
guard — is the ONLY confirmation authority for the deterministic
path: a finding requires the observable differential (baseline /
candidate / control) with the negative control refusing. UM-DR-28
added the **representation-equivalence oracle**
(`cqa_v2/representation_oracle.py`): canonical JSON normalization
(sorted keys, a documented minimal volatile-key rule set — timestamps,
request/trace ids; NEVER owner/outcome/privilege/tenant fields,
adversarially pinned) + body-represented authorization semantics
extracted through a documented field-alias vocabulary (owner ≡
owned_by ≡ resource.owner; granted→outcome vocabulary; alias/effective_as
→ privilege escalation) surfaced through the guard's context channels.
Headers always win; parse failures fall back to the exact pre-oracle
behavior; every enrichment records which rules fired. The frozen
guard's four header-only channels (authorization_outcome,
effective_privilege[_granted], data_redacted) gained the standard
top-level fallback every other channel already had (declared refreeze,
UM-DR-28) — the verdict branches and thresholds are untouched. The
deception-resistant causal verifier (`deception/`) adds
baseline/candidate/control(+repeat) protocol with structural
signatures and one-way verdicts (no inconclusive→confirmed) —
measured 24/24 rejection of deception fixtures, blind set 8/8
(`reports/deception/benchmark_v1.json`). An LLM may PROPOSE
hypotheses; the Charter §4.1 gate
(`production/hypothesis_charter.py`) refuses LLM budget expansion
unless a fresh (≤7 days) measurement shows recall ≥ 0.5 ∧ precision ≥
0.7 ∧ > deterministic baseline on ≥ 30 samples — fail-closed. The
deterministic baseline is 0.137 (recorded); the gate refuses it by
construction.

## 6. Measured detection performance (the honest numbers)

See the genealogy table in `docs/engineering/M10_RECALL_RCA.md` §1 —
seven measurements, never merged. Headlines:

- **Original blind_v3 corpus (recorded, LLM off):** recall 0.1370 /
  precision 0.6667 (10/15/63/42). FN RCA: 76.2% methodology-
  unobservable state transitions; 23.8% read-only comparator-oracle
  misses.
- **Same corpus, LLM on:** 0.3425 / 0.5556 — recall bought with
  precision (the Charter gate exists precisely to prevent trading one
  for the other).
- **Replica corpus (author-known):** read-only 0.3425/1.0 → stateful
  prober 1.0/1.0 (13.2 req/case).
- **Generalization fixture (UM-DR-27; unknown token routes, root
  index as the only surface):** read-only 0.3425/1.0 → legacy grammar
  0.3425/1.0 (**+0.0000 — the control: name-guessing does not
  generalize**) → observed-source prober **1.0/1.0** (73/73, 0 FP,
  8.9 req/case, discovery cost 1 request).
- **Per-family on every corpus:** simple ≥ 0.4 (original) / 1.0
  (fixtures); reasoning and compositional 0.0 read-only → 1.0 with
  stateful discovery on the fixtures. The original-target families
  cannot be re-measured in-repo (target absent).
- **Equivalence fixture (UM-DR-28; body-represented authorization
  semantics — the comparator miss CLASS, rotating field names, nested
  objects, volatile churn, rotated key order):** legacy observations
  + grammar fallback **0.0 recall** (the miss class reproduced);
  legacy observations + observed source **0.0 recall** (THE
  COMPARATOR GAP — transitions apply, the guard is blind); oracle
  observations + observed source **1.0/1.0** (73/73, 0 FP, 47 TN).
  Evidence: `reports/qualification/umdr28_equivalence_measurement.json`.
- **Campaign E2E (UM-DR-28; structurally different live target —
  ledger/OpenAPI grammar, unguessable tokens):** 3/3 ground-truth
  vulns confirmed (IDOR-after-settle, alias-escalation, compositional
  pend+close), 4/4 safe accounts unconfirmed, decoy never confirmed,
  2/2 out-of-scope cases refused before any request. Evidence:
  `reports/qualification/umdr28_campaign_e2e.json`.
- **Deception robustness:** 24/24 fixture rejection, 0 FP, blind 8/8
  (production_qualified — the only component at that label).

**Blind-spot statement:** aggregate numbers never hide family
weaknesses — the M11 benchmark contract refuses aggregates without
per-family detail and sample sizes (structurally enforced).

## 7. Capability matrix (the 29 registered validator families + the stateful/identity spine)

Status ladder: **Proven** (validator registered + adversarial tests +
benchmark evidence) / **Partial** (registered + tests; benchmark
coverage or reachability limited) / **Implemented-Unverified** /
**Planned** / **Absent**.

| Family | Implementation (detector) | Validation mechanism | Test coverage | Measured | Status + limitation |
|---|---|---|---|---|---|
| SQLI / BLIND_SQLI | `production/validators.py` dispatch + payload engine | response-differential + time-based causal, negative control | validator suites + payload WSTG corpus | lab (vulnbox confusion matrix) | Proven (deterministic); blind variants latency-bound |
| XSS | registered validator | reflection differential w/ context checks | validator suites | lab | Proven; DOM-XSS via browser farm only |
| COMMAND_INJECTION | registered validator | output-marker causal | suites | lab | Proven; non-echo variants OOB-dependent |
| LFI / RFI / PATH_TRAVERSAL / FILE_UPLOAD | registered validators | content-signature + control | suites | lab | Proven |
| SSTI / XXE / XXE_OOB | registered validators | expression-marker / entity causal | suites | lab | Proven; XXE_OOB needs OAST reachability |
| SSRF / BLIND_SSRF | registered validators + egress policy | callback + response causal | suites | lab | Proven; egress policy operator-scoped |
| OPEN_REDIRECT | registered validator | Location-chain within scope law | M2 adversarial corpus | corpus-tested | Proven |
| INFO_DISCLOSURE | registered validator | content-pattern + control | suites | lab | Partial (pattern set bounded) |
| AUTH_BYPASS / JWT_MANIPULATION | registered validators | token-tamper differential | suites | lab | Proven |
| IDOR / BOLA / PRIVILEGE_DIFFERENTIAL / MASS_ASSIGNMENT | registered validators + M5 two-identity differential plans | A-own baseline vs B-cross differential + randomized-id control | stateful_api suites + validators | lab (plans); live execution advisory | Partial — the differential PLANS are proven; live sequence execution runs through the execution_sandbox→validator chain (deferred owner) |
| BUSINESS_LOGIC / RACE_CONDITION | registered validators + workflow_fuzzing | invariant differential / twin-request | suites | lab | Partial — complex multi-step logic needs per-target grammar (the UM-DR-27 source mechanism is the path in) |
| CACHE_POISONING / PROTOTYPE_POLLUTION | `production/advanced_validators.py` (UM-DR-26 registered — was dead code on arrival) | keyed-response differential / property-observation | advanced suites | lab | Partial (registration fixed; corpus depth bounded) |
| GRAPHQL_* (4 families) | `production/graphql_validator.py` (UM-DR-26 registered) | introspection/depth/field-suggestion/batching differentials | graphql suites | lab | Partial |
| **State-transition auth bugs** (the blind_v3 mechanism classes) | `production/stateful_probe.py` + `transition_sources.py` + `stateful_discovery.py` (UM-DR-28 campaign path) | two-phase causal: read differential → observed-surface transition → guard; scope-gated executor; control rotation | 27 UM-DR-27 + 48 UM-DR-28 tests incl. the LangGraph-runtime and node-level E2E | **1.0/1.0 on the generalization fixture (+0.0000 grammar control); 1.0/1.0 on the equivalence fixture; 3/3 on the campaign E2E** | Proven on fixtures (lab_qualified) and CAMPAIGN-INTEGRATED (UM-DR-28); independent holdout pending |
| **Representation-equivalence / body-represented authorization semantics** | `cqa_v2/representation_oracle.py` + the guard's channel-fallback seam | canonical-normalization differential + alias-vocabulary semantics extraction; adversarial no-over-normalization pin | 23 UM-DR-28 tests + 47 byte-compat regressions | **0.0 → 1.0 recall on the equivalence fixture, 0 FP throughout** | Proven on fixtures (lab_qualified); author-known corpus honesty boundary |
| Deception resistance (cross-cutting) | `deception/` causal verifier | baseline/candidate/control(+repeat), structural signatures | 16 tests + benchmark | 24/24, blind 8/8, 0 FP | **Proven — production_qualified** |

Not claimed: N-day/CVE matching against known software versions (the
ق6 cve_advisory is advisory-only), network-layer bugs (TLS/headers
outside the HTTP application layer), and client-side bugs beyond
DOM-XSS. These are **Absent by scope**, recorded here per the honesty
rule.

## 8. False-positive and false-negative engineering

FP: the causal guard (negative control mandatory) + the deception
verifier (one-way verdicts) + dedup gate + the Charter precision
threshold for any LLM path. Measured FP on every corpus this window:
0 (fixtures) / 5 (original, LLM off) / 20 (original, LLM on — the
recorded argument for the gate).
FN: root-caused to observability — 76.2% methodology (LIFTED by the
stateful path, UM-DR-27/28) and 23.8% comparator-oracle limits
(REPAIRED by the representation-equivalence oracle on the miss class,
UM-DR-28; the exact original bytes are unrecoverable — target absent).
Remaining FN surface: targets whose authorization semantics appear in
neither headers nor the documented body-alias vocabulary (honest
INCONCLUSIVE — the fail-safe default, never a guessed confirmation).

## 9. How AI is used (and where it is refused)

LLMs (multi-provider, `llm_researcher/`) may: propose hypotheses,
interpret behavior, suggest test candidates, classify root causes —
always behind the ToolBoundary, structured-output schemas, spend caps,
and the prompt-injection boundary (target content is untrusted text,
never instructions; the model cannot grant itself permissions).
LLMs never: determine authorization, expand scope, confirm findings,
or bypass gates. The Charter §4.1 gate currently REFUSES the LLM
hypothesis path budget (measured 0.3425 recall does not clear 0.5,
and precision 0.5556 is below 0.7 — the recorded run is the evidence).

## 10. Missing capabilities and research opportunities (owners assigned)

1. ~~Campaign-node wiring of the source-driven prober~~ — DONE
   (UM-DR-28; flag-gated, fail-soft, proven E2E).
2. ~~The read-only comparator oracle for representation-equivalence~~
   — DONE (UM-DR-28; the miss class recovered 0.0→1.0 with 0 FP).
3. Independent holdout corpora for production_qualified (operator
   dependency — the M10 gate stays closed until then).
4. Live sequence execution for the M5 differential plans
   (execution_sandbox→validator chain).
5. Per-family qualification on the generalization + equivalence
   corpora in the weekly ق5 canary (M11 extension).
6. Deception-corpus expansion beyond 24 fixtures (M11 scope).
7. Declare (or fold) the family spine's non-findings output keys as
   PentestState channels — currently dropped by LangGraph channel
   filtering; findings delivery unaffected (UM-DR-28 discovery,
   next builder window).
8. The body-alias vocabulary is deliberately minimal and
   English-conventioned; a measured expansion path (per-observation
   rule feedback, still adversarially pinned) is the next recall
   increment for exotic representations.

— End of Document B —
