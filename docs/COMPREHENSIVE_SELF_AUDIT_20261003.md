# TEAM-RED / COMPREHENSIVE SELF-AUDIT — 2026-10-03

**Reviewed project:** `/tmp/webpent_vuln_arsenal`  
**Reviewed package:** `/home/ubuntu/webpent-vuln-arsenal-sprint-a-remediated.zip`  
**Method:** independent source inspection, fresh tests, fresh gates, fresh bounded local campaigns, and hostile comparison against the 15-section brief. Prior reports were treated as claims, not evidence.

## 1. Executive verdict

**PRIOR_WORK_REFUTED**

The project is substantial and many claimed modules are real, but the prior completion language is too broad to survive this audit. The full suite, acceptance suite, frozen manifest, and five gates are currently reproducible. The trust spine has genuine HMAC, semantic, negative-control, and replay checks. However, the claim that M4 is the only credential-attachment boundary is refuted by legacy authentication/validator/tool paths that carry cookies and auth headers directly. The untrusted-content defense is not universal because ToolBoundary and Dalfox expose raw target output to callers. The Chaining Engine has five patterns and static wiring, but no live chain executed and its reportability gate trusts executor booleans without independently requiring a sealed chain proof. Personas are behaviorally different only in bounded family ordering; `all` is advertised but not executable. Several product, provider, payload, and auth claims are only partial.

## 2. Exit-criteria re-score

The requested labels are applied to the actual claims, not to the length of the implementation.

| criterion | prior claim | independent result | MET/NOT MET/UNKNOWN | evidence |
|---|---|---|---|---|
| 8 promotion gates | Eight gates are implemented and block | **PARTIAL**: one compound ProofBundle contract is decomposed into eight predicates; no eight named gate objects or exhaustive per-gate production tests | NOT MET | `src/webpent/models/proof_bundle.py:552-597`; selected semantic/tamper tests pass, but no systematic eight-predicate production test |
| ProofBundle seal/HMAC/replay | Fully protected | **VERIFIED with scope limits**: HMAC, semantic checks, negative controls, and replay consistency are real | MET | `proof_bundle.py:265-306,407-437`; `replay_verifier.py:73-125`; focused proof tests: 42 passed |
| Frozen manifest | 13/13 | **VERIFIED for the authority manifest**; older historical manifests disagree with the tree | MET for canonical manifest; NOT MET for “all manifests” | `scripts/verify_frozen_manifest.py` exit 0; 13 entries match; historical SHA files contain mismatches |
| Three-agent path | Fully live and generic | **PARTIAL**: source wiring is real; several campaign artifacts are incomplete/offline and the callback trusts downstream PROMOTED state | NOT MET | `hunter_graph.py`, `hunter_runner.py`; offline fixtures explicitly set `live_executor_available=False` |
| Personas | Three genuinely different agents | **PARTIAL**: preferred-family ordering differs; prompt/tool/focus fields are mostly metadata; `all` dispatch fails | NOT MET | `personas.py:39-72`; `hunter_graph.py:316-327`; `get_persona('all')` raises `ValueError` |
| 13 vulnerability families | All can find bugs | **PARTIAL**: registry and validators exist; controlled-local promotion exists for a subset; XSS, SQLI, and AUTH_BYPASS lack equivalent focused live proof | NOT MET | `experiment_fabric.py`; `validators.py`; Sprint-A and family tests; no focused live proof for XSS/SQLI/AUTH_BYPASS |
| Auth detector | JWT, cookies, API keys | **PARTIAL**: JWT/cookies/basic/OAuth signals exist; API-key detection is absent | NOT MET | `auth_detector.py:25-29,145-161,224-238`; no API-key signal path |
| Login executor | JSON APIs and PHP forms | **PARTIAL**: JSON and ordinary urlencoded HTML forms work; no PHP-specific/multipart branch | NOT MET | `login_executor.py:265-317`; no `enctype`/multipart/PHP-specific executor |
| Principal provisioning | 2+ principals in M4 | **PARTIAL**: sealing/authorize/resolve exists and sanitized evidence claims success; direct end-to-end registration/provisioning coverage is incomplete | NOT MET | `principal_provisioning.py:164-312`; no end-to-end test for registration fallback |
| Real ID discovery | IDs are discovered, not hardcoded | **PARTIAL**: collection/dashboard discovery exists; unsigned caller-supplied numeric claims are accepted and JWT decoder is not wired into production provisioning | NOT MET | `identity_discovery.py:189-226`; `principal_provisioning.py:297-305` |
| Foreign registration | Works | **PARTIAL/UNVERIFIED**: conditional branch exists, but no direct provisioning test proves the 401/403 register-then-login path | UNKNOWN | `principal_provisioning.py:190-220`; no test call site found |
| Payload library | Complete and used | **PARTIAL**: 1,421 records are real and used for some candidates; Planner does not consume payload documents and `SQL_INJECTION` vs `SQLI` prevents broad use | NOT MET | `docs/payload_library.json`; `hypothesis_generator.py:646-650`; `planner/agent.py:100-107` |
| Learning loop | Consultation changes priorities | **PARTIAL**: extraction/consultation/ranking hooks exist; A/B evidence reports zero effectiveness and sanitized artifacts omit before/after ordering | NOT MET | `lesson_extractor.py`, `hunter_runner.py:560-599`; learning A/B evidence reports `improvement_demonstrated:false` |
| Multi-provider LLM | Failover is production verified | **PARTIAL**: pool/router code and simulated tests exist; committed runtime traces show OpenAI only and no real provider failover | NOT MET | `key_pool.py`, `task_router.py`, `providers/pool.py`; failover artifact explicitly says monkeypatched/non-real |
| Product layer | Kill switch/dashboard/reports/cost complete | **PARTIAL**: primitives and report proof gates exist; dashboard omits requested cost/time, duration is hard-coded 0.0, and per-call pricing is unconnected | NOT MET | `product_layer.py:95-148`; `service/facade.py:54-65`; `shared/llm.py:304-327` |
| Chaining Engine | Five patterns and live governed chains | **PARTIAL**: five patterns and static M4/AVI callback exist; both current live projections have zero chains; executor booleans are trusted | NOT MET | `chain_engine.py:33-88,341-359,545-550`; current `docs/sprint_a_live_evidence/*.json` |
| Mind Map notes | Mind Map writes per campaign | **PARTIAL**: NoteTaker writes campaign Markdown; no standalone MindMap module and collision isolation is not enforced | NOT MET | `note_taker.py:48-63`; `hunter_runner.py:506-508`; duplicate campaign IDs in historical artifacts |
| Curiosity engine | Anomalies alter hunting | **PARTIAL**: flags are detected and sent to Planner prompt; deterministic ranking ignores them and causal effect is unproved | NOT MET | `curiosity_engine.py:63-149`; `hunter_runner.py:592-634`; `hunter_graph.py:316-331` |
| Untrusted-content defense | All target content is masked | **PARTIAL/REFUTED as global claim**: canonical wrapper works, but ToolBoundary and Dalfox return raw output | NOT MET | `untrusted_content.py:161-185`; `tool_boundary.py:187-192`; `dalfox.py:297-321`; boundary test manually wraps output |
| Code quality/secrets | Clean and no secrets | **PARTIAL**: no known runtime credentials found in current package; exact `except Exception:` count is 220 across 98 files, plus 337 `except Exception as` handlers | NOT MET | independent AST/text scan; current ZIP marker scan count 0 |
| Runtime acceptance | Everything ran and passed | **PARTIAL**: fresh full suite and gates pass; fresh bounded campaigns ran without credentials/LLM, so authenticated/provider qualification is not shown | NOT MET | fresh `2180 passed`; 5 gates exit 0; fresh scratch campaigns `llm_enabled=false` |

## 3. Claim attack matrix

| claim_id | prior statement | verdict | evidence | impact |
|---|---|---|---|---|
| C01 | “M4 is the only credential attachment boundary” | **REFUTED** | `src/webpent/agents/authentication/agent.py:805-817,983-1016,1273-1284`; validator/tool paths pass session cookies/auth headers outside the new ContextAuthority path | A credential-bearing alternate path remains outside the claimed choke point |
| C02 | “Untrusted-content wrapper protects all target content” | **REFUTED** | `tool_boundary.py:187-192` returns raw headers/body preview; `dalfox.py:297-321` returns raw scanner output; boundary test manually wraps after raw exposure | Prompt injection or target-secret exposure remains possible through alternate callers |
| C03 | “All 13 families are live-capable” | **EXTENDED** | Registry/validator/template support exists, but live promotion evidence is uneven; XSS/SQLI/AUTH_BYPASS lack equivalent focused live proof | Registry presence is being mistaken for efficacy |
| C04 | “Three personas are real agents” | **EXTENDED** | Different preferred-family ordering is demonstrable, but allowed tools/focus/template are not dispatched; `all` fails | Behavior difference is narrower than claimed |
| C05 | “Chain engine is verified” | **EXTENDED** | Five patterns and source-input tests pass; both live chain summaries have zero executions and zero reports; report gate trusts booleans | Static/synthetic verification is being presented as live chain proof |
| C06 | “Learning changes priorities” | **EXTENDED** | Consultation and adjustment code exists, but A/B evidence says `improvement_demonstrated:false`, and route modifiers can affect unrelated families | Learning influence and correctness are not established |
| C07 | “Multi-provider failover works” | **EXTENDED** | Pool mechanics and monkeypatched tests pass; runtime traces show OpenAI only | Availability and failover in production remain unverified |
| C08 | “Dashboard tracks cost and time” | **REFUTED** | HTML product renderer has no cost/time fields; completion facade duration is `0.0`; LLM trace is `unpriced` | Operators can see an apparently complete dashboard without actual cost/time truth |
| C09 | “Registration and identity discovery are complete” | **EXTENDED** | Branches exist, but no end-to-end registration test; unsigned identity claims fallback is not wired into verified JWT flow | Foreign-account setup and identity binding can fail silently or trust weak claims |
| C10 | “Clean code quality” | **REFUTED** | Exact scan found 220 plain `except Exception:` handlers in 98 files | Broad exception swallowing can hide security/runtime failures |
| C11 | “Runtime acceptance proves the whole product” | **EXTENDED** | Current full suite is real and green; fresh live hostile runs were unauthenticated and LLM-disabled | Test green-ness does not prove authenticated production behavior |

## 4. New defect register

| id | severity | title | why it matters | evidence | why prior work missed it |
|---|---|---|---|---|---|
| D-01 | P0 | Global M4-only invariant is false | Legacy auth/validator/tool paths can carry credentials outside ContextAuthority | `authentication/agent.py:805-817,1273-1284`; validator/tool call sites | Audit focused on the new HTTPX provisioning path, not alternate browser/legacy paths |
| D-02 | P0 | Raw target output remains available before masking | ToolBoundary and Dalfox expose raw response/header/output material to callers that may feed LLM prompts | `tool_boundary.py:187-192`; `dalfox.py:297-321`; boundary test manual wrapping | The wrapper was tested as an adapter, not enforced at the source boundary |
| D-03 | P1 | Chain reportability trusts executor booleans | A synthetic executor can return confirmed/replay-verified without a proof reference or passed gates | `chain_engine.py:545-550`; forged probe produced a report with `proof_bundle_ref=None` and empty gate list | Tests used a friendly lambda executor and checked positive flags rather than authority provenance |
| D-04 | P1 | API-key auth is absent/misclassified | API-key responses can be treated as Bearer, causing failed login or incorrect credential attachment | `auth_detector.py`; `login_executor.py` API-key field behavior | JWT/cookie happy paths dominated auth testing |
| D-05 | P1 | Identity claim fallback is unsigned and not wired | Numeric `sub/userId` claims can be caller-supplied without signature/issuer/audience validation | `identity_discovery.py:221-225`; production provisioning does not pass claims | “No hardcoded ID” was treated as equivalent to trustworthy ID binding |
| D-06 | P1 | Dashboard/cost truth is incomplete | Duration is hard-coded, LLM usage is unpriced, and preflight is not reconciled to per-call accounting | `service/facade.py:54-65`; `shared/llm.py:304-327`; `product_layer.py:29-54` | Unit tests checked formula shape, not actual campaign reconciliation |
| D-07 | P1 | Persona `all` is a broken advertised mode | CLI/help advertises all, but runtime `get_persona('all')` raises | `cli/commands.py:1219,1511`; `get_persona` behavior | Helper selection test was mistaken for end-to-end dispatch |
| D-08 | P1 | Family coverage is overstated | XSS/SQLI/AUTH_BYPASS lack equivalent live promotion proof; registry/handcrafted observations are weaker | family registry/tests and missing focused live evidence | Registry and unit dispatch tests were counted as runtime efficacy |
| D-09 | P2 | Payload family naming mismatch | `SQL_INJECTION` catalog records are not selected by `SQLI` generator/advisor paths | `payload_library.json`; `hypothesis_generator.py:646-650`; `payload_advisor.py:107-116` | Payload count and metadata tests did not assert SQLI catalog selection |
| D-10 | P2 | Curiosity is not causally connected to ranking | Flags are computed after candidate generation and ignored by deterministic sort | `hunter_runner.py:592-634`; `hunter_graph.py:316-331` | Co-occurrence in artifacts was treated as influence |
| D-11 | P2 | Learning route modifiers can cross families | A family-specific lesson’s route modifier can adjust unrelated families on the same route | `lesson_consultant.py:80-103`; bounded smoke showed cross-family adjustments | Consultation tests asserted adjustment existence, not semantic scope |
| D-12 | P2 | Notes isolation is convention-only | Caller-controlled/reused artifact roots and duplicate historical IDs can collide | `hunter_runner.py:481-508`; duplicate note artifact scan | Separate directories were mistaken for enforced ownership/isolation |
| D-13 | P2 | Exception hygiene is incomplete | 220 exact broad handlers plus 337 named broad handlers remain | independent source scan | A nine-file cleanup was generalized to the repository |
| D-14 | P3 | Historical manifests/reports contradict current state | Several older SHA manifests and reports mismatch current source/counts | historical manifest scan; conflicting report counts | “Latest report” was not separated from archived claims |

## 5. Fat-cat / hidden-risk list

- The green full suite is real, but it is not equivalent to authenticated target qualification. The fresh hostile campaigns ran deterministically with LLM disabled and no credentials.
- The security gates pass while the M4 global boundary is still bypassable through a separate legacy authentication/tool path. The gate checks import authority and denylist properties, not every credential-bearing runtime path.
- The untrusted wrapper is an opt-in adapter. The test itself demonstrates raw content exists before the manual wrap step.
- The Chaining Engine has an authority-shaped interface but its final report gate accepts favorable executor flags without independently proving a sealed chain bundle and passed-gate set.
- The current project contains many historical artifacts with duplicate campaign identifiers and conflicting counts. They are useful history, not current proof.
- The five-gate vault check explicitly states that comparative-flow OQ-3 is not enforced.
- The product layer accepts caller-supplied aggregate cost counters while the LLM trace marks usage unpriced. This can create confident but inaccurate cost dashboards.
- Broad exception handling is much larger than the narrow cleanup claim.

## 6. Internal contradictions

1. The completion language says M4 is the only credential attachment boundary, while `authentication/agent.py`, validator, and tool code still carry cookies/auth headers outside ContextAuthority.
2. The boundary test is named as if ToolBoundary masks output, but it first asserts raw injection is present and only becomes safe after a manual wrapper call.
3. The completion language says chain execution is governed and verified, while current chain artifacts show zero executions and the ChainEngine report gate accepts missing proof reference/empty gate lists when executor booleans are favorable.
4. The project has reports with incompatible full-suite counts, including historical “2,115 passed/8 failed” and later “2,129 passed/0 failed,” while the fresh current run is 2,180 passed.
5. The CLI advertises persona `all`, but the actual single-persona dispatch rejects it.
6. The payload library advertises SQL_INJECTION records, while the generator/advisor lookup uses SQLI and falls back instead of selecting those records.
7. The dashboard/report wording suggests cost/time completeness, while duration is hard-coded to zero and LLM usage is explicitly unpriced.
8. The claim of a standalone Mind Map is contradicted by the source inventory: the active implementation is NoteTaker plus a text filter, not a MindMap module.

## 7. Overclaim / underclaim audit

### What was oversold

- The global claim that M4 is the only credential attachment choke point.
- The claim that all target content is universally masked before any LLM-facing path.
- The claim that all listed vulnerability families are live-proven.
- The claim that personas are three independent behavioral agents.
- The claim that chain execution was verified as a live governed chain.
- The claim that provider failover was production-verified.
- The claim that the product dashboard provides truthful cost/time tracking.
- The claim that code quality was clean after a narrow exception cleanup.

### What was undersold

- The ProofBundle/HMAC/replay implementation is materially real and has meaningful tamper/negative-control tests.
- The current 13-file canonical frozen manifest is independently valid.
- The payload catalog is substantial, internally consistent, and genuinely used for a subset of hypothesis generation.
- NoteTaker and the learning extraction/consultation modules are active code, not empty stubs; their limitations are integration/semantics, not total absence.
- Current full-suite and acceptance results are genuinely reproducible when run from the correct project environment.

### What was labeled done without proof

- End-to-end foreign registration and authenticated identity provisioning.
- Real provider failover across multiple providers.
- Live multi-step chain execution.
- Causal curiosity-driven prioritization.
- CVSS vector/score consistency validation.
- Universal lethal-trifecta protection.

## 8. Minimum honest restatement

The project is a large, testable WebPent codebase with a real ProofBundle/HMAC/replay trust spine and a valid 13-file authority manifest. The full current test suite passes 2,180 tests, the exact acceptance suite passes 20/20 across three rounds, and all five current gates return exit 0. Planner, Exploiter, Validator, auth, provisioning, payload, learning, notes, persona, product, and chaining modules exist. Their guarantees are uneven. M4 is not the only credential path globally. Raw target output remains available through alternate boundaries. Personas mainly change family ordering. Payloads do not cover all catalog families. Provider failover is simulated, not live-proven. Dashboard cost/time truth is incomplete. No live combined chain executed in the inspected evidence. The current status is **PARTIAL, not complete**.

## 9. What would be required before any “PASS”

1. Remove or formally govern every alternate credential-bearing path so ContextAuthority/M4 is the single attachment boundary across browser, legacy validator, tools, and HTTPX paths.
2. Make ToolBoundary and every scanner/target-output return path produce an untrusted, redacted projection by construction; add an end-to-end provider-byte test.
3. Require a sealed chain ProofBundle, proof reference, replay verification, and nonempty passed-gate evidence inside ChainEngine itself, not only as executor booleans.
4. Add API-key-specific detection/material/attachment and PHP/multipart authentication tests.
5. Cryptographically validate identity claims and add an end-to-end two-principal registration/provisioning test.
6. Either implement persona `all` or remove it from CLI/help; add comparable end-to-end runs for NahamSec, STOK, and Logic.
7. Fix `SQL_INJECTION`/`SQLI` family normalization and prove catalog payload use in an executed validator path.
8. Add focused live promotion evidence for XSS, SQLI, and AUTH_BYPASS, or downgrade their claims to registry/unit support.
9. Connect curiosity to a deterministic bounded ranking/selection effect and prove it with before/after tests.
10. Scope learning modifiers by lesson family and demonstrate an A/B priority change with inspectable candidate order.
11. Wire real per-call cost and elapsed-time data to the dashboard and reconcile it against preflight estimates.
12. Validate CVSS vectors semantically against scores.
13. Add collision-resistant per-campaign note ownership and a real standalone Mind Map only if that feature is required.
14. Reduce broad exception handlers or document and gate each remaining one with no silent security-failure swallowing.
15. Re-run authenticated, LLM-enabled Juice Shop and CrAPI campaigns from the corrected source, retain sanitized but independently replayable evidence, and demonstrate at least one genuine combined chain if claiming chain runtime completion.

## 10. Explicit non-findings

- The current canonical frozen authority manifest was not found corrupted: all 13 entries matched.
- The current full suite did not show a failing test: 2,180 tests passed with 10 warnings.
- The current exact acceptance selection did not show a failing round: three rounds reported 20 passed.
- The five current gate scripts returned exit 0 from the correct project directory.
- The current final ZIP integrity check passed, and the known runtime credential marker scan returned zero matches.
- ProofBundle tamper, negative-control, HMAC, and replay-consistency attacks were blocked by the inspected implementation/tests.
- The payload catalog did not show duplicate IDs in the independent count.
- NoteTaker did write sanitized campaign Markdown in the inspected runtime artifacts.
- Curiosity detection did produce bounded anomaly flags; the non-finding is causal influence, not detector absence.
- Learning extraction and consultation did execute in the inspected evidence; the non-finding is demonstrated effectiveness and semantic family isolation.
- Five chain patterns were present; the non-finding is live chain execution and independently enforced chain-proof authority.
- No evidence was found that the current ZIP contains the known operator runtime credentials.
