# Ultimate Validation Sprint — Final Evidence Report

**Run date:** 2026-10-04  
**Workspace:** `/tmp/webpent_vuln_arsenal`  
**Authorization boundary:** local Juice Shop, CrAPI, WebGoat, and DVWA only. No external VDP target was contacted.

## Executive verdict

**Overall verdict: PARTIAL / NOT READY FOR REAL ENGAGEMENT.**

The trust, scope, audit, browser, regression, and live-campaign controls produced useful evidence. The latest bounded Juice Shop rerun produced **3 confirmed/promoted findings with sealed ProofBundle references and replay verification**, but the sprint still does not satisfy the complete requested acceptance bar: CrAPI produced no promoted BOLA, WebGoat and DVWA had no operator principals and therefore no qualified findings, and a complete production trace was not demonstrated on the latest Juice run because `replan` was not observed. No external VDP target was contacted.

No vulnerability is claimed from a status code, shaped request, curiosity flag, login signal, or an inconclusive result alone.

## Changes completed in this continuation

- Added the requested additive `webpent scope check --url URL --scope FILE` command. It parses the typed policy and performs a local `ScopeEnforcer.check_url` decision without target network activity.
- Added focused scope CLI coverage and regression coverage for promotion/ProofBundle projection.
- Corrected runtime decision-model normalization in the chain projection without changing the frozen trust spine.
- Separated audit telemetry anchors from the bounded execution-stage budget; execution stages remain fail-closed at the configured limit.
- Preserved the M4-only credential boundary and added bounded `identity_paths` loader support for live identity discovery.
- Regenerated the canonical direct-I/O inventory after review; it remains **624 records** and its focused test passes.

## Target summary

| Target | Live/scoped activity | Authentication evidence | Campaign result | Audit | Verdict |
|---|---|---|---|---|---|
| Juice Shop | HTTP target healthy; browser crawl completed; deterministic family probes completed; several bounded agent-hunt runs; latest v4 rerun crawled 35 routes | Latest v4: API-JWT detection; owner and foreign principals succeeded, were M4-bound, and identity discovery succeeded through `/api/Users` | Latest v4: **3 confirmed/promoted**, 0 inconclusive, 0 refuted; 3 sealed ProofBundle references and replay verification | Verified; 24 events. Latest production trace is incomplete only because `replan` was not observed | **PARTIAL — finding evidence exists, complete sprint objective not met** |
| CrAPI | HTTP gateway and related local gateway ports scoped; 27–29 routes crawled; workshop/community seed paths configured | Regression v2 admitted 2 principals with identity discovery and M4 binding | Regression v2: 0 confirmed, 12 inconclusive, 1 blocked, 0 refuted. No promoted workshop/community BOLA | Verified; 52 events | **FAIL objective** |
| WebGoat | 1 route crawled under typed local scope | No operator principals supplied; auth detector reported `none` | 0 candidates, 0 confirmed, 0 refuted; no qualified execution campaign | Verified | **NOT QUALIFIED** |
| DVWA | 1 route crawled under typed local scope | Form-session signal detected, but no operator principals supplied | 0 candidates, 0 confirmed, 0 refuted; no qualified execution campaign | Verified | **NOT QUALIFIED** |

## Live campaign accounting

The table below includes all completed campaign summaries currently under the sprint evidence directory. These are separate bounded runs, not a claim that their findings are all unique.

| Campaign artifact | LLM calls | Actual recorded cost | Routes | Confirmed | Inconclusive | Refuted | Audit verified |
|---|---:|---:|---:|---:|---:|---:|---|
| `campaigns/crapi` | 32 | $0.13541375 | 27 | 0 | 16 | 0 | true |
| `campaigns/crapi_r2` | 20 | $0.07742750 | 27 | 0 | 9 | 0 | true |
| `campaigns/crapi_regression_v2` | 32 | $0.12665525 | 29 | 0 | 12 | 0 | true |
| `campaigns/dvwa` | 1 | $0.00086775 | 1 | 0 | 0 | 0 | true |
| `campaigns/juice_regression` | 20 | $0.07566325 | 35 | 0 | 0 | 0 | true |
| `campaigns/juice_regression_v2` | 19 | $0.07402200 | 35 | 0 | 0 | 0 | true |
| `campaigns/juice_regression_v3` | 23 | $0.09423000 | 35 | 2 | 0 | 0 | true |
| `campaigns/juice_regression_v4` | 7 | $0.03197775 | 35 | **3** | 0 | 0 | true |
| `campaigns/webgoat` | 1 | $0.00109650 | 1 | 0 | 0 | 0 | true |
| **All completed artifact totals** | **155** | **$0.61735375** | — | **5** | **37** | **0** | — |

Pricing uses the live built-in model catalog preflight for `gpt-5-mini`: `$0.25/M` input and `$2.00/M` output. Costs above are read from campaign traces/artifacts, not estimates. The v4 campaign used 7 calls, 21,975 input tokens, 13,242 output tokens, and recorded `$0.03197775`.

## Latest Juice Shop v4 evidence

- Campaign: `regression-juice-live-v4-20261003`
- Routes crawled: 35
- Executable candidates: 2
- Validation counts: **3 confirmed, 0 inconclusive, 0 refuted, 0 blocked**
- Confirmed references: 3 hypothesis IDs, each with a `proof_bundle_ref` and `replay_verified: true`
- Audit: 24 events; `verified: true`
- Scope: 0 violations; local Juice Shop policy remained active
- Credentials: owner and foreign principals succeeded and were M4-bound; no credentials/tokens are included in the artifacts
- Production trace: 37 total entries, 13 bounded execution stages; `complete: false` because `replan` was not observed. This limitation is retained rather than hidden.
- Chain engine: 0 combined chains and 0 generated bounty reports. This is expected because the strict report generator requires a CVSS score and justification in addition to the sealed ProofBundle.
- Campaign runtime: 179.13 seconds. A timestamp for the first finding was not captured, so no first-finding latency claim is made.

Sanitized v4 artifacts are under `campaigns/juice_regression_v4/`, including `campaign_summary.json`, `hunter_state.json`, `audit_verification.json`, `cost_report.json`, `dashboard_render.md`, and `chain_summary.json`.

## Vulnerability-family matrix

| Family | Tested | Confirmed/promoted | Evidence | Status |
|---|---|---:|---|---|
| IDOR | Yes; Juice identity/object hypotheses were executed through the governed path | **At least 1 in latest v4** | v4 contains sealed ProofBundle references and replay verification; exact vulnerability narrative still requires report-quality CVSS metadata | **Live evidence exists; not submission-ready** |
| BOLA | Yes; CrAPI identity, workshop, and community seed paths were configured | 0 | CrAPI principals were admitted in regression v2, but all governed outcomes remained inconclusive/blocked and no ProofBundle was promoted | **Not proven** |
| XSS | Yes; Juice family probes and campaign family attempts | 0 | No reflection/validator/promotion proof | **Not proven** |
| SQL injection | Shaped Juice login probe performed | 0 | Authentication-shaped response was only an interesting signal; no governed baseline/candidate/control and 8-gate ProofBundle | **Not proven** |
| SSRF | Shaped Juice probe performed | 0 | No internal-access proof or promotion | **Not proven** |
| Open redirect | Redirect probe performed | 0 | No validated redirect proof | **Not proven** |
| Information disclosure | `/.env`, `/admin`, and `/debug` metadata probes performed | 0 | SPA-equivalent response digests; no disclosure proof | **Not proven** |

## Browser-layer evidence

Browser validation is operational but partial:

- Target: local Juice Shop instance.
- Pages visited: **3**.
- Intercepted traffic events: **500**.
- State nodes: **3**.
- Queue outcome: `queue_exhausted`.
- Sanitized evidence: `browser/browser_juice_shop.json`.
- No JavaScript-source count was captured (`0` in the sanitized metric); this is a measurement gap, not proof that the target has no JavaScript.

## Scope and VDP preparation

Typed local scope policies exist for all four labs under `scopes/`. The CrAPI policy permits the main local gateway (`8888`) and the observed official local gateway-related ports (`8443`, `30080`, `30443`) while retaining denial for arbitrary ports such as `9999`.

The additive local command was verified:

```text
webpent scope check --url https://api.github.com/v1/users --scope docs/ultimate_validation_20261003/vdp/github_scope.yaml
```

It returned `IN_SCOPE`, `allowed: true`, and a policy fingerprint. An out-of-scope control returned `OUT_OF_SCOPE`, `allowed: false`, and `violation_category: unknown_scope`. Focused scope tests: **13 passed** in the latest continuation run.

VDP YAMLs are candidate policy artifacts, not authorization:

- Yahoo: current source-derived policy explicitly denies Yahoo assets listed as out of scope by the fetched current policy.
- Comcast: conservative review-required policy because the fetched static policy did not provide a complete asset list.
- GitHub: candidate wildcard policy; `thirdparty.github.com` can match the wildcard, so ownership/asset-list confirmation is required before use.

No request was made to any external VDP asset.

## Audit, trust-chain, and frozen evidence

- Latest Juice v4 audit: 24 events, verified true.
- CrAPI regression v2 audit: 52 events, verified true.
- WebGoat and DVWA audits: verified true.
- The 13 frozen modules listed in `docs/P1_BASELINE_PROVENANCE.txt` were SHA-256 checked and all matched, including frozen `llm_researcher/tool_boundary.py` (`c46608c3add66d66...`).
- Direct-I/O inventory: regenerated deliberately after review, **624 records**, site set unchanged; focused inventory test passed.
- No frozen module was modified by this continuation.

## Final validation results

- Production-spine import: **IMPORT_OK**.
- Full suite: **2201 passed, 0 failed, 9 warnings**.
- Acceptance round 1: **20/20 passed**.
- Acceptance round 2: **20/20 passed**.
- Acceptance round 3: **20/20 passed**.
- `check_state_contract`: **exit 0**.
- `check_orchestrator_construction_authority`: **exit 0**.
- `check_isolation_denylist`: **exit 0**.
- `check_vault_import_authority`: **exit 0**.
- `verify_test_count`: **exit 0** (`2201 >= 1940`).
- Direct-I/O regeneration: **exit 0** (`624 -> 624`, site set unchanged).
- Direct-I/O focused tests: **4 passed**.
- Frozen manifest: **all 13 MATCH**.
- Scope/production regression focused tests: **5 passed**; scope-focused run before the final full validation had **13 passed**.

## Reporting decision

No submission-ready bounty report is included. The latest Juice campaigns contain promoted ProofBundle references, but the strict bounty reporter correctly refuses to fabricate a report when a CVSS score and justification are absent from the live finding projection. A report generated from the SQLi-shaped response, a curiosity flag, or an inconclusive CrAPI candidate would violate the report quality gate.

## Remaining blockers for READY

1. Bind a governed CVSS score/vector and justification to the promoted Juice findings, then generate reports only from the sealed ProofBundles.
2. Complete the production trace contract on the latest live path, including an observed `replan` stage where the campaign actually needs it.
3. Resolve CrAPI workshop/community candidate inconclusiveness and obtain at least one independently replay-verified promoted BOLA, if the local deployment exposes one.
4. Supply authorized operator principals and target-specific login configuration for WebGoat and DVWA, then rerun bounded campaigns.
5. Complete the browser JavaScript-source metric comparison.

**Readiness:** the codebase and regression gates are green; live engagement qualification is **PARTIAL**, not READY.
