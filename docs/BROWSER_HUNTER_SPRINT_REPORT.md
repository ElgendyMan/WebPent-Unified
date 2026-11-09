# Browser Hunter Sprint — Final Report

**Run date:** 2026-10-02  
**Target:** `http://127.0.0.1:3000` (official OWASP Juice Shop, local loopback)  
**Campaign:** `browser-hunter-juice-20261001t212143z`

## Executive result

The Browser Hunter layer was restored and exercised against the live Juice Shop target. Browser reconnaissance, structural StateGraph generation, JavaScript analysis, real guarded LLM planning, and governed AVI delegation all ran. The run produced **no promoted finding** and therefore no bounty report. This is recorded as an honest **functional acceptance FAIL/PARTIAL**, not converted into a synthetic success.

## Observed campaign measurements

| Metric | Observed value |
|---|---:|
| Rendered pages visited | 3 |
| HTTP routes crawled by governed crawler | 33 |
| StateGraph nodes / transitions | 3 / 2 |
| JavaScript bundles analyzed | 100 |
| JavaScript endpoint candidates | 300 |
| Hidden route candidates | 200 |
| Intercepted browser traffic events | 0 observed |
| Curiosity flags | 26 |
| Deterministic candidates generated / executable | 20 / 10 |
| Real guarded LLM calls | 1 |
| Model | `gpt-5-mini` |
| Input / output tokens | 5,974 / 1,725 |
| Actual LLM cost | **$0.00494350** |
| Wall-clock campaign duration | 53.789 seconds |
| Promoted / confirmed findings | 0 |
| Refuted findings | 0 |
| Inconclusive findings | 0 |
| Audit chain | **verified: true** |

The live cost calculation used the catalog rates of $0.25/M input tokens and $2.00/M output tokens. No target body, credential, or raw authorization material was written to the campaign evidence.

## Browser and security boundary

- Browser contexts for owner/foreign aliases were created separately; the isolation artifact records `isolated: true`.
- Browser traffic and response handling uses the `UntrustedContent` boundary and stores placeholders, digests, shapes, and header names rather than raw content.
- JavaScript secret-like strings are masked and represented by digest/length metadata.
- Planner output is schema-checked; malformed items are rejected individually and cannot crash or bypass the graph.
- Actual execution remains delegated to `ModernOrchestrator/ScopeLaw/AVI/PromotionPipeline`; the browser layer is advisory reconnaissance only.
- Credentials remain M4-only by contract.

The canonical campaign sidecar recorded **zero intercepted traffic events** even though the rendered crawler visited three pages. This is an observed instrumentation gap, not evidence that no browser network traffic occurred; the release includes the empty sidecar and does not claim complete traffic capture.

## Acceptance interpretation

- Browser reconnaissance: **PASS** — rendered crawl and structural artifacts were produced from the live target.
- Real LLM usage and cost evidence: **PASS** — one live `gpt-5-mini` call with numeric token/cost telemetry.
- Audit verification: **PASS** — chain root `c58f75e61c7d507646a65d70f97dc2ff670489bf8a092d229dde1d37d1514061` verified.
- Promoted finding requirement: **NOT MET** — 0 confirmed/promoted findings.
- Refuted finding requirement: **NOT MET** — 0 refuted findings.
- Full production trace completeness: **NOT MET** — the trace reports missing deep-recon, execution, observation, proof, and promotion stages for this runner path. This limitation is preserved rather than hidden.
- Full suite: **PARTIAL** — 2,100 passed, 8 failed, 0 skipped out of 2,108. The eight failures were in existing Chromium/system-browser and async webhook/OOB/TLS test areas; they are listed in `FULL_SUITE_EVIDENCE.txt` and were not represented as Browser Hunter successes.
- Exact acceptance rerun: **PASS** — 20/20 in each of three rounds.
- Five security gates: **PASS** — all five exit 0.
- Frozen manifest: **PASS** — 13 files unchanged.

## Verdict

**PARTIAL / FAIL for end-to-end hunting acceptance.** The implementation and evidence boundaries work, but this run did not demonstrate a promoted Juice Shop vulnerability and the direct-invoke production trace remained incomplete. No claim of a discovered vulnerability is made.

## Evidence

The canonical run is under `docs/browser_hunter_evidence/campaign/`. The raw working artifact was retained outside the release archive for local audit at:

`artifacts/browser-hunter-juice-20261001t212143z/`
