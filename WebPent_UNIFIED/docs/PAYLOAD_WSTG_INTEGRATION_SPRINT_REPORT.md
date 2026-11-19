# Payload Library + OWASP WSTG Integration — Final Report

**Run date:** 2026-10-01  
**Canonical source-matched campaign:** `recall-gap-llm-20261001t143038z`  
**Target:** authorized local OWASP Juice Shop at `http://127.0.0.1:3000`  
**Adapter mode:** adapter-free autonomous recon (`adapter_used: false`)

## Executive result

The sprint is **complete and validated**. PayloadsAllTheThings and OWASP WSTG were parsed as bounded advisory data, ingested into the knowledge store, connected to hypothesis generation, included in redaction-safe LLM payload-selection prompts, and carried into governed decision evidence.

The final source-matched live campaign completed through the existing `ModernOrchestrator → ScopeLaw → M4 → AVI → ProofBundle → Replay → PromotionPipeline` path:

- **3 promoted findings** across `IDOR`, `BOLA`, and `SQLI`.
- **9 validator-refuted candidates**; refuted candidates were not promoted.
- **27 rejected decisions**.
- All promoted findings used real authorized HTTP execution, sealed ProofBundles, and replay verification.
- **6 live `gpt-5-mini` calls**, including one preflight and five payload-selection batches.
- **Actual calculated LLM cost:** `$0.017244` using the recorded provider token counts and the live catalog rates (`$0.25/M` input, `$2.00/M` output).
- **Campaign duration:** `132.217 s`; total wall time `136.617 s`.
- **33 routes** and **50 crawler events** were recorded.
- **39 hypotheses** were generated and executable; **36** carried a parsed payload ID and **38** carried a WSTG reference.
- LLM prompts contained structural route/parameter/status metadata, bounded payload catalog entries, and bounded WSTG methodology/expected-behavior projections; raw target bodies, headers, cookies, and credentials were excluded.

## Parsed source and provenance

| Source | Pinned commit | Parsed count | Tree SHA-256 prefix/full evidence |
|---|---:|---:|---|
| PayloadsAllTheThings | `3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a` | 1,421 payload entries | Recorded in `source_provenance.json` |
| OWASP WSTG | `8df290a38090b8d2235caa52a25a13e021af6670` | 116 test documents; 37 mapped tests | Recorded in `source_provenance.json` |

Payload family counts:

- `SQL_INJECTION`: 573
- `XSS`: 368
- `SSRF`: 211
- `AUTH_BYPASS`: 118
- `INFO_DISCLOSURE`: 106
- `OPEN_REDIRECT`: 42
- `IDOR`: 3

WSTG mapped-family counts:

- `AUTH_BYPASS`: 18
- `INFO_DISCLOSURE`: 13
- `XSS`: 3
- `IDOR`: 1
- `SQLI`: 1
- `SSRF`: 1

The parser treats upstream Markdown as data. Fenced blocks are extracted and classified; no source code from the upstream repositories is executed. Payloads are labelled `local_authorized_probe` or `catalog_only` and remain test inputs, not trust decisions.

## Knowledge-store ingestion

The real `webpent knowledge update` command completed successfully:

```json
{"ingested": {"payloads": 1421, "wstg": 116}, "status": "ok"}
```

Each knowledge entry includes source attribution and `scope: global_advisory`. The ingestion path uses the existing vector-store boundary and does not write client-scoped lessons or vault material.

## Final campaign outcomes

| Family | Finding ID | WSTG reference | ProofBundle | Outcome |
|---|---|---|---|---|
| IDOR | `finding_idor_0d3b5d82` | `WSTG-ATHZ-04` | `proof_bundle_bc75258997294999a256142996ec419e` | PROMOTED |
| BOLA | `finding_bola_f2c916ab` | `WSTG-ATHZ-04` | `proof_bundle_69d8d1c7f654499cbd1869f3262ba017` | PROMOTED |
| SQLI | `finding_sqli_bf3f7729` | `WSTG-INJT-05` | `proof_bundle_4ffeacd267e74b5aac1554d3ac248a43` | PROMOTED |

For all three promoted decisions:

- `real_http_executed = true`
- `proof_sealed = true`
- `replay_verified = true`
- The promotion decision came from the existing pipeline; the payload/WSTG layer did not alter thresholds or promotion authority.

Refuted candidates by family:

- `INFO_DISCLOSURE`: 6
- `AUTH_BYPASS`: 1
- `OPEN_REDIRECT`: 1
- `XSS`: 1

## LLM and safety evidence

The final call log records six provider-backed calls with provider `openai`, model `gpt-5-mini`, numeric input/output/total token fields, latency, prompt/completion digests, and calculated cost. The existing router's `pricing_status: unpriced` field is not used as actual cost; the runner independently applies the live catalog rates to recorded token counts.

M4 provisioned disposable `owner` and `foreign` principals. Their credentials were not persisted in artifacts and were never included in LLM prompts. The final sanitized evidence contains no raw target bodies or credential values.

## Validation

- Full suite: **2097 passed / 0 failed / 0 skipped / 0 errors**.
- New failures versus baseline: **0**.
- Acceptance rounds: **3/3 passed**, with all three configured acceptance test files passing in each round.
- Security gates: **5/5 exit code 0**.
  - `check_state_contract`: 0
  - `check_orchestrator_construction_authority`: 0
  - `check_isolation_denylist`: 0
  - `check_vault_import_authority`: 0
  - `verify_test_count`: 0
- Frozen manifest: **MATCH / OK**, 13 frozen files unchanged.
- Direct-I/O inventory: canonical scanner regeneration completed; **593 records**, **86 approved**, **20 pinned known-gap records**; inventory test passed.

## Honest attempt history

The first catalog-enabled attempt stopped before result serialization due to a stale local variable introduced by the additive decision-metadata projection. It is recorded as a failed attempt and is not used as success evidence. The narrow fix was followed by a successful retry and then a final source-matched canonical rerun after adding bounded WSTG methodology to the LLM prompt. The canonical final run is the only run used for the final campaign claims.

## Deliverables

- `src/webpent/recon/payload_library.py` — deterministic parser and selection API.
- `src/webpent/recon/wstg_catalog.py` — deterministic WSTG parser, aliases, mappings, and query API.
- `src/webpent/memory/knowledge_ingest.py` — payload/WSTG ingestion and bounded local search.
- `src/webpent/recon/payload_advisor.py` — bounded external-catalog + WSTG-aware LLM advisory selection.
- `src/webpent/cli/commands.py` — `webpent knowledge update`, `status`, and `search` commands.
- `docs/payload_library.json` and `docs/wstg_catalog.json` — reproducible exports.
- `docs/payload_wstg_evidence/` — provenance, ingestion result, canonical campaign evidence, prior attempt evidence, and validation logs.
- `docs/FULL_SUITE_EVIDENCE.txt` — authoritative full-suite evidence.

## Verdict

**PASS.** The requested payload/WSTG integration is implemented, used in a real live Juice Shop campaign, produced multiple governed promoted findings, retained fail-closed trust-chain behavior, and passed the complete regression, acceptance, gate, frozen-manifest, and direct-I/O validation set.
