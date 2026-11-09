# RAG + Learning Loop Sprint — Final Report

**Run date:** 2026-10-01  
**Target:** local official OWASP Juice Shop v20.2.0 at `http://127.0.0.1:3000`  
**Campaigns:** `learning-demo-20261001t111635z-a` and `learning-demo-20261001t111635z-b`  
**Client scope:** `learning-demo-client`

## Executive result

The additive learning loop is implemented and verified. Two real, adapter-free Juice Shop campaigns completed with a live `gpt-5-mini` advisory call in each campaign. Campaign B retrieved lessons produced by Campaign A and applied them only to advisory hypothesis ordering. The system did **not** manufacture a security improvement:

- **Learning consultation:** observed in Campaign B (`5` lesson IDs, `5` family hits, `5` route hits, `10` lesson hits in metrics).
- **Lessons persisted:** `10` negative lessons (`8 INFO_DISCLOSURE`, `2 SSRF`).
- **Promoted findings:** `0` in both campaigns.
- **Refuted findings:** `5` in each campaign.
- **Improvement verdict:** **NOT DEMONSTRATED**. B had lower measured LLM advisory cost and slightly shorter wall time, but promoted yield did not increase and remained zero.
- **Trust-chain result:** no promotion authority was bypassed; no bounty report was generated because no promoted sealed finding existed.

This is an honest partial outcome, not a failed implementation claim.

## Live A/B measurements

| Metric | Campaign A | Campaign B |
|---|---:|---:|
| Wall duration | 22.514 s | 22.435 s |
| LLM advisory calls | 1 | 1 |
| Model/provider | `gpt-5-mini` / `openai` | `gpt-5-mini` / `openai` |
| Input tokens | 2,431 | 2,431 |
| Output tokens | 3,772 | 3,121 |
| Actual derived cost | $0.00815175 | $0.00684975 |
| Hypotheses generated | 11 | 11 |
| Hypotheses tested | 11 | 11 |
| Promoted | 0 | 0 |
| Refuted | 5 | 5 |
| Inconclusive | 6 | 6 |
| Lesson hits | 0 | 10 |
| Applied lessons | 0 | 5 |
| Audit verification | `verified: true` | `verified: true` |

Costs are calculated from provider-reported tokens and the live catalog rates used by the runner: `$0.25/M` input and `$2.00/M` output. Raw target bodies, headers, cookies, and credentials were not sent to the LLM or retained in the package evidence.

## Implemented changes

1. **Structured lesson contracts** — typed lesson, provenance, confidence, source-campaign, and priority-adjustment models.
2. **Scoped lesson storage** — SQLite-backed structured lessons keyed by client, target type, family, route pattern, and source campaign; legacy APIs remain compatible.
3. **Proof-gated extraction** — positive, negative, priority, and coverage lesson extraction from actual campaign outcomes; no lesson can create proof or promotion authority.
4. **Advisory consultation** — client-isolated consultation with family/route matching and bounded priority adjustments. It never skips candidates, expands scope, or promotes findings.
5. **Recon integration** — optional client-scoped consultation is wired into hypothesis ordering; existing unscoped behavior remains backward-compatible.
6. **Writeup/CVE parser and CLI extensions** — deterministic structural parsing with explicit `--writeup`, `--cve`, and `--no-llm` options. Optional LLM enhancement receives masked structural summaries only.
7. **RAG ingestion hardening** — mixed-source `source_id` deduplication is now idempotent across one batch; duplicate ingestion returned `0` chunks.
8. **Improvement tracker and dashboard** — per-campaign cost, timing, tested/promoted/refuted/inconclusive counts, lesson hits, and effectiveness are exposed in a read-only Learning section.
9. **Denylist/inventory maintenance** — the shifted bounded loader import is explicitly reviewed and the direct-I/O inventory was regenerated from the canonical scanner.

## RAG ingestion evidence

Four public sources were ingested in an isolated vector store:

- PortSwigger IDOR writeup: `IDOR` structural entries.
- PortSwigger XSS writeup: `XSS` structural entries.
- PortSwigger SSRF writeup: `SSRF` structural entries.
- Official NVD JSON for `CVE-2021-44228`: one `UNKNOWN` family entry because the parser does not invent an unsupported vulnerability family.

Observed results: **12** parsed/added entries, **0** entries added on the duplicate batch, and **4** filtered query results for an IDOR authorization/parameter query. Only parser-generated structural summaries were stored; source bodies were not passed to campaign prompts.

## Validation evidence

- Full suite: **2079 passed, 0 failed, 0 skipped, 0 errors**; new failures vs baseline: `0`.
- Exact acceptance round 1: **PASS**.
- Exact acceptance round 2: **PASS**.
- Exact acceptance round 3: **PASS**.
- `check_state_contract`: exit `0`.
- `check_orchestrator_construction_authority`: exit `0`.
- `check_isolation_denylist`: exit `0`.
- `check_vault_import_authority`: exit `0`.
- `verify_test_count`: exit `0`.
- Frozen manifest: **MATCH / exit 0**, 13 frozen files verified.
- Focused learning/RAG/recon tests: **18 passed** in the final focused regression set.

An earlier validation attempt run from `/home/ubuntu` produced environment-only errors (`pytest`, `yaml`, and manifest path unavailable). It was discarded and rerun from the project root; the corrected validation above is the authoritative result.

## Evidence and limitations

The package contains sanitized campaign decision projections, LLM token/cost telemetry, audit JSONL/workspace files, dashboard render, learning metrics, RAG ingestion evidence, and validation logs. Raw campaign result files containing target response material and runtime SQLite/vector-store databases are intentionally excluded.

No submission-ready bounty report is included: the actual campaigns produced zero promoted findings, so the report quality gate correctly emitted no report.

> **Verdict:** implementation and safety gates **PASS**; real learning-loop improvement criterion **NOT DEMONSTRATED** on this Juice Shop A/B sample.
