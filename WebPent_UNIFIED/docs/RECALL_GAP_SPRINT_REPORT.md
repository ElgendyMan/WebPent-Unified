# Hunting Effectiveness Sprint — Close the Recall Gap

**Target:** `http://127.0.0.1:3000` (official OWASP Juice Shop v20.2.0)
**Final campaign:** `recall-gap-llm-20261001t130445z`
**Run date:** 2026-10-01

## Verdict

**PASS for the stated campaign acceptance criteria.** The final run used the enabled live `gpt-5-mini` provider, generated 39 executable hypotheses across all active families, and promoted four replay-verified findings from four families. The 8 rejected/refuted validator outcomes were retained as negative evidence and no rejected candidate was reported as a bounty finding.

The specific Juice Shop `/rest/products/search?q=` JSON endpoint remained inconclusive for XSS in the governed HTTP validator. The promoted XSS was a separate real reflected-input surface at `/redirect?to=`. This report does **not** claim that the product-search endpoint was promoted.

## Baseline diagnosis

The pre-fix diagnosis campaign (`recall-gap-diagnosis-20261001t114609z`) observed 32 routes, generated 43 hypotheses, executed 33, and promoted 0. The main causes were:

| Surface/family | Observed failure | Root cause | Corrective action |
|---|---|---|---|
| `/rest/basket/{id}` IDOR | IDOR was generated but deferred | No two authenticated principals were provisioned in the baseline run | Provisioned owner/foreign users through M4 vault-bound bearer attachment and corrected the owner-resource request contract |
| `/rest/user/login` SQLi | Login was recognized but body execution was not faithful | Generated JSON body metadata was not translated into `Content-Type`; the selected body value was not exposed to the deterministic validator | Added governed content-type translation and selected-body payload evidence |
| `/rest/products/search?q=` XSS | JSON API response did not reflect HTML | The API endpoint returns JSON and is not the browser search-box surface | Added JavaScript/heuristic discovery for `/search?q=`, plus bounded HTML-compatible payload selection |
| `/search?q=` XSS | Route was previously absent from the crawler | Angular/frontend route was not in the bounded route queue | Added same-origin frontend search heuristic and route normalization |
| `/rest/admin/application-version` | Endpoint was found but the proof path was not promoted | Version disclosure needed endpoint-aware semantic evidence and replay-preserved URL metadata | Added safe request URL/structural metadata; the final campaign still rejected this candidate because the promotion semantic path did not meet the configured disclosure contract |
| Admin/debug and API surfaces | Coverage was sparse | JavaScript/API/hidden-route discovery was incomplete | Added bounded JS route extraction, common route heuristics, and per-parameter family expansion |
| SSRF/open redirect | Candidates existed but most were not confirmation-grade | Validators correctly required target-side causal indicators | Added payload library/advisory selection and retained fail-closed validator behavior |

## Final live campaign evidence

- **LLM:** enabled; `gpt-5-mini`; 6 real calls; payload advice was recorded and validated against the bounded payload library.
- **Cost:** `$0.0241355` actual provider-derived cost, below the `$1.00` acceptance limit.
- **Duration:** `171.332s` total wall time; below the 10-minute limit.
- **Crawl:** 33 routes, 50 crawl events, one-request-per-second campaign bound.
- **Hypotheses:** 39 generated and 39 executable across AUTH_BYPASS, BOLA, IDOR, INFO_DISCLOSURE, OPEN_REDIRECT, SQLI, SSRF, and XSS.
- **Principals:** owner and foreign users were provisioned through M4; credentials were not persisted in evidence and were not sent to the LLM.
- **Promotions:** 4; every promoted decision had all promotion gates passing and replay verification true.
- **Validator refutations:** 8; no refuted candidate was promoted.

### Promoted findings

| Family | Resource | Finding ID | ProofBundle | Replay |
|---|---|---|---|---|
| IDOR | `/rest/basket/1` | `finding_idor_0d3b5d82` | `proof_bundle_a37a347f0aec423b9cef59e3539913fc` | PASS |
| BOLA | `/rest/basket/1` | `finding_bola_f2c916ab` | `proof_bundle_16ae7bab069a4903a4508e05ac0c6856` | PASS |
| SQLI | `/rest/user/login` | `finding_sqli_bf3f7729` | `proof_bundle_97ac4775fbb94c619a2a591341fe434e` | PASS |
| XSS | `/redirect?to=` | `finding_xss_a69f6fbb` | `proof_bundle_b153555152e44e1388b16d4a65cb963f` | PASS |

The IDOR proof used the real owner/foreign/control triple. Juice Shop returns HTTP 200 with a null data envelope for an invalid basket; the validator now accepts that only as an independent control when the structural null-data signal or normalized body fingerprint is distinct, while still requiring owner/foreign identity separation and successful unauthorized access.

## Safety and integrity

- Execution remained under `ModernOrchestrator`, `ScopeLaw`, AVI, M4, and `PromotionPipeline`; no frozen trust authority was weakened.
- Target content remained untrusted. LLM prompts received structural projections and payload-library identifiers, not raw target bodies, headers, credentials, or vault material.
- The final promoted ProofBundles were sealed, replay-verified, target-backed, and had no failed promotion gates.
- The campaign's summary and cost files contain numeric token/cost evidence; they do not contain API keys, bearer tokens, passwords, or raw target bodies.

## Validation status

The final targeted post-fix regression set passed **25 tests**. The final full suite passed **2082/2082** with zero failures. Each of the exact three acceptance rounds passed **20/20**; all five security gates exited 0; and the frozen manifest verified **13/13** files. Results are recorded under `docs/recall_gap_evidence/validation/` and in `docs/FULL_SUITE_EVIDENCE.txt`.

## Reproducible evidence

- `scripts/run_recall_gap_diagnosis.py` — baseline structural diagnosis.
- `scripts/run_recall_gap_llm_campaign.py` — bounded live LLM campaign runner.
- `docs/recall_gap_evidence/diagnosis/` — sanitized pre-fix diagnosis evidence.
- `docs/recall_gap_evidence/final_campaign/` — sanitized v9 campaign, LLM, cost, payload, and result evidence.
