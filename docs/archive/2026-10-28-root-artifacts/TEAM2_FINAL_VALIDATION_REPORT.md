# Team-2 Final Validation Report — WebPent Ultimate

## Verdict

**Runtime chain is proven on authorized local WebGoat, but no security finding is promoted.**

The final governed campaign completed the browser-discovery → LLM advisory → AVI execution → CausalGuard → ProofBundle/replay/promotion decision chain. All final decisions were **INCONCLUSIVE**; therefore no reportable finding is claimed.

## Runtime evidence

| Control | Observed result |
|---|---:|
| Local scope violations | 0 |
| Browser SPA states explored | 20 |
| Structural browser routes/forms merged | 31 / 32 |
| Routes crawled in final campaign | 37 |
| Candidates generated / executable | 60 / 10 |
| Real LLM calls | 21 |
| LLM model | gpt-5-mini |
| Input / output tokens | 64164 / 40172 |
| Calculated LLM cost | $0.096385 |
| Production trace complete | True |
| Audit chain verified | True |
| Confirmed / promoted findings | 0 / 0 |

## What was repaired

1. Browser crawler waits briefly for SPA DOM hydration and preserves same-origin fragment states.
2. Presentation/session query variations no longer consume the browser page budget as duplicate states.
3. Same-origin browser-observed form metadata is merged as **structural facts only** into recon.
4. LLM advisory prompts receive redacted request metadata only; body values, headers, query values, and credential-shaped assignments remain outside the prompt. The governed concrete specs are restored only after catalog selection, inside the existing AVI path.

## Truthful outcome

The campaign exercised 21 real guarded LLM invocations and 11 governed validation outcomes. All 11 required more evidence; zero ProofBundle references and zero replay-verified promotions were produced. That is a correct fail-closed result, not a vulnerability claim.

## Validation

- Focused regression suite: **51 passed**.
- No scope violations were recorded.
- Production trace included all required stages, including world-model mutation, research decision, bounded tool execution, observation, outcome recording, CausalGuard, ProofBundle, replay, and promotion decision.
- The audit chain finalized and verified successfully: `eaf077734c02d6f5a0c540ea5e51eac85185eb7df06ba731dbbceb6e5d9d2ee1`.

## Artifact map

- [Structured final evidence](TEAM2_FINAL_EVIDENCE.json)
- `validation-runtime/webgoat_hunt/campaign_summary.json` — campaign summary
- `validation-runtime/webgoat_hunt/HONEST_REPORT.md` — failure-first campaign report
- `validation-runtime/webgoat_hunt/audit_verification.json` — audit proof
- `validation-runtime/webgoat_hunt/graph_trace.json` — planner/exploiter/validator trace
- `validation-runtime/webgoat_hunt/llm_calls.json` — redaction-safe LLM usage telemetry

No credential, key, authorization header, session token, raw request body, or raw response body is included in this report.
