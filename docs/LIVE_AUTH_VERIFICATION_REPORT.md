# Live Auth and Concrete Exploiter Verification

**Date:** 2026-10-02  
**Scope:** authorized local Juice Shop and official OWASP crAPI lab services only  
**Execution path:** structural crawler → generic auth detector/login executor → M4 vault → Hunter graph → ModernOrchestrator/AVI → ProofBundle/replay/PromotionPipeline

## Final result

- **Juice Shop:** authentication, M4 binding, concrete execution, and one genuine promoted IDOR verified.
- **CrAPI:** authentication and M4 binding verified; no promoted finding. The documented BOLA endpoint returned HTTP 404 for both valid contexts.
- **Overall two-target promotion objective:** **PARTIAL/FAIL** because CrAPI promotion was not observed.

## Juice Shop

- The authorized foreign principal was registered in the local lab and independently verified with HTTP 200 and a token-bearing response.
- Owner and foreign contexts were separately sealed and verified through M4.
- Campaign: `hunter-24db436e5d3d`.
- Observed usage: 3 LLM calls, `$0.01341075`.
- Validation: 1 confirmed, 0 refuted, 1 inconclusive, 0 blocked.
- Audit chain: verified, 12 events.
- Promoted result: one IDOR with real HTTP execution, semantic identity binding, sealed ProofBundle, replay verification, and all eight promotion gates passed.

## CrAPI

- Two separate operator-supplied principals authenticated successfully and were independently M4-bound.
- Campaign: `hunter-2662b3a53e71`.
- Observed usage: 3 LLM calls, `$0.01607175`.
- Validation: 0 confirmed, 0 refuted, 1 inconclusive, 1 blocked.
- Audit chain: verified, 12 events.
- Manual probe of `/identity/api/v2/user/1`: both authenticated contexts returned HTTP 404. No BOLA is claimed.

## Final code fixes verified

- Provisioning now uses the same canonical `sha256_text(target_url)[:16]` fingerprint as AVI/M4. This fixed the prior false `x_user_not_vault_bound` condition caused by a raw-string fingerprint mismatch.
- Provisioning now exercises M4 `authorize_execution → resolve` before reporting `vault_bound=true`.
- Planner provider/JSON failures fall back only to already-existing governed candidate catalog entries; no arbitrary route or payload invention was introduced.
- Concrete baseline/candidate/negative-control request triples are preserved through the Exploiter boundary.

Focused auth, M4, concrete-request, planner-fallback, and replan tests passed. No raw passwords, bearer tokens, cookie values, target bodies, or credential files are included in this report or the sanitized evidence projections.
