# Generalization Test — Phase 3 Diagnosis

**Run date:** 2026-10-02  
**Scope:** untouched Phase 2 runs against the official CrAPI compose gateway, DVWA, and WebGoat.  
**Important:** No WebPent source, validators, trust-chain module, or target-specific adapter was modified during Phase 2.

## 1. Executive result

The untouched system **did not generalize sufficiently** beyond the Juice Shop-shaped path. It successfully started the same bounded HTTPX crawler and 3-agent Planner → Exploiter → Validator loop on all three targets, but only CrAPI produced executable hypotheses. No target produced a promoted finding.

The evidence shows a mixed result:

- **Systemic:** the core production trace did not enter the required deep-recon/AVI/promotion stages in these runs; form applications were not discovered past redirect entrypoints; the generic runner had no authenticated-principal provisioning for non-Juice-Shop targets; and the live LLM budget was consumed during the CrAPI campaign before all planned advisory work completed.
- **Partially generic:** structural crawling, audit finalization, redaction-safe LLM calls, and deterministic status accounting worked across all targets; CrAPI route discovery and hypothesis generation worked without target-specific code.
- **Not proven overfit:** the Phase 2 run did not establish that validators themselves are Juice-Shop-specific because DVWA/WebGoat generated no executable candidate, and CrAPI candidates reached governed validation but not promotion. A validator-specific conclusion requires post-fix form/API fixtures or executed cross-stack candidates.

**Verdict at this stage:** the system is **overfitted/under-generalized in discovery and execution readiness**, while its safety and audit layers generalized.

## 2. Untouched Phase 2 observed results

| Target | URL used | Routes crawled | Crawl events | Hypotheses | Executable | LLM calls | Cost | Validator outcomes | Promoted |
|---|---|---:|---:|---:|---:|---:|---:|---|---:|
| CrAPI | `http://127.0.0.1:8888` | 20 | 35 | 8 | 4 | 12 | $0.04902600 | 5 inconclusive, 1 refuted | 0 |
| DVWA | `http://127.0.0.1:8081` | 1 | 30 | 0 | 0 | 1 | $0.00301325 | none | 0 |
| WebGoat | `http://127.0.0.1:8082/WebGoat` | 1 | 30 | 0 | 0 | 1 | $0.00206525 | none | 0 |

All three campaigns finalized and independently verified their campaign audit chain. The runner recorded real guarded LLM calls and actual token-derived cost. No promoted finding or bounty report was generated.

### 2.1 CrAPI

**What worked:**

- The application was discovered and 20 routes were structurally recorded.
- Eight hypotheses were generated, including executable information-disclosure, open-redirect, XSS, and SSRF-shaped candidates.
- Four candidates were marked executable and six graph-level validation outcomes were recorded.
- One candidate was refuted and five were inconclusive; no false positive was promoted.
- Planner, Exploiter, and Validator nodes were exercised.

**What broke or remained incomplete:**

- The production trace remained incomplete: it saw only entrypoint/scope/audit lifecycle stages and listed missing deep-recon, bounded-tool-execution, observation, proof-bundle, and promotion stages.
- The report recorded identity binding as unbound and real HTTP execution as false for the governed candidates. This prevented an honest promotion.
- The twelve-call cap was exhausted before provider I/O for a later advisory request (`LLM call budget exhausted before provider I/O: calls=12 max=12`). This is a budget/graph accounting limitation, not evidence of a target vulnerability.
- No authenticated CrAPI owner/foreign principals were provisioned by the untouched generic runner; therefore BOLA/IDOR and privilege-escalation claims were not actually exercised.

### 2.2 DVWA

**What worked:**

- The DVWA process was healthy at the HTTP boundary and the root route returned a redirect.
- One real guarded Planner LLM call and audit-chain finalization completed.

**What broke:**

- The crawler recorded only the root route (`302`) and did not follow the redirect to the login surface.
- Zero hypotheses and zero executable candidates were generated.
- Session-cookie authentication was not detected or provisioned by the untouched runner, so DVWA's forms, SQLi, XSS, command-injection, and file-inclusion surfaces were never reached.
- Consequently no validator was exercised; it is not valid to claim that DVWA validators failed.

### 2.3 WebGoat

**What worked:**

- The official WebGoat application was made healthy on `/WebGoat` after setting its documented separate WebWolf port; the root path returned a redirect to login.
- One real guarded Planner LLM call and audit-chain finalization completed.

**What broke:**

- The crawler recorded only the `/WebGoat` redirect entrypoint and did not follow the login redirect.
- Zero hypotheses and zero executable candidates were generated.
- Spring Security/session authentication was not detected or provisioned by the untouched runner.
- No validator was exercised, so no validator-specific failure can be claimed.

## 3. Answers to the required diagnosis questions

### 3.1 Did validators assume Juice Shop response patterns?

**Not conclusively demonstrated in Phase 2.** CrAPI reached governed validation and produced five inconclusive plus one refuted result, but no confirmed result. DVWA and WebGoat never reached a validator because discovery stopped at redirects. The honest finding is that validator generality is **unproven**, with an existing systemic blocker before validation.

### 3.2 Did identity binding assume JWT?

**The system is not yet authentication-general.** The untouched runner configured `principal_count=0`, and CrAPI's trace reported identity binding as unbound. DVWA's session-cookie model and WebGoat's Spring Security session were not provisioned. This is a systemic contract gap: M4 needs an auth-provider abstraction that can attach JWT, cookie/session, or other explicitly registered credential material without sending secrets to the LLM.

### 3.3 Did the hypothesis generator only understand REST APIs?

**The observed result strongly indicates a form/redirect discovery gap.** CrAPI's REST-shaped surface generated eight hypotheses. DVWA and WebGoat exposed redirect entrypoints but generated zero hypotheses. The generator's form capabilities could not be evaluated because the crawler did not fetch the redirected login pages. A generic HTML form → hypothesis path is required and must be tested with synthetic/form fixtures, not target-name branches.

### 3.4 Did the crawler handle PHP and Java applications?

**It handled the initial HTTP boundary but not redirect-driven application traversal.** Both DVWA/PHP and WebGoat/Java returned valid redirects; the crawler stopped at one route and did not reach the actual login/form/application pages. This is a generic redirect-following and same-origin traversal defect, not a PHP- or Java-specific parser defect proven by evidence.

### 3.5 Was the payload library effective on different stacks?

**Not evaluated for DVWA/WebGoat; partially exercised on CrAPI.** The library was available in the system, and CrAPI candidates carried payload/WSTG metadata, but no cross-stack form candidate reached execution. There is no honest basis to claim payload success or failure on DVWA/WebGoat from this run.

## 4. Classification

### 4.1 Systemic, target-agnostic components

1. **Redirect traversal/readiness:** the bounded crawler does not reliably follow same-origin HTTP redirects from the initial entrypoint.
2. **Auth mechanism abstraction:** the generic campaign path does not detect and provision session-cookie authentication alongside bearer/JWT-style identities.
3. **HTML form surface modeling:** redirect-following prevents generic login and form fields from entering the structural surface map and hypothesis generator.
4. **Generic principal binding for M4:** authenticated owner/foreign/control identities are not available to the generic runner; `principal_count=0` means BOLA/IDOR cannot be tested.
5. **Production/AVI stage accounting:** the trace reports the deep execution/proof/promotion stages missing even when the graph runs, so the current path cannot prove full-chain execution on these targets.
6. **LLM budget accounting:** the graph consumes the bounded call budget across planner/exploiter/validator advisory roles without reserving capacity or producing a clean per-target budget outcome before provider attempts.

### 4.2 Components that may be Juice-Shop-specific

No component is proven Juice-Shop-specific solely by this Phase 2 evidence. The following are **suspect rather than confirmed**:

- Any validator branch relying on JSON `data` envelopes or Juice Shop status/body conventions.
- Any identity adapter that assumes the Juice Shop bearer-token flow.
- Any route heuristic that names Juice Shop endpoints.

These must be tested by generic fixtures and removed or generalized only if the fixture confirms a real defect.

### 4.3 Partially generic components

- **Crawl and structural redaction:** works on the initial HTML/redirect boundary and fully on CrAPI, but does not yet traverse redirects into form applications.
- **Hypothesis generation:** works for discovered REST/API-like routes; form coverage is not reachable in the current flow.
- **3-agent coordination:** Planner/Exploiter/Validator events work, but the governed Exploiter path did not establish real M4/AVI request execution in these runs.
- **Audit and security boundary:** audit chains verify on all targets and raw target content/credentials were not returned to LLM prompts; this part generalized successfully.

## 5. Phase 4 fix boundary

The only justified next fixes are generic and must apply to Juice Shop, CrAPI, DVWA, and WebGoat:

1. Follow bounded same-origin redirects and preserve redirect targets as structural route events.
2. Parse HTML forms generically, including method/action, field names/types, hidden fields, and login signals; never retain raw form bodies in LLM context.
3. Add an auth-mechanism abstraction for explicitly supplied M4 aliases that can represent bearer/JWT and session-cookie material; secrets remain M4-only.
4. Make the execution/trace contract report actual governed request stages or clearly label a no-execution outcome; do not manufacture proof or promotion.
5. Reserve and account for graph LLM calls so budget exhaustion is a clean, auditable halt rather than a late provider-I/O exception.

No target names, target-specific paths, credentials, or response-format workarounds are justified by this diagnosis.

## 6. Evidence locations

- Untouched raw per-target results: `docs/generalization_evidence/phase2_raw/`
- CrAPI report: `docs/generalization_evidence/phase2_raw/crapi/HONEST_REPORT.md`
- DVWA report: `docs/generalization_evidence/phase2_raw/dvwa/HONEST_REPORT.md`
- WebGoat report: `docs/generalization_evidence/phase2_raw/webgoat/HONEST_REPORT.md`
- Each target's `campaign_summary.json`, `hunter_state.json`, `graph_trace.json`, `llm_calls.json`, `audit_verification.json`, and dashboard render are in its target directory.

## 7. Phase 3 verdict

**The system is overfitted/under-generalized to Juice Shop at the discovery and authenticated-execution boundary.** The safety boundary, audit verification, and bounded advisory orchestration generalized; application traversal, form/auth discovery, generic M4 identity provisioning, and complete AVI execution evidence did not.
