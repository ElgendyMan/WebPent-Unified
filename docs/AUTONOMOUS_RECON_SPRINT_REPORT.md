# Adapter-Free Autonomous Recon Sprint Report

**Date:** 2026-10-01  
**Working tree:** WebPent current project tree  
**Execution mode:** local loopback targets only; no external target was contacted

## Scope of the change

This sprint adds an adapter-free, URL-driven reconnaissance path:

- `webpent scan --adapter-free` exposes bounded crawler controls.
- `POST /api/v1/recon` exposes the same bounded path behind the existing API role boundary.
- The crawler discovers structural facts only: routes, methods, status codes, content types, digests, forms, parameter shapes, and login/API signals.
- Target response bodies, header values, cookies, authorization material, and prompt-injection text are not returned in the surface map.
- Hypotheses are advisory and are delegated to the existing `ModernOrchestrator → AVI → validators → ProofBundle → ReplayVerifier → PromotionPipeline` chain.
- No target adapter is imported by the new recon package or production facade.

## Validation

| Check | Result |
|---|---:|
| Full regression suite | **2042 passed, 0 failed** |
| Acceptance round 1 | **20 passed** |
| Acceptance round 2 | **20 passed** |
| Acceptance round 3 | **20 passed** |
| `check_state_contract.py` | **EXIT 0** |
| `check_orchestrator_construction_authority.py` | **EXIT 0** |
| `check_isolation_denylist.py` | **EXIT 0** |
| `check_vault_import_authority.py` | **EXIT 0** |
| `verify_test_count.py` | **EXIT 0**; 2042 collected, floor 1940 |
| Direct-I/O inventory | **Regenerated canonically; drift test passed** |
| Frozen trust-spine comparison | **Matched validated archive** |

The full suite emitted only the project’s existing development-key and HTTPX deprecation warnings; no test failed.

## Campaign A — OWASP Juice Shop

- Target: local `http://127.0.0.1:3000`
- Adapter used: **false**
- Scope source: `inferred_from_url`
- Pages/endpoints observed: **21**
- Forms: **0**
- Parameters: **1**
- Executable hypotheses: **10**
- Governed decisions: **10**
- Promoted: **0**
- Rejected: **10**
- Crawl duration recorded by the crawler: **1.216 seconds**

The run successfully traversed the static frontend resources and discovered API-like routes without importing the Juice Shop adapter. The observed candidates were rejected by the existing validation/promotion chain in this unauthenticated run; no false promotion was forced.

## Campaign B — Controlled local second target

- Target: local `http://127.0.0.1:8765`
- Adapter used: **false**
- Scope source: `inferred_from_url`
- Pages/endpoints observed: **4**
- Forms: **1**
- Parameters: **3**
- Hypotheses: **6**
- Executable hypotheses: **5**
- Governed decisions: **5**
- Promoted: **1**
- Rejected/inconclusive: **4**
- Crawl duration recorded by the crawler: **0.270 seconds**

### Promoted finding

- Finding ID: `finding_open_redirect_009fbaa2`
- Family: `OPEN_REDIRECT`
- Validator outcome: `CONFIRMED`
- Promotion decision: `PROMOTED`
- Promotion pipeline: `PromotionPipeline_v1`
- Proof bundle: `proof_bundle_384ef3aacb034ed1b4e667a747c6b01d`
- Proof origin: `target_runtime`
- Validator: `canonical_validator_open_redirect`
- Proof sealed: **yes**
- Replay verified: **yes**
- Real HTTP executed: **yes**
- Audit trace: **chain_verified=true**, **full_coverage=true**, **65 stages**
- Promotion gates failed: **none**

The causal evidence was a three-request sequence: baseline `200`, candidate external redirect `302`, and negative control `200`. The artifact stores request/response digests and status codes, not raw response bodies or credential material.

### Non-promoted outcomes

The same run also produced rejected or inconclusive outcomes for information disclosure and IDOR candidates. The IDOR candidates remained fail-closed because no two-principal credential context was supplied to this unauthenticated adapter-free run.

## Kill-switch verification

A separate run halted after two observed pages and five callback checks:

- `crawl_halted=true`
- `decisions_executed=0`
- `halted_before_execution=true`
- `next_action_was_suppressed=true`

This demonstrates that the stop callback is checked before continuing discovery and before entering governed execution. The existing durable campaign ledger remains the production mechanism for operator-triggered halt/resume control.

## Security and redaction observations

- The serialized campaign artifacts contain no `Authorization:` value, bearer token, `Set-Cookie` value, password assignment, or target prompt-injection text.
- The new recon path does not attach credentials. Credential attachment remains owned by M4/context authority.
- External redirect behavior was observed as a response signal; the HTTP boundary did not follow the unallowlisted external destination.
- The existing trust spine and frozen modules were not modified.

## Cost and timing accounting

- LLM calls: **0** for this adapter-free deterministic discovery path.
- LLM cost: **0** for this run.
- The current adapter-free result schema records crawler duration, but does not yet emit a wall-clock `time_to_first_finding` metric. Recorded crawl durations are shown above; an exact first-finding wall-clock value is therefore **not claimed**.

## Deliverables

- Source: `src/webpent/recon/autonomous_crawler.py`
- Source: `src/webpent/recon/hypothesis_generator.py`
- Production facade: `src/webpent/production/autonomous_recon.py`
- CLI/API integration: `src/webpent/cli/commands.py`, `src/webpent/api/app.py`
- Juice Shop artifact: `artifacts/autonomous_recon_juice_shop_20261001/`
- Controlled-target artifact: `artifacts/autonomous_recon_second_target_20261001/`
- Read-only dashboard render: `artifacts/autonomous_recon_second_target_20261001/dashboard_render.txt`
