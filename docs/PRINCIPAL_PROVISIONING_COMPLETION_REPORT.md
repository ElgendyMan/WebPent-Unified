# Principal Provisioning and Concrete Exploiter — Final Gap-Closure Report

**Run date:** 2026-10-02  
**Scope:** authorized local Juice Shop and CrAPI targets; the earlier four-target baseline also covered DVWA and WebGoat.  
**Execution path:** bounded HTTPX recon → generic auth detection/login → M4 vault → Hunter Planner/Exploiter/Validator → ModernOrchestrator/AVI → ProofBundle/replay/PromotionPipeline

## Executive verdict

**PARTIAL — Juice Shop regression passed; CrAPI generalization did not produce a promotion.**

The system now performs real two-principal provisioning, uses the same canonical target fingerprint as AVI/M4, builds concrete owner/foreign/control request triples, and can fall back to the existing governed candidate catalog when an advisory Planner response fails. A genuine Juice Shop IDOR was promoted through the full runtime chain. CrAPI authentication and M4 binding succeeded, but the documented BOLA endpoint returned `404` for both valid principals; no CrAPI vulnerability is claimed.

The requested outcome of promoted findings on both targets was therefore **not met**. No false positive was promoted and no finding was fabricated.

## Final implementation changes

- `src/webpent/recon/auth_detector.py`: generic structural detection for password forms, API/JWT login shapes, session-cookie names, Basic challenges, OAuth redirects, and registration surfaces; no token or cookie values are returned.
- `src/webpent/recon/login_executor.py`: bounded same-origin login with hidden-field preservation, conservative form/API/Basic handling, in-memory bearer/cookie capture, safe validation, and redacted serialization.
- `src/webpent/recon/principal_provisioning.py`: up to three operator-supplied principals, canonical owner/foreign role mapping, registration fallback only when operator-authorized, M4 sealing, and **authorize/resolve verification before `vault_bound=true` is reported**.
- **Final bug fix:** principal provisioning now uses `sha256_text(target_url)[:16]`, exactly matching AVI/M4. Previously it used a raw-string SHA-256 digest, so sealing appeared successful but AVI looked up a different vault binding.
- `src/webpent/agents/hunter_graph.py`: explicit bounded `replan` node after actual `INCONCLUSIVE` results, maximum three replans per hypothesis, sanitized feedback, and catalog-only fallback when advisory Planner JSON/provider execution fails.
- `src/webpent/agents/hunter_runner.py` and `src/webpent/recon/hypothesis_generator.py`: concrete IDOR/BOLA request metadata is preserved and hydrated into baseline/candidate/negative-control specs; credentials never enter LLM prompts or evidence.
- CLI runtime credential input remains supported through JSON or a local ignored file; no runtime credential file was committed.

## Security properties verified

- Credentials are operator-supplied at runtime only.
- Successful login evidence contains only alias, role, auth type, status, material kind/name, and digest.
- M4 is the only credential attachment boundary; AVI blocks unbound principals fail-closed.
- Concrete requests are still executed through ScopeLaw/ToolBoundary/ModernOrchestrator/AVI.
- No raw target response body, token, cookie value, password, or Authorization value was placed in LLM prompts or final evidence projections.
- The frozen manifest remains byte-identical: **13/13 files match**.
- Direct-I/O inventory was regenerated from the canonical AST scanner: **618 records, 94 approved, 20 pinned known-unapproved records**.

## Focused and acceptance tests

- Principal/auth/graph/generalization focused suite: **20 passed**.
- Canonical direct-I/O inventory suite after regeneration: **4 passed**.
- Exact 20-test acceptance input:

| Round | Result |
|---|---:|
|---|---:|
| 1 | 20 passed |
| 2 | 20 passed |
| 3 | 20 passed |

**Acceptance reproducibility:** **YES — 20/20 in all three rounds.**

## Security gates

| Gate | Result |
|---|---|
| `check_state_contract.py` | PASS, exit 0 |
| `check_orchestrator_construction_authority.py` | PASS, exit 0 |
| `check_isolation_denylist.py` | PASS, exit 0 |
| `check_vault_import_authority.py` | PASS, exit 0 |
| `verify_test_count.py` | PASS, exit 0; 2,123 collected before the final full-suite run |
| Frozen manifest | PASS, 13/13 byte-identical |

## Full-suite evidence

Final command: `PYTHONPATH=src pytest tests/ -q --tb=no`

**2,115 passed, 8 failed, 23 warnings.**

The eight failures are inherited environment/async/browser families and are not in the changed principal-provisioning or concrete-exploiter tests:

- system Chromium readiness;
- two WebSocket/webhook tests;
- one async TLS factory test;
- two OOB/database parity tests;
- two async SSRF/mock tests affected by nested event-loop teardown.

The direct-I/O drift failure from the first final run was resolved by canonical regeneration; the final full-suite run no longer reports that failure.

## Live Juice Shop campaign

A foreign account was registered in the authorized local Juice Shop lab and then verified independently with a successful login response containing a token. The campaign used two separate runtime principals, two M4-bound bearer materials, and concrete IDOR requests.

| Metric | Result |
|---|---:|
| Campaign | `hunter-24db436e5d3d` |
| Routes crawled | 35 |
| Candidates generated / executable | recorded in sanitized evidence projection |
| LLM calls | 3 |
| Observed LLM cost | `$0.01341075` |
| Confirmed / refuted / inconclusive / blocked | 1 / 0 / 1 / 0 |
| Audit chain | verified; 12 events |
| Promotion | **1 PROMOTED IDOR** |

The promoted finding had real HTTP execution, M4 identity binding, a confirmed causal differential, a sealed ProofBundle, replay verification, and all eight PromotionPipeline gates passed. Finding ID: `finding_idor_0d3b5d82`.

This is a genuine non-simulated Juice Shop result. It is the only promoted finding claimed in this report.

## Live CrAPI campaign

Two separate operator-supplied CrAPI principals authenticated successfully and were independently M4-bound. The governed campaign reached AVI with concrete requests, but the generated basket route was not present in this CrAPI deployment.

| Metric | Result |
|---|---:|
| Campaign | `hunter-2662b3a53e71` |
| Routes crawled | 25 |
| Candidates generated / executable | 20 / 5 |
| LLM calls | 3 |
| Observed LLM cost | `$0.01607175` |
| Confirmed / refuted / inconclusive / blocked | 0 / 0 / 1 / 1 |
| Audit chain | verified; 12 events |
| Promotion | **0** |

### Manual BOLA verification

The documented endpoint `/identity/api/v2/user/1` was probed with both valid authenticated contexts:

- both login attempts: HTTP `200`, token present;
- both BOLA probes: HTTP `404`;
- response bodies were represented only by digests in the local diagnostic output.

The endpoint therefore did not demonstrate the requested cross-user data access in this container state. The result is **not a system-confirmed BOLA**.

## Trace and replan note

The focused graph regression proves explicit replan events are emitted only after actual `INCONCLUSIVE` verdicts and are capped at three. An earlier bounded CrAPI smoke also recorded a complete production trace containing `replan`. The final Juice and CrAPI campaign traces did not require a replan stage in the specific executed decision sequence; the final evidence does not claim `replan` occurred when that trace stage was absent.

## Evidence files

Sanitized final projections are in [`docs/gap_closure_evidence/`](./gap_closure_evidence/):

- `juice_shop_final.json` — promoted Juice Shop finding and redacted principal/audit metrics.
- `crapi_final.json` — CrAPI M4/auth/decision metrics and no-promotion result.
- `crapi_manual_bola.json` — manual endpoint status projection.

The full campaign artifact trees remain local runtime evidence and are excluded from the sanitized release archive.

## Final limitations

1. The Juice Shop acceptance target was achieved with one genuine promoted IDOR.
2. The CrAPI promotion target was not achieved because the tested deployment returned `404` for the documented BOLA endpoint; no endpoint invention or target-specific hardcoding was added.
3. The overall full-suite result remains partial because of eight inherited environment/async/browser failures.
4. No estimate-versus-actual cost claim is made beyond the observed provider usage values above; the final runs used actual reported token-cost traces.
