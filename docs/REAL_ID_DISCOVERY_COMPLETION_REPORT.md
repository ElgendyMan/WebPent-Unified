# Real-ID Discovery Completion Report

**Date:** 2026-10-03  
**Workspace:** `/tmp/webpent_gap_closure_fixed/webpent`

## Executive result

The real-ID discovery implementation is complete and verified. It discovers authenticated principal IDs from same-origin protected responses, matches IDs in generic user collections by the operator profile identifier, falls back to numeric JWT claims, and feeds only governed concrete request specs into M4/AVI.

The Juice Shop regression promoted three access-control findings through the existing trust chain. The current CrAPI deployment did not produce a promotion: the discovered owner ID was real, but the requested `/identity/api/v2/user/{id}` resource route returned `404` for baseline, candidate, and negative control. The system rejected that result rather than manufacturing a BOLA.

## Implementation

- Added `src/webpent/recon/identity_discovery.py`.
  - Same-origin, bounded requests through `make_safe_httpx_client`.
  - Candidate order: operator-declared paths, `/identity/api/v2/user/me`, `/current`, `/identity/api/me`, and `/identity/api/v2/user/dashboard`.
  - Generic matching by `email`, `username`, `user_name`, or `login` for collection responses.
  - Numeric JWT `userId`, `user_id`, `userid`, or `sub` fallback without signature claims entering artifacts.
  - Derives sibling `/{id}` templates only from an observed self/dashboard path.
  - Serialized evidence contains presence, digest, source, status, names, and templates; not tokens, passwords, or raw responses.
- Extended principal provisioning to run identity discovery after successful login and expose redacted availability metadata plus runtime-only IDs.
- Extended concrete IDOR/BOLA generation to use discovered owner/foreign IDs and derive a bounded negative control (`max(observed IDs)+1` for numeric IDs).
- Added principal-identifier matching for generic user collections, enabling operator configuration such as `/api/Users` outside WebPent source.
- Added a planner/catalog guard so a real identity-template candidate remains inside the bounded catalog and is selected before generic access-control guesses when two distinct principals are available.
- Normalized all generated request paths to same-origin relative paths before AVI joins them to the target URL.
- No frozen trust module was changed.

## Live CrAPI result

- Target: `http://127.0.0.1:8888` (authorized local lab gateway).
- Both owner and foreign profiles authenticated successfully.
- Dashboard discovery returned owner ID `5` and foreign ID `8`.
- Identity template derived from the observed dashboard route: `/identity/api/v2/user/{id}`.
- Governed real-ID triple:
  - baseline: `GET /identity/api/v2/user/5` with owner context → `404`
  - candidate: `GET /identity/api/v2/user/5` with foreign context → `404`
  - negative control: `GET /identity/api/v2/user/9` with foreign context → `404`
- Validator outcome: **INCONCLUSIVE**; promotion: **REJECTED**; no finding ID or ProofBundle was created.
- Independent manual probe of the documented video resource showed owner access `200` and foreign access `404`; this is not a BOLA and was not promoted.
- Campaign metrics: 14 LLM calls, actual cost `$0.05783625`, validation counts `blocked=4`, `inconclusive=1`, `refuted=1`, `confirmed=0`.
- Audit chain: **verified**, 12 events, root `ccefeb294e8a59b374554d51886f06899d98c9c7b51344c63faa306544c73151`.

## Live Juice Shop regression

- Target: `http://127.0.0.1:3000` (authorized local lab).
- Owner and registered foreign profiles authenticated successfully.
- Operator runtime configuration used `/api/Users` as an identity collection path; no target-specific code was added.
- The concrete access-control requests used owner resource `/rest/basket/1` and derived negative control `/rest/basket/26`.
- Result: **3 PROMOTED** access-control findings (`2` BOLA and `1` IDOR record in the campaign summary), all with real runtime request sequences and sealed promotion evidence.
- Campaign metrics: 14 LLM calls, actual cost `$0.0596025`, validation counts `blocked=2`, `confirmed=3`, `inconclusive=1`, `refuted=0`.
- Audit chain: **verified**, 12 events, root `47afaddebbec01bf29791270b88941cef3c58448900c9f44ab88f046a1c2dbf4`.

## Automated verification

| Check | Result |
|---|---:|
| Focused identity/provisioning/graph/recon tests | 29 passed |
| Full suite | 2129 passed, 0 failed |
| Direct-I/O inventory contract | 4 passed |
| Acceptance round 1 | 20/20 passed |
| Acceptance round 2 | 20/20 passed |
| Acceptance round 3 | 20/20 passed |
| Reproducibility | Yes, 20/20 in all 3 rounds |
| Frozen manifest | OK, 13/13 files |
| `check_state_contract` | exit 0 |
| `check_orchestrator_construction_authority` | exit 0 |
| `check_isolation_denylist` | exit 0 |
| `check_vault_import_authority` | exit 0 |
| `verify_test_count` | exit 0; 2129 collected, floor 1940 |
| Direct-I/O inventory | 621 records; 95 approved; 20 pinned unapproved |

## Acceptance statement

- **Real-ID discovery:** PASS.
- **Juice Shop regression:** PASS; promoted findings remain available through the trust chain.
- **CrAPI promotion requirement:** NOT MET in this deployment; the route tested from discovered identity data is not present (`404/404/404`). This is an observed target limitation, not a fabricated success.
- **Trust-chain safety:** PASS; non-confirmed CrAPI evidence produced no reportable finding, no ProofBundle, and no finding ID.
