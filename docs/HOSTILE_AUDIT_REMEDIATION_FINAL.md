# WebPent Hostile-Audit Remediation — Final Record

**Working tree:** recovered complete project under `/tmp/webpent_remediation_project`

## Result

The audited defects were remediated without changing the frozen trust spine. The final tree compiles, the complete regression suite is green, the current acceptance set is reproducible, all five security gates pass in the project environment, and the authoritative 13-file frozen manifest matches byte-for-byte.

## Remediation completed

### Evidence and reporting integrity

The bounty-report generator now requires a promoted status, an authentic sealed ProofBundle, replayable evidence, eight promotion gates, and request/response sequences whose digests and response statuses match the sealed bundle exactly. Tampered URLs, digests, statuses, ordering, and refuted findings are rejected. The fresh demo reports are generated from actual decision payloads and not from historical fixture artifacts.

### Authority and manifest integrity

`verify_frozen_manifest.py` is now the explicit authority check. It rejects missing entries, duplicate entries, path traversal, symlink escapes, stale hashes, and mismatches. The 13 authoritative trust-spine files all match. Historical manifests remain historical; they are not used as the current authority.

### Adapter-free recon

The recon path preserves discovered request method, body, query, and parameter location. BOLA/IDOR hypotheses are deferred unless two principals are available. SSRF candidates are generated only from structurally observed URL/resource signals. The production facade reports generated, executable, deferred, and deferred-reason counts instead of silently presenting advisory hypotheses as executable findings.

The CLI now supports repeatable inline `--scope` entries in addition to `--scope-file`, and the API accepts normalized scope entries plus a bounded principal count. Raw credentials are still not accepted by the adapter-free endpoint; credential attachment remains an M4 responsibility. Explicit scope entries with non-default ports are rejected by the existing scope grammar; local loopback targets use the safer inferred-from-URL exact-host path.

### Multi-campaign service hardening

Campaign identifiers are validated against a safe identifier grammar before they influence paths. Metadata is recursively sanitized before persistence. Per-campaign action reservations are bound to the manager’s configured budget and maximum-action limits. Health checks use the authoritative frozen-manifest verifier, and recurring health scheduling state is persisted instead of being only a caller-controlled in-memory claim.

### Security inventory

The checked-in direct-I/O JSON and Markdown artifacts were regenerated from the canonical AST scanner after remediation edits. The current scan contains 578 records, 20 pinned unapproved records, and 67 unknown-family records, with the existing fail-closed policy preserved. No new unreviewed site was silently approved.

## Fresh two-target execution

`scripts/run_scaling_demo.py` now delegates to the fresh runner rather than importing old campaign evidence. `scripts/run_fresh_two_target_demo.py` starts two independent loopback targets and executes both campaigns concurrently through the production spine.

| Campaign | Real decisions | Promoted | Refuted | Reports |
|---|---:|---:|---:|---:|
| fresh-target-a | 5 | 1 | 4 | 1 JSON + 1 Markdown |
| fresh-target-b | 5 | 1 | 4 | 1 JSON + 1 Markdown |

Each promoted open-redirect decision has a sealed ProofBundle, three executed requests, three response observations, replay metadata, causal confirmation, semantic identity binding, and all eight promotion gates. Refuted decisions do not generate bounty reports. The service kill switch was exercised per campaign: halt moved `fresh-target-a` to `OPERATOR_HALTED`, the next reservation was denied, and resume returned it to `RUNNING`.

## Independent validation

| Check | Result |
|---|---:|
| `python -m compileall -q src tests scripts` | PASS |
| Full suite | 2052 passed, 0 failed |
| Current I-3/I-2 acceptance round 1 | 20 passed |
| Current I-3/I-2 acceptance round 2 | 20 passed |
| Current I-3/I-2 acceptance round 3 | 20 passed |
| `check_state_contract.py` | exit 0 |
| `check_orchestrator_construction_authority.py` | exit 0 |
| `check_isolation_denylist.py` | exit 0 |
| `check_vault_import_authority.py` | exit 0 |
| `verify_test_count.py` | exit 0; 2052 collected, floor 1940 |
| `verify_frozen_manifest.py` | exit 0; 13/13 hashes match |
| G-02 direct-I/O tests | 4 passed |

The original patch-chain acceptance filenames `test_sprint_i3_e2e_walking_skeleton.py` and the earlier I-2 path are absent from the recovered complete tree. The current equivalent I-3 vertical-flow test plus the current I-2 walking-skeleton and hotfix tests were used, producing 20/20 in all three rounds. This naming limitation is recorded rather than hidden.

## Evidence locations

- Fresh demo summary: `artifacts/fresh_two_target_demo_20261001/demo_summary.json`
- Fresh dashboard projection: `artifacts/fresh_two_target_demo_20261001/dashboard_render.json`
- Fresh generated reports: `artifacts/fresh_two_target_demo_20261001/reports/`
- Current direct-I/O inventory: `docs/direct_io_inventory.json` and `docs/DIRECT_IO_INVENTORY.md`
- Authoritative frozen manifest: `docs/integration/WEBPENT_AUTHORITY_MANIFEST.json`
- Manifest verifier: `scripts/verify_frozen_manifest.py`
