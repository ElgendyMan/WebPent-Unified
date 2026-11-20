# G-02 Dynamic-Resolution Hardening Report

**Scope:** `WEBPENT_G02_DYNAMIC_RESOLUTION_HARDENING_PLAN.md`
**Repository:** `ElgendyMan/webpent-v61`
**Pre-change HEAD:** `b4bc981a6ff774d3bc278f977d4c406d3163bb08`
**Release lineage:** hardening commit `8e3701e87c7780569716b9fb1b75f7e6206f3813`; manifest/report delivery lineage currently ends at `111cab77d47498c7a7a5fe8449145b968c81caa9`
**Run date:** 2026-08-22

## Executive result

The verified F1 static-analysis bypass was reproduced before the fix and is now rejected fail-closed. The primary scanner detects `getattr(sys.modules["subprocess"], "run")` as an unapproved `dynamic_resolution` record, while the independent secondary scanner agrees and reports no cross-check error. Expiry metadata is now enforced as an injected-date TTL rather than decorative text. Six adversarial indirection regressions are present and pass.

This report qualifies the **G-02 dynamic-resolution hardening scope only**. It does not qualify the project as a VIP autonomous bug hunter, and it does not establish any live target finding or confirmed vulnerability.

## Phase evidence

### Phase 1: pre-fix reproduction

The isolated `/tmp/g02_repro` fixture reproduced the bypass before source changes. The pre-fix run returned no record for the planted `evil_agent` file, no unapproved records, no cross-check errors, and `FULL VERDICT PASSED: True`. The fixture and runner were kept outside the repository.

### Phase 2: resolver and secondary hardening

The primary resolver now handles constant-string AST subscripts such as `sys.modules["subprocess"]`, resolves local aliases derived from those subscripts, and does not silently drop unresolved `getattr` calls. The secondary scanner independently observes coarse `getattr(` dynamic-resolution sites, preserves tokens after string literals, handles multiline calls, and avoids Python 3.12 f-string token false positives. Cross-check keys include `dynamic_resolution` records consistently.

The exact post-fix replay produced:

```text
records mentioning backdoor file: [{'file': 'src/webpent/agents/evil_agent/agent.py', 'line': 5, 'column': 14, 'kind': 'dynamic_resolution', 'symbol': 'getattr', 'normalized_symbol': "getattr(sys.modules['subprocess'], ... )", 'transport': 'dynamic_resolution', 'transport_family': 'unknown', 'classification': 'dynamic_resolution', 'approval_status': 'not_approved', 'reason': 'indirect transport resolution is unknown and must fail closed'}]
unapproved records: 1
cross-check errors: []
FULL VERDICT PASSED: False
```

### Phase 3: expiry TTL

`expired_approval_errors(today=...)` parses approval expiry dates as ISO dates, rejects invalid or expired dates fail-closed, and is wired into the runtime gate. The injected-date regression passed:

```text
tests/test_g02_runtime_invariants.py::test_expired_approval_errors_fail_closed_with_injected_date PASSED [100%]
======================= 1 passed, 3 deselected in 0.06s ========================
```

The current non-expired runtime gate returned:

```json
{"errors": [], "external_target_contacted": false, "passed": true, "primary_records": 279}
```

The matching precommit gate returned:

```json
{"errors": [], "external_target_contacted": false, "passed": true}
```

### Phase 4: adversarial regressions

`tests/test_g02_adversarial_indirection.py` contains six isolated `tmp_path` fixtures, one for each planned case: subscript-style `sys.modules` with double and single quotes, two-step local aliasing, non-literal `importlib.import_module`, aliased `httpx.Client`, and aliased `os.system`. Each assertion checks record kind/approval semantics rather than only process exit status. The complete G-02 suite and the dedicated required suite both passed with 33 tests.

### Phase 5: CI and artifact verification

CI discovery was verified with collection-only output; the broad pytest step collects the new adversarial module without a workflow change. Inventory generation is deterministic: two successive scans produced identical hashes.

The checked-in inventory changed from 63 to 279 records, with 216 additions and zero removals. The additions are exclusively observability records:

```text
added_by_kind={'dynamic_resolution': 216}
added_by_approval={'not_applicable': 216}
added_non_observability=  (empty)
```

Thus the artifact diff is **not empty**, contrary to the plan's expected artifact statement, but the drift is fully classified as generic dynamic-resolution observability. No new approved transport or unapproved production transport was introduced by the hardening changes. Hiding or reverting these records would weaken the stated detection objective, so they are retained and documented.

## Definition of Done results

| Gate | Result |
|---|---|
| Full test suite | `1347 passed, 290 warnings` |
| G-02 filtered suite | `33 passed, 1314 deselected` |
| Dedicated required G-02 suite | `33 passed` |
| Adversarial suite | `6 passed` |
| Ruff | PASS |
| Compileall | PASS |
| Strict test-function preservation check | `1293 >= 498`, PASS |
| G-02 runtime gate | PASS; `external_target_contacted=false`; `primary_records=279` |
| G-02 precommit gate | PASS; `external_target_contacted=false` |
| Inventory determinism | PASS; two identical JSON and Markdown hashes |
| F1 replay | PASS as a rejection test: one `not_approved` record, zero cross-check errors, verdict false |
| Expiry replay | PASS as a rejection test with injected future date |
| Git diff check | PASS |

## Limitations and remaining blockers

The inventory now reports generic dynamic observations as `not_applicable` while transport-bearing or unresolved transport indirection remains fail-closed. This is intentional: generic data-model `getattr` must remain visible for observability without turning every ordinary getter into a raw-I/O violation.

The repository-wide quality suite still contains its pre-existing warnings. The G-02 plan is complete at the code-contract level, but this does not change the previously documented live-lab, Docker/distributed-runtime, RAG, or sealed-ProofBundle qualification blockers. No external target was contacted by these gates, and no vulnerability is confirmed by this work.

## Files changed by this plan

- `src/webpent/shared/direct_io_inventory.py`
- `src/webpent/shared/secondary_io_scanner.py`
- `scripts/check_g02_runtime.py`
- `scripts/check_g02_precommit.py`
- `tests/test_g02_runtime_invariants.py`
- `tests/test_g02_adversarial_indirection.py`
- `docs/direct_io_inventory.json`
- `docs/DIRECT_IO_INVENTORY.md`
- `docs/g02_dynamic_resolution_hardening_report.md`

All source changes are target-agnostic, additive in detection coverage, and retain fail-closed approval behavior.
