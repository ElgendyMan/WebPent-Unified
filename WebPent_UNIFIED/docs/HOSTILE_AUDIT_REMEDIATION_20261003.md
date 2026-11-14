# Hostile-Audit Remediation Report — 2026-10-03

## 1. Scope and baseline

This report supersedes the prior hostile self-audit for the attached `webpent-gap-closure-fixed.zip` tree. The baseline was independently unpacked before source changes.

Baseline blockers found:

- The attached tree's `src/webpent/models/proof_bundle.py` did not match the frozen-manifest hash. The trusted manifest hash was restored without changing the frozen module.
- The first independent full-suite run reported **10 failures / 2113 passed** when run without an operator audit key. Two ProofBundle/OOB failures were caused by the intentionally fail-closed missing-key state; the remaining async failures exposed a Playwright lifecycle leak and test-loop contamination.
- Direct-I/O inventory was stale after earlier source changes.
- A non-frozen authority regression test expected a stale ZIP-local hash rather than the manifest-authoritative frozen hash.

No target credentials, tokens, cookies, raw target bodies, or provider prompts were added to the project.

## 2. Remediation implemented

### 2.1 Finding identity and lifecycle

Updated `src/webpent/production/autonomous_validation_v1.py`:

- Finding IDs now include engagement, target fingerprint, hypothesis, experiment, and vulnerability class, so the same hypothesis cannot collide across campaigns or targets.
- Rejected, refuted, inconclusive, and blocked decisions no longer expose a reportable finding ID.
- Non-promoted decisions no longer expose a ProofBundle in the reportable decision payload.
- Proof/seal metadata is reported as verified only for an actually reportable promoted bundle.
- Serialized ProofBundle inputs are round-tripped through the frozen `ProofBundle` model and `verify_seal()`; a forged `{sealed: true, authenticity_tag: ...}` dictionary is rejected.

### 2.2 Concrete bounded replanning

Updated the non-frozen Hunter graph/runner path:

- An accepted replan selects the complete existing governed catalog candidate, including its concrete baseline/candidate/negative-control request triple.
- Replanned method, route, parameter, owner/foreign values, and request specs are hydrated into the hypothesis passed to AVI.
- AVI receives the selected hydrated candidate rather than the stale pre-replan candidate.
- The graph remains bounded at three replans per hypothesis and records an explicit `replan` event only after an inconclusive verdict.
- No arbitrary route, payload, identity, credential, or scope expansion is accepted from the advisory model.

### 2.3 Browser lifecycle and async stability

Updated `src/webpent/recon/browser_farm.py`:

- When the final campaign browser closes, the shared synchronous Playwright driver is stopped and cleared.
- This prevents leaked Playwright greenlets from contaminating later asyncio-managed operations and eliminates the `Sync API inside the asyncio loop` failure.

The two previously unmarked top-level async SSRF regression methods are explicitly marked with `pytest.mark.asyncio`.

### 2.4 Artifact and regression corrections

- Regenerated `docs/direct_io_inventory.json` and `docs/direct_io_inventory.md` from the canonical AST scanner.
- Updated the non-frozen authority regression test to assert the restored manifest-authoritative ProofBundle hash.
- Added focused regressions for scoped finding IDs, concrete request replacement after replanning, serialized ProofBundle forgery rejection, and deterministic redaction assertions.

## 3. Verification results

### Full suite

Executed with an ephemeral strong runtime key:

```text
AUDIT_SECRET_KEY=<runtime-only strong test key>
PYTHONPATH=src python -m pytest tests/ -q --tb=no
```

Result:

```text
2123 passed, 0 failed, 11 warnings
```

Warnings were dependency/deprecation warnings and intentional development-mode key warnings; no test failed.

### Focused remediation suite

```text
96 passed, 3 warnings
```

This included principal provisioning, Hunter graph, generalization, bounty reporting, ProofBundle, browser, webhook/TLS, SSRF, OOB parity, deep-recon authority, and direct-I/O tests.

### Reproducibility acceptance

The exact 20-test acceptance input was run three times:

| Round | Result | Duration |
|---|---:|---:|
| 1 | 20 passed / 0 failed | 42.02s |
| 2 | 20 passed / 0 failed | 42.89s |
| 3 | 20 passed / 0 failed | 43.65s |

Reproducibility: **YES — 20/20 × 3**.

## 4. Security and integrity gates

| Gate | Result |
|---|---|
| Frozen manifest | OK — 13 files |
| State contract | OK |
| Orchestrator construction authority | OK |
| Isolation denylist | OK — 0 violations |
| Vault import authority | OK |
| Test count | OK — 2123 collected, floor 1940 |
| Direct-I/O artifact drift | None; canonical records match |

The direct-I/O scanner reports **20 known pinned unapproved records**. These are the existing reviewed/pinned gap set represented in the artifact; they are not a newly introduced drift and are not silently approved by this remediation.

## 5. Trust-chain assessment

The remediation does not modify the frozen trust modules. Promotion remains fail-closed through the existing AVI/M4, ProofBundle, replay, PromotionPipeline, and security-gate path.

In particular:

- A high confidence score cannot create a promoted finding without a confirmed causal validator outcome.
- A serialized forged ProofBundle cannot satisfy the signature gate.
- Rejected and inconclusive outcomes do not receive reportable finding identity or ProofBundle output.
- Replanning cannot bypass AVI or M4 and cannot invent a target request outside the existing governed catalog.

## 6. Live campaign status

This remediation run was an independent code, artifact, and regression verification pass. It did **not** claim a new live Juice Shop or CrAPI campaign result, and it did not reuse prior live findings as fresh evidence. Existing campaign evidence remains historical evidence only.

The runtime audit key used for tests was supplied only in the process environment and was not written to source, reports, logs, or the archive.

## 7. Residual limitations

- The direct-I/O artifact intentionally retains the previously pinned 20 unapproved records. They remain visible for follow-up review rather than being hidden or approved.
- The project contains historical campaign/report documents from earlier work. This report is the authoritative result for the 2026-10-03 remediation verification.
- No claim is made here that a new non-Juice-Shop vulnerability was promoted; that requires a separate fresh authorized live campaign.

## 8. Final verdict

**PASS for the hostile-audit remediation scope.**

The frozen manifest is restored and matches, the full suite is green, the exact acceptance input is reproducible 20/20 across three rounds, and the corrected identity, proof-lifecycle, concrete-replan, browser-lifecycle, and inventory issues are covered by source checks and focused regressions.
