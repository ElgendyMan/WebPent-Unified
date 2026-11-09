# P8–P11 Execution Status

**Release posture:** `NOT_QUALIFIED` for VIP promotion. The current evidence scope is the authorized local OWASP Juice Shop at `http://127.0.0.1:3000`; no public target, provider traffic, OAST, OTP/MFA bypass, session bypass, or raw secret/body retention was used.

## Current evidence summary

| Area | Current evidence | Result | Qualification meaning |
|---|---|---:|---|
| P8 browser and proof contracts | Typed `juice-shop-mat-search` workflow, target binding, causal differential, negative control, sealed central bundle, seal verification, and central replay | Passed for the explicitly allowlisted workflow | Demonstrates the strict P8 proof path for one local XSS workflow; it is not full catalog qualification |
| P8 live Juice Shop proof | Runs `xss02`, `xss03`, and `xss04` passed; `xss01` naturally failed with `causal_signal_not_demonstrated` | Partial live evidence | The failed run remains recorded; successful runs do not become a P10 benchmark by themselves |
| P9 distributed runtime | Two-worker Celery/Redis loopback run, killed-worker redelivery, checkpoint resume, retry exhaustion with redacted DLQ projection, and cross-process ledger probe | Partial; `not_qualified` | Lease contention, broker-level idempotency, live TLS, live redaction/retention, and backup/restore remain unproven |
| P10 Juice Shop benchmark | Independent challenge metadata summary: 116 challenges; one XSS class/workflow exercised; three successful strict proof runs | `p10_passed=false` | Mapping is not approved for recall; precision, recall, class coverage, FP, and FN remain null |
| P11 release gate | Dynamic artifact checks now evaluate P8/P9/P10; P8 passes and P9/P10 fail closed | `passed=false`, `hard_checks_passed=false` | Correctly blocks promotion with precise P9/P10 blockers; release manifest verification passed |

## P8 boundary and provenance

The browser adapter accepts the typed search operation only for the named Juice Shop workflow and scopes interaction to the known search component. Generic form input remains fail-closed. The strict proof runner requires baseline, candidate, and independent negative-control observations tied to the same engagement and target, then requires a target-backed causal predicate, central storage, a sealed bundle, `verify_seal()`, and central replay.

The machine-readable P8/P10 artifact is [`docs/juice_shop_qualification_report.json`](juice_shop_qualification_report.json). It records the four isolated runs, retains no raw response bodies or headers, and includes SHA-256 hashes for the source logs. The consolidated status artifact is [`docs/p8_p11_execution_evidence.json`](p8_p11_execution_evidence.json). The central-bundle source log is referenced by hash only; raw logs remain outside the repository.

## P9 boundary

The P9 runtime artifact is [`docs/p9_distributed_runtime_evidence.json`](p9_distributed_runtime_evidence.json). It records real target-free local runtime progress. The Redis broker used for that lab run was plaintext loopback (`redis://127.0.0.1:16379/0`), so it cannot satisfy the live `rediss://` requirement. The artifact also truthfully marks multi-worker lease contention, broker idempotency, live redaction/retention, and backup/restore as incomplete.

The live P9 tasks are target-free qualification tasks. They did not contact Juice Shop or any external target. A killed child worker was redelivered and resumed without duplicating the recorded side effect, and the retry task produced a durable redacted dead-letter projection. These observations improve reliability confidence but do not substitute for the missing production-like checks.

## P10 boundary

The local Juice Shop `/api/Challenges` metadata was used as a discovery-independent catalog reference and reduced to a count, ID-set digest, and XSS catalog keys; raw response bodies were not retained. The current mapping status remains `partial_not_approved_for_recall`. Only the `juice-shop-mat-search` XSS workflow was exercised, so the three passing proof runs are not a complete benchmark. P10 must remain unqualified until an approved ground-truth mapping, broader class/workflow coverage, isolated target-state measurement, and computed precision/recall/class-coverage/FP/FN metrics exist.

Historical WAPTLab health-only observations remain separate from the Juice Shop artifacts. They are not used as the current live P10 benchmark and are not an unconditional VIP blocker in the dynamic P11 gate.

## P11 gate result

The release gate is [`docs/vip_quality_gate.json`](vip_quality_gate.json). It executed compileall, Ruff, G-02 regeneration and checks, the full test/security/release checks, and dynamic P8/P9/P10 artifact validation. Its final state is:

```text
p8-live-proof-artifact: passed
p9-distributed-qualification-artifact: failed
p10-juice-shop-benchmark-artifact: failed
hard_checks_passed: false
passed: false
release_manifest_verify: true
```

The gate now reports only the relevant dynamic blockers for this evidence set:

```text
P9 distributed qualification is incomplete
P10 Juice Shop benchmark is incomplete or not qualified
```

The P11 contract regression includes positive P8 validation, named P9/P10 failure reasons, malformed-JSON fail-closed behavior, and a guard that rejects the old unconditional WAPTLab blocker. The targeted contract file currently passes 12 tests after the new validators were added.

## Promotion decision

The conservative ladder remains `NOT_READY → ENGINEERING_READY → EVIDENCE_READY → BENCHMARK_QUALIFIED → DISTRIBUTED_QUALIFIED → VIP_QUALIFIED`. The defensible current state is `ENGINEERING_READY_WITH_PARTIAL_LIVE_EVIDENCE`. `VIP_QUALIFIED` is **not** assigned because P9 and P10 are still incomplete and P11 correctly fails closed.

## Reproduction commands

```text
cd /tmp/webpent-review
export PYTHONPATH=src:integrations/bbscout/src
.venv/bin/pytest -q tests/test_vip_quality_gate_contract.py
.venv/bin/ruff check scripts/run_vip_quality_gate.py tests/test_vip_quality_gate_contract.py
.venv/bin/python -m compileall -q scripts/run_vip_quality_gate.py tests/test_vip_quality_gate_contract.py
.venv/bin/python scripts/run_vip_quality_gate.py
```

These commands validate the current local source and release gate. They do not authorize provider I/O, public-target testing, CAPTCHA/OTP bypass, session/database bypass, or promotion of offline/mock evidence to live qualification.
