# Generalization Test — CrAPI, DVWA, WebGoat, and Juice Shop

**Run date:** 2026-10-02  
**System path:** HTTPX crawler → Planner/Exploiter/Validator loop → governed AVI/M4 path  
**LLM:** live `gpt-5-mini` through the enabled OpenAI-compatible provider  
**Trust-chain status:** frozen manifest verified; no frozen trust module modified

## Executive verdict

**PARTIAL — the system generalized materially at discovery and bounded orchestration, but full vulnerability confirmation/generalized promotion was not demonstrated.**

The post-fix run completed independently for all four targets, verified all four audit chains, discovered routes and generated executable hypotheses on all four, and recorded 48 real LLM calls at an actual token-derived cost of **$0.19854475**. It produced **0 promoted findings**, **23 inconclusive outcomes**, and **2 refuted outcomes**. The system therefore did not meet the stronger “find at least one vulnerability on each stack” expectation, and the production trace still reported one missing stage (`replan`) on these runs.

No target-specific branch or workaround was added. The correct conclusion is not “PASS”: the safety/audit/discovery generalization is demonstrated, while generalized authenticated execution and promotion remain incomplete.

## 1. Phase 2 — untouched baseline

Phase 2 was run before the systemic changes, with no WebPent source, validator, trust-chain module, or target-specific adapter modification during the test.

| Target | Routes | Events | Hypotheses | Executable | LLM calls | Cost | Outcomes | Promoted |
|---|---:|---:|---:|---:|---:|---:|---|---:|
| CrAPI | 20 | 35 | 8 | 4 | 12 | $0.04902600 | 5 inconclusive, 1 refuted | 0 |
| DVWA | 1 | 30 | 0 | 0 | 1 | $0.00301325 | none | 0 |
| WebGoat | 1 | 30 | 0 | 0 | 1 | $0.00206525 | none | 0 |

**Baseline diagnosis:** CrAPI reached candidate validation but had no bound principals and no complete execution/proof/promotion trace. DVWA and WebGoat stopped at redirect entrypoints, so their forms and authentication surfaces were never reached. The baseline evidence did not justify claiming validator-specific Juice-Shop overfitting because DVWA/WebGoat never reached validators.

Raw baseline evidence is in `docs/generalization_evidence/phase2_raw/`.

## 2. Phase 3 — diagnosis

The detailed evidence-backed diagnosis is in [`GENERALIZATION_PHASE3_DIAGNOSIS.md`](GENERALIZATION_PHASE3_DIAGNOSIS.md).

### Systemic issues identified

1. Same-origin redirect traversal and redirect readiness.
2. Generic HTML form modeling and login-signal preservation.
3. Authentication abstraction limited to bearer/JWT-shaped material; session cookies needed an M4-only mode.
4. Generic principal binding was not available in the untouched runner, so BOLA/IDOR could not be proven.
5. Production/AVI stage synchronization did not expose all observed stages accurately.
6. LLM budget exhaustion needed a clean, auditable graph halt.

### Not proven to be Juice-Shop-specific

No validator was declared Juice-Shop-specific from the baseline evidence. No target-name condition, target-specific route workaround, or response-format exception was added.

## 3. Phase 4 — systemic fixes

The following additive, target-agnostic changes were implemented:

- `src/webpent/recon/autonomous_crawler.py`
  - bounded same-origin redirect traversal;
  - structural redirect events and target recording;
  - generic form/auth-signal extraction;
  - session-cookie names retained structurally while cookie values remain masked;
  - explicit `respect_robots=False` opt-in for authorized assessments, with default robots enforcement preserved.
- `src/webpent/recon/hypothesis_generator.py`
  - generic form-to-hypothesis generation;
  - POST body/method/action preservation;
  - non-login POST forms remain advisory-only; GET forms and explicitly detected login POST forms may be executable;
  - no secret-shaped field payload selection.
- `src/webpent/production/context_authority.py`
  - additive vault-bound session-cookie attachment;
  - caller-supplied forged `Cookie`/`Authorization` values are discarded when M4 attaches the authorized cookie.
- `src/webpent/agents/hunter_graph.py`
  - clean budget-halt transition without a `KeyError`.
- `src/webpent/agents/hunter_runner.py`
  - observed AVI-stage synchronization only; no fabricated stage completion.
- `tests/test_generalization_systemic_fixes.py`
  - redirect/form/cookie regression coverage;
  - explicit authorized robots-override coverage.

The final focused regression set passed **11 tests** after the form-safety correction. Frozen-manifest verification passed with **13/13 files** unchanged.

## 4. Phase 5 — fixed rerun on all four targets

Each target received a fresh process, a unique engagement/audit identifier, a fresh artifact directory, live LLM calls, and a bounded 12-call budget. All four campaigns completed without audit-chain collision.

| Target | Routes | Events | Hypotheses | Executable | LLM calls | Cost | Duration | Outcomes | Promoted | Audit |
|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---|
| CrAPI | 20 | 35 | 8 | 4 | 12 | $0.05228275 | 210.338s | 5 inconclusive, 1 refuted | 0 | PASS |
| DVWA | 18 | 35 | 8 | 4 | 12 | $0.04866175 | 196.229s | 6 inconclusive | 0 | PASS |
| Juice Shop | 25 | 42 | 8 | 4 | 12 | $0.04900800 | 203.607s | 5 inconclusive, 1 refuted | 0 | PASS |
| WebGoat | 3 | 34 | 2 | 2 | 12 | $0.04859225 | 198.382s | 7 inconclusive | 0 | PASS |
| **Total** | **66** | **146** | **26** | **14** | **48** | **$0.19854475** | **808.556s** | **23 inconclusive, 2 refuted** | **0** | **4/4** |

### Per-target conclusions

- **CrAPI:** route discovery and candidate generation remained functional; 4 executable candidates reached the governed path, but no authenticated owner/foreign principals were supplied, so no honest BOLA/IDOR promotion was possible.
- **DVWA:** generic redirect traversal reached 18 routes and generated 8 hypotheses, demonstrating that the PHP/forms discovery gap was fixed. No finding was confirmed; all 6 outcomes were inconclusive.
- **Juice Shop:** regression discovery remained functional at 25 routes with 8 hypotheses. No finding was promoted in this no-principal generalization run; one candidate was refuted.
- **WebGoat:** redirect traversal reached 3 routes and generated 2 executable candidates. No finding was confirmed; 7 outcomes were inconclusive.

### Safety and evidence observations

- All four audit chains independently verified (`event_count=4` per target).
- LLM calls were real and token-costed; target content and credentials were not placed in LLM context.
- No promoted finding, ProofBundle report, or bounty report was created, so none is claimed.
- The production trace was **not complete** on any target: each reported `replan` as missing. This is retained as an unmet execution-evidence item rather than hidden or marked complete.

Post-fix evidence is in `docs/generalization_evidence/phase5_final_20261002t0201z/`.

## 5. Validation

### Focused systemic regressions

- **11 passed**, 1 warning.
- Frozen manifest: **OK (13 files)**.

### Exact 20-test acceptance rerun

The corrected runner used `uv run pytest` and the project interpreter:

- Round 1: **PASS**
- Round 2: **PASS**
- Round 3: **PASS**
- Reproducibility: **YES**

### Security gates

| Gate | Result |
|---|---:|
| `check_state_contract` | 0 |
| `check_orchestrator_construction_authority` | 0 |
| `check_isolation_denylist` | 0 |
| `check_vault_import_authority` | 0 |
| `verify_test_count` | 0 |
| Frozen manifest | 0 / MATCH |

### Full suite

The final full suite collected **2112** tests and reported:

- **2104 passed**
- **8 failed**
- **0 skipped**

The eight failures were existing async-runtime/Playwright/OOB/webhook test families, not the changed generalization modules: Playwright Sync API inside an asyncio loop, `asyncio.run()` inside a running loop, and related async SSRF/webhook/OOB tests. The changed form regression was fixed and the affected hostile recon test passed. Because the complete suite is not green, the release validation status is **PARTIAL**, not PASS.

Full evidence is in [`FULL_SUITE_EVIDENCE.txt`](FULL_SUITE_EVIDENCE.txt). The original uncorrected acceptance logs showing `pytest: command not found` are preserved as environment evidence; the corrected validation is authoritative.

## 6. Final acceptance checklist

| Requirement | Result |
|---|---|
| Untouched Phase 2 raw results for CrAPI, DVWA, WebGoat | PASS |
| Evidence-backed Phase 3 diagnosis | PASS |
| Generic systemic fixes only | PASS — no target-specific branches added |
| Four-target post-fix rerun | PASS — all completed |
| Real LLM calls and actual cost | PASS — 48 calls, $0.19854475 |
| Four audit chains verified | PASS |
| Zero false-positive promotions | PASS — 0 promoted, 2 refuted, 23 inconclusive |
| At least one post-fix finding per target | NOT DEMONSTRATED |
| Complete production/AVI trace | NOT DEMONSTRATED — `replan` missing |
| 20-test acceptance, 3 rounds | PASS |
| Five security gates | PASS |
| Frozen manifest | PASS |
| Full suite | PARTIAL — 2104/2112 |

## Final verdict

> **The system generalized at the crawler, structural surface, audit, redaction, bounded LLM, and hypothesis-generation layers, but generalized authenticated exploitation and full promotion are not yet proven. It is not honest to claim that the system fully generalizes or that it finds vulnerabilities across all four stacks.**

The next justified work item is to complete generic principal provisioning and the missing `replan`/AVI trace synchronization, then rerun the four targets. Do not add target-specific adapters or weaken promotion gates.
