# Team 1 Final Security Review

**Document ID:** TEAM1-FINAL-SECURITY-REVIEW-1.0
**Date:** 2026-09-10
**Rule:** no weakening of any security authority (protocol §2). All FORBIDDEN components were verified **unmodified** (Team-1 touched exactly 4 existing files, all additively: `.gitignore`, `attack_graph/__init__.py`, `settings.py` additive field, `research_engine/__init__.py` lazy exports).

## 1. CausalGuard — sole verdict authority
- `src/webpent/cqa_v2/causal_guard.py` (619 loc): unmodified. `BLOCKED` never transitions to CONFIRMED/CLEAN; CONFIRMED requires 7 structural conditions. Integration layer produces only advisory signals/tasks → never bypasses it.
- `proof_oracles.py` second independent oracle: unmodified.
- **Status: INTACT.**

## 2. ProofBundle / promotion / replay
- `models/proof_bundle.py` (frozen, `extra="forbid"`, sha256 digests, seal, replay binding, promotion gate requiring `oracle_decision=="CONFIRMED"` AND `evidence_origin=="target_runtime"` AND `target_backed`): unmodified.
- `cqa_v2/replay_verifier.py` strict v1.8.4 rule (`replay_valid = verdict_match AND evidence_match AND seal_valid AND seal_match AND replay_executed`): unmodified.
- **Status: INTACT.**

## 3. ActionAuthority / safety gates / scope / permission
- `shared/action_authority.py`, `shared/safety_gate.py` (http/https only, redaction, monotonic kill switch), `config/policies.py` (`SandboxPolicy`, `RabbitHolePolicy`): unmodified.
- SSRF restrictions: preflight reachability + metadata blocklist preserved; no new network path introduced.
- **Status: INTACT.**

## 4. P9 / P10 / governance
- `shared/p9_qualification.py` (P9=CLOSED invariant), `benchmark/p10*.py` (strict fail-closed; review mapping can never confer P10/VIP), `production/qualification.py` (12 fail-closed checks incl. `external_target_contacted`): unmodified.
- Global grep for forbidden claims (`vip_qualified=True`, `P10_OPEN`, `P9=OPEN`, `PRODUCTION_READY`, `REAL_WORLD_VALIDATED`, `FULLY_AUTONOMOUS`, `qualification_state=QUALIFIED`) in src/tests/docs/integration: **zero matches**. Only `p10_opened: bool = False` defaults found.
- Bug-bounty blocked (`enable_bug_bounty_reporter=False`); external targets forbidden for qualification.
- **Status: INTACT — vip_qualified=false, qualification_state=CONDITIONAL, P10=CLOSED, P9=CLOSED.**

## 5. Secret handling
- Repository secret scan (sk-/AKIA/AIza/ghp_/xox-/private-key patterns) across src/tests: clean. The only `AKIA…` string is an intentional redaction fixture in `test_v25_javascript_intelligence.py`.
- `graph/checkpoints.py` recursive secret redaction before persist; `shared/resume_capability.py` HMAC-signed (JWT-secret ≥32 chars, never persisted): unmodified.
- `ProviderPool` redacts keys to 4-char prefix. No test credentials inserted into source. No secrets in handoff docs.
- **Status: INTACT.**

## 6. Ground-truth isolation
- `ground_truth.json` / `expected_findings.json` exist only under `benchmarks/` (and historical `goed_v1_8_*` evaluators).
- Static proof: **no file under `src/webpent/` references `ground_truth.json` or `expected_findings.json` by name.** Consumers are evaluation-only code (`scripts/evaluate_ground_truth.py`, `benchmarks/*`, historical harnesses). Evaluator ≠ Executor.
- **Status: INTACT.**

## 7. Provider failover
- `llm_researcher/providers/factory.py` real-API gate: missing key → `RuntimeError("REAL_API_UNAVAILABLE")`; no silent mock; mock only via explicit `ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION=true` + warning.
- `providers/pool.py` + `shared/llm.py` (`_DEAD_PROVIDERS` circuit breaker, 600s TTL, `LLM_ENABLED=false` raises → deterministic fallback): unmodified. All-providers-exhausted → `SAFE_DEFER`/`SAFE_STOP`.
- **Status: INTACT.**

## 8. Shannon provenance (zero-copy)
- No telltale Shannon identifiers (`capella`, `pi agent`, `renumber-core`, `sarif-exporter`, `git-as-database`, `temporal workflow`, `mantis`) found in any new integration source file. Every Shannon-derived capability is `ADAPT` (original Python re-implementation of the pattern) or `KEEP`/`BUILD`/`REJECT` — never `PORT`, per AGPL zero-copy policy (`SHANNON_LICENSE_AUDIT.md`).
- **Status: INTACT.**

## Verdict
No security gate weakened. All invariants preserved. `FILES_DELETED = 0`.
