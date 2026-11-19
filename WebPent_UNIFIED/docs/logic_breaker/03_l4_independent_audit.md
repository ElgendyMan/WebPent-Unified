# L4 — Independent Verification & Finding Semantics Audit

All checks re-executed from the repository and the delivered ZIP. Advisory
only; no live-target requests were made at any point.

## 1. Artifact verification — PASS

- HEAD at audit start: `3ded001` (then two L4 commits added: red test,
  fix). `git status` clean except `download/econ/portfolio_transitions.jsonl`.
- ZIP sha256 independently recomputed:
  `4aeef1eaaac94df73e70fb0012312c1333d5d0ce3429f760ffe09e39f5c7b706`
  (matches the reported checksum; command `sha256sum`).
- ZIP manifest (3,075 files, extracted and listed) equals
  `git ls-files` at HEAD exactly (diff exit 0). Spot-checked files
  (logic_port.py, finding_bridge.py, test file, README, results doc)
  byte-identical to the repo (`cmp`/sha256).
- `download/econ/portfolio_transitions.jsonl` IS modified relative to
  HEAD (+14 appended lines, pre-existing working-tree change by the
  repository owner, present before the L0–L3 mission and never reset).
  It is intentionally part of this delivery and is the only working-tree
  overlay in the ZIP.

## 2. Security invariants — PASS

- Active HTTP only through the production path:
  `logic_port.py:139` (baseline), `:141` (candidate), `:147` (control)
  all call the inherited `HTTPExperimentPort._observe_post`, which builds
  a `CampaignTask` and executes via
  `http_port.py` `self._runtime.action_executor.execute(task, ..., preconditions_met=True)`
  (ActionAuthority → G-02 smart_http adapter, registered at
  `logic_port.py:487-498` with canonical wrapper, scope policy,
  inventory ref, proof contract and expiry).
- No direct HTTP: grep over `src/webpent/egaie/` finds no
  `requests`/`httpx`/`urlopen`/`socket`/`aiohttp` network clients; only
  `urllib.parse` for URL splitting.
- Sealed/frozen files: `modern_spine.py` and `live_hunter/profile.py`
  full-file sha256 compared against the pre-mission baseline commit
  `dde2a4d` — identical (`git show dde2a4d:... | sha256sum`). Isolated
  packages `verdict/`, `emulator/`, `rehearsal/`: `git diff dde2a4d..HEAD`
  empty. `findings.py`: diff empty.
- Missing/contradictory evidence never CONFIRMED:
  `logic_port.py:170-225` (oracle): `_executed` requires
  `execution=="executed"`, no placeholder, non-None status; non-200 →
  clean; missing/ill-structured payloads → inconclusive; verdict
  confirmed only on explicit predicate violation
  (`amount_mismatch` when charged != authoritative,
  `unauthorized_discount` when discount_applied_by != owner);
  all-denied → blocked. Regression-tested
  (`tests/egaie/test_logic_price_integrity.py`, oracle-contract cases).
- Replay does not reissue HTTP: `LogicProofBundlePort.verify`
  (`logic_port.py:375-401`) reloads the bundle's recorded dicts, reruns
  `InvariantValidationPort.validate` on them, and compares verdict,
  digests, seal and identity. No transport is referenced anywhere in
  verify(). Tampered evidence or foreign identity → replay_valid False
  (tested).
- Ground truth unavailable to the detector: `grep -rn '\.positive'
  logic_port.py orchestrator.py causal_adapter.py http_port.py` → no
  matches (polarity consumed only by the benchmark scorer,
  `http_runner.py:243-249`, after the run). Demonstrated empirically:
  renaming case ids, experiment ids and request paths in observation
  payloads yields byte-identical oracle verdicts (see below).
- Resume cannot repeat a mutation: deterministic per-task idempotency
  token `idem=_sha256(task_key)[:16]` (`logic_port.py:123`) is enforced
  once-per-token by the controlled target's `_apply_mutation`
  (`http_target.py`). Measured on interrupt/resume:
  checkout/inv-1 applied_count == 1, coupon/inv-1 applied_count == 1
  (max 1, zero duplicates), `resume_correct: true`.

## 3. Finding semantics — FAIL found, FIXED

Trace (end-to-end, before the fix): POST observations (baseline/candidate/
control) → `InvariantValidationPort.validate` → confirmed with
violated_predicates → `LogicProofBundlePort.build/verify` → state
hypothesis CONFIRMED + replay-valid bundle record → `finding_bridge.py`
→ Finding.

DEFECT: `finding_bridge.py` exported the price-integrity violation as
`vuln_class=AUTH_BYPASS` (severity high). The oracle verified pricing
invariants only; no authorization-boundary evidence exists, so the
authorization-bypass label claimed evidence that was never verified.

DECISION: the repository's VulnClass taxonomy has no price-integrity /
business-logic member, and `findings.py` is never modified, so no class
is fabricated. The finding now carries `VulnClass.UNKNOWN` (existing
supported member) with the business-logic typing preserved explicitly:
title `"Price integrity violation: <case_id>"`, reasoning beginning
"Price-integrity logic verdict from the invariant oracle
(amount_mismatch / unauthorized_discount)… Not an authorization-boundary
finding…". Nothing was weakened: CausalGuard, proof sealing, replay
verification, ActionAuthority and all gates untouched.

Regression tests (TDD, red first, then fix):
- `test_logic_finding_semantics_are_price_integrity_not_auth_bypass`
  (new): full-run findings must not be auth_bypass, must be UNKNOWN,
  title must carry the price-integrity typing, reasoning must name the
  predicates, severity high.
- The L0 assertion that expected `auth_bypass` was superseded by the
  L4 decision (comment in the test records this); it now asserts
  UNKNOWN + not auth_bypass.
- Authorization findings still require authorization-specific evidence:
  auth_bypass findings can only originate from the existing
  CausalGuard path (v1/v2 wiring unchanged, `http_runner.py:160-174`);
  the logic bridge can never emit auth_bypass (tested).

## 4. Benchmark integrity (independent rerun, `scripts/logic_benchmark_snapshot.py`)

Adaptive: TP 2 (pos-coupon-1, pos-price-1), FP 0, TN 2 (neg-coupon-1,
neg-till-1), FN 0 → precision 1.0, recall 1.0, F1 1.0; replay-valid
confirmed 2/2; 18 HTTP actions, 9.0 per confirmed; terminal
objectives_complete. Baseline (same port, budgets, oracle): TP 1, FP 0,
TN 2, FN 1 → precision 1.0, recall 0.5, F1 0.667; 12 requests;
terminal round_budget_exhausted. Retries: none required; duplicate
mutations: 0 (idempotency enforced per token). Negative controls:
neg-till-1 CLEAN, neg-coupon-1 INCONCLUSIVE — never confirmed.
Randomization invariance: identical oracle verdicts when case ids,
experiment ids and paths in the evidence payloads are renamed
(amount-mismatch and unauthorized-discount confirmed identically; clean
stays clean). Claims are limited to these four fixtures on the
controlled loopback target.

## 5. Final gates (after the fix)

- Full battery: 4,400 passed, 0 failed (4,388 pre-mission + 12 Logic
  Breaker tests; monotonic).
- Construction-authority gate: exit 0.
- Ruff: clean on `src/webpent/egaie/` and the test file.
- Seals vs pre-mission baseline `dde2a4d`: identical full-file hashes;
  prefixes `d10783ec422b…` / `30fd86c61156…` unchanged.

## Changed files (L4)

- `tests/egaie/test_logic_price_integrity.py` (red test commit `b431cc5`,
  then fix-aligned assertion commit)
- `src/webpent/egaie/finding_bridge.py` (semantics fix)
- `README.md`, `docs/logic_breaker/01_price_integrity_results.md`,
  `docs/logic_breaker/02_changed_files_and_gates.md` (doc updates)
- This file.
