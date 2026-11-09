# M11_PHASE_REPORT.md — M11 (Benchmarking & Research Qualification)

**Phase:** M11 of the CANONICAL_PHASE_REGISTRY (Part 4 §13 — P0/P1).
**Date closed:** 2026-11-06 (UTC).
**Window:** DRIFT_REGISTER UM-DR-22.
**Baseline entering:** post-M9 tree (UM-DR-21); frozen authority manifest untouched; frozen-module gate 661 green.
**Refreeze:** NONE REQUIRED — a NEW package (`src/webpent/qualification/`) outside the frozen gate, composing the M3/M6 engines. Zero frozen-file changes.

---

## 1. What was delivered

### 1.1 — Per-family metrics (`qualification/metrics.py`)

`compute_family_metrics` — TP/FP/FN/TN → precision/recall/F1/accuracy plus the registry's operational metrics: confirmed count, inconclusive rate, scope-rejection rate, human-intervention rate, crash count, reproducibility, time-to-first, cost-per-confirmed, requests-per-finding. Every row carries its sample size.

### 1.2 — No aggregate without per-family (the acceptance, structural)

`BenchmarkReportV2` — dataset descriptor (name/version/commit/seed/ground-truth ref, all recorded); the model REFUSES empty family tables and any zero-sample row; `compute_aggregate()` derives the pooled numbers FROM the family rows (`derived_from_family_rows: true`). Dataset version/commit/seed/ground-truth are mandatory fields.

### 1.3 — The qualification-label ladder (`qualification/labels.py`)

`unqualified` → `unit_tested` (green run evidence) → `lab_qualified` (+ a benchmark report with per-family sizes + reproducibility on a recorded dataset) → `production_qualified` (+ a zero-FP blind set + a zero-FP deception benchmark pass +, for LLM-involved components only, a passing Charter §4.1 verdict). Fail-closed with named missing evidence; failing tests block the whole ladder.

### 1.4 — The wired weekly runner (`qualification/weekly.py`) — the ق5 canary

`run_weekly_benchmarks()` executes the internal set on every call and writes the dated report under `reports/qualification/`: the deception benchmark (24 fixtures), the Charter §4.1 baseline replay (the recorded blind_v3 metrics through the live gate — refused by construction), the ق5 dojo self-benchmark WHEN the operator configures the agent factory (absent ⇒ the honest `self_benchmark_not_configured` note; a factory failure is recorded, never swallowed), and the qualification-label rollup. **Executed at closure**: `reports/qualification/weekly_20261105T201149Z.json` — deception_verifier = `production_qualified`; deterministic_hypothesis_engine = `lab_qualified` (honest: the 0.137-recall baseline does not clear the blind-set bar — the label records the truth, not the aspiration).

## 2. Acceptance vs the registry

| Registry acceptance (Part 4 §13) | Status |
|---|---|
| per-family metrics (the full named list) | **delivered** (§1.1) |
| no aggregate score without per-family detail and sample size | **delivered, structural** (§1.2) |
| dataset version/commit/seed/ground-truth recorded | **delivered** (§1.2 — mandatory fields) |
| qualification labels (unit-tested → production-qualified) | **delivered** (§1.3) |
| weekly runs + canary scheduler + ق5 self-benchmark wired | **delivered** (§1.4 — the runner + dated reports; the cron/scheduler ENROLLMENT is M12's operations surface) |
| CLAIMS_VS_REALITY discipline | **maintained** — the rollup publishes the honest label for the deterministic engine |
| baselines + ablations + fixed/equal-budget comparisons; frozen system before blind holdout | **partially delivered** — the baseline replay + blind-set scoring exist (M3/M6/M11); full ablation matrices on live corpora require operator-deployed targets (Juice Shop/crAPI) — the runner accepts them, records their descriptors, and never fabricates their absence |

Deferred with owners: live Juice-Shop/crAPI/OWASP-Benchmark runs + held-out target rotation + ablation matrices → operator-deployed corpora (the runner's interfaces accept them; the sandbox has no live targets by policy); cron enrollment of the weekly runner → M12's operations window.

## 3. Gate evidence at closure

- **Tests:** `tests/test_m11_qualification.py` — 10 passed.
- **Frozen-module gate:** 661 passed (no frozen changes).
- **Test-count gate:** 8,498 ≥ floor 8,115.
- **Authority manifest:** untouched (13 files).

— End of M11_PHASE_REPORT.md —
