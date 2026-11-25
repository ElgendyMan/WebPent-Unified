#!/usr/bin/env python3
"""UM-DR-47 Phase M — the measurement battery (brain ON, real numbers).

Mission M1+M2+M3: reuse the 46 baseline battery's six family labs
(vulnerable + secure variants, declared ground truth, out-of-scope
origin invariant, the exact same official entrypoint and metric
attribution) — with the Phase W brain engine ACTIVE
(``ENABLE_BRAIN_ENGINE=true``), fresh research-memory dir per campaign
(deterministic; the memory save itself is recorded per run).

What is measured, by code (never by engine label):
  TP / FP / FN, precision, recall, requests, requests-per-confirmed,
  time-to-first-candidate, time-to-first-confirmed, replay success,
  run-to-run reproducibility, per family and overall — PLUS the brain
  wiring's own counters (W4 coverage tasks + W5 chain steps that
  reached the live pool, brain_engine channel summary, research
  memory saved).

The DELTA versus the 46 baseline
(deliverables/umdr46/final_benchmark/BASELINE_METRICS.json) is
computed by the same script that writes the reports — the reports are
generated, never hand-written.

Usage:
  uv run python scripts/umdr47_measurement_battery.py            # full run
  uv run python scripts/umdr47_measurement_battery.py --runs 1   # quick
  uv run python scripts/umdr47_measurement_battery.py --from-run-files
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")
os.environ.setdefault("LLM_ENABLED", "false")
os.environ.setdefault("EMBEDDINGS_OFFLINE", "true")
os.environ.setdefault("DISABLE_RAG", "true")

import umdr46_baseline_battery as base  # noqa: E402  (the 46 machinery)

BATTERY_VERSION = "umdr47-measurement/1.0.0"
OUT_DIR = REPO / "deliverables" / "umdr47"
RUN_DIR = OUT_DIR / "measurement_run_files"
BASELINE_46 = (REPO / "deliverables" / "umdr46" / "final_benchmark"
               / "BASELINE_METRICS.json")


# ---------------------------------------------------------------------------
# Brain-wiring capture (wraps the entrypoint inside the worker process)
# ---------------------------------------------------------------------------
_BRAIN_CAPTURE: dict = {}


def _install_capture() -> None:
    import webpent.cli.unified_hunt as uh

    if getattr(uh.run_unified_hunt, "_umdr47_capture", False):
        return
    original = uh.run_unified_hunt

    def _capturing(*args, **kwargs):
        summary = original(*args, **kwargs)
        try:
            pool = summary.get("hypotheses_dump") or []
            _BRAIN_CAPTURE["w4_pool"] = sum(
                1 for h in pool if "UM-DR-47 W4" in str(h.get("origin_detail")))
            _BRAIN_CAPTURE["w5_pool"] = sum(
                1 for h in pool if "UM-DR-47 W5" in str(h.get("origin_detail")))
            _BRAIN_CAPTURE["pool_total"] = len(pool)
            _BRAIN_CAPTURE["memory_saved"] = bool(
                summary.get("research_memory_saved"))
            _BRAIN_CAPTURE["safe_stopped"] = bool(summary.get("safe_stopped"))
        except Exception:  # noqa: BLE001 — capture is best-effort
            pass
        return summary

    _capturing._umdr47_capture = True  # type: ignore[attr-defined]
    uh.run_unified_hunt = _capturing


def _brain_fields() -> dict:
    return {
        "w4_coverage_tasks_in_pool": _BRAIN_CAPTURE.get("w4_pool", 0),
        "w5_chain_steps_in_pool": _BRAIN_CAPTURE.get("w5_pool", 0),
        "pool_total": _BRAIN_CAPTURE.get("pool_total", 0),
        "research_memory_saved": _BRAIN_CAPTURE.get("memory_saved", False),
        "safe_stopped": _BRAIN_CAPTURE.get("safe_stopped", False),
    }


def _worker(family: str, variant: str, run_index: int, out_path: str) -> int:
    # each worker: brain ON + a fresh deterministic memory dir
    os.environ["ENABLE_BRAIN_ENGINE"] = "true"
    mem_dir = tempfile.mkdtemp(prefix="umdr47-mem-")
    os.environ["WEBPENT_RESEARCH_MEMORY_DIR"] = mem_dir
    _install_capture()
    _BRAIN_CAPTURE.clear()
    rec = base.run_campaign(family, variant, run_index)
    rec["schema"] = "umdr47-measurement-campaign/v1"
    rec["battery_version"] = BATTERY_VERSION
    rec["brain_engine"] = {
        "enabled": True,
        "flag": "ENABLE_BRAIN_ENGINE=true (env, pydantic-settings mapping)",
        "memory_dir_policy": "fresh per campaign (deterministic; the "
                              "save itself is recorded per run)",
        **_brain_fields(),
    }
    Path(out_path).write_text(
        json.dumps(rec, indent=2, default=str), encoding="utf-8")
    shutil.rmtree(mem_dir, ignore_errors=True)
    return 0


# ---------------------------------------------------------------------------
# Runner (subprocess isolation, the 46 battery's pattern)
# ---------------------------------------------------------------------------
def _run_subprocess(family: str, variant: str, run_index: int,
                    tmp_dir: Path) -> tuple[dict | None, str | None]:
    import subprocess

    out_path = tmp_dir / f"m_{family}_{variant}_run{run_index}.json"
    cmd = [sys.executable, str(Path(__file__).resolve()),
           "--worker", family, variant, str(run_index), str(out_path)]
    env = dict(os.environ)
    env["ENABLE_BRAIN_ENGINE"] = "true"
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO,
                          env=env, timeout=600)
    if proc.returncode != 0 or not out_path.is_file():
        return None, (proc.stderr or proc.stdout or "worker failure")[-2000:]
    return json.loads(out_path.read_text()), None


def _load_records(runs: int) -> list[dict]:
    records: list[dict] = []
    for family in base.FAMILY_LABS:
        for variant in ("vulnerable", "secure"):
            for run_index in range(1, runs + 1):
                path = RUN_DIR / f"measurement_{family}_{variant}_run{run_index}.json"
                if path.is_file():
                    records.append(json.loads(path.read_text()))
    return records


def _pct(num: int, den: int) -> float:
    return round(100.0 * num / den, 2) if den else 0.0


def _brain_aggregate(records: list[dict]) -> dict:
    completed = [r for r in records if r["status"] == "COMPLETED"]
    runs_with_w4 = [r for r in completed
                    if r.get("brain_engine", {}).get(
                        "w4_coverage_tasks_in_pool", 0) > 0]
    return {
        "campaigns_with_w4_tasks_in_pool": len(runs_with_w4),
        "campaigns_completed": len(completed),
        "w4_tasks_total": sum(
            r.get("brain_engine", {}).get(
                "w4_coverage_tasks_in_pool", 0) for r in completed),
        "w5_steps_total": sum(
            r.get("brain_engine", {}).get(
                "w5_chain_steps_in_pool", 0) for r in completed),
        "research_memory_saved_runs": sum(
            1 for r in completed if r.get("brain_engine", {}).get(
                "research_memory_saved")),
        "safe_stopped_runs": sum(
            1 for r in records if r.get("brain_engine", {}).get(
                "safe_stopped")),
    }


def _delta(metrics_47: dict, baseline: dict) -> dict:
    """47 (brain ON) minus 46 baseline, per overall metric — by code."""
    b_metrics = baseline.get("metrics") or {}
    b_over = (b_metrics.get("overall") or baseline.get("overall")
              or baseline.get("aggregate") or {})
    o = metrics_47["overall"]
    keys = ["campaigns_total", "campaigns_completed", "tp", "fp", "fn",
            "declared_defects_total"]
    delta: dict = {"comparison": {
        "baseline_46": "deliverables/umdr46/final_benchmark/BASELINE_METRICS.json",
        "measured_47": "deliverables/umdr47/MEASUREMENT_METRICS.json",
        "note": "same six family labs, same ground truth, same entrypoint, "
                "same metric attribution; the only intentional variable "
                "is ENABLE_BRAIN_ENGINE (46=false, 47=true)",
    }}
    table = {}
    for k in keys:
        bv, nv = b_over.get(k), o.get(k)
        table[k] = {"baseline_46": bv, "measured_47": nv,
                    "delta": (None if (bv is None or nv is None)
                              else nv - bv)}
    for k in ("precision", "recall"):
        bv, nv = b_over.get(k), o.get(k)
        table[k] = {"baseline_46": bv, "measured_47": nv,
                    "delta_points": (None if (bv is None or nv is None)
                                     else round(nv - bv, 2))}
    rb, rn = (b_over.get("replay") or {}), (o.get("replay") or {})
    if rb and rn:
        rate_b = _pct(rb.get("verified", 0), rb.get("total", 0) or 1)
        rate_n = _pct(rn.get("verified", 0), rn.get("total", 0) or 1)
        table["replay_success_pct"] = {
            "baseline_46": rate_b, "measured_47": rate_n,
            "delta_points": round(rate_n - rate_b, 2)}
    delta["overall_table"] = table
    return delta


def _write_report(metrics: dict, brain: dict, delta: dict,
                  records: list[dict]) -> None:
    o = metrics["overall"]
    lines = [
        "# UM-DR-47 — MEASUREMENT REPORT (Phase M, brain ON)",
        "",
        "> Generated by ``scripts/umdr47_measurement_battery.py`` from the",
        "> machine record ``MEASUREMENT_METRICS.json`` — never hand-written.",
        "> Confirmed = Tool-Confirmed only (CausalGuard + ProofBundle +",
        "> replay); generated hypotheses are never TP. Attribution joins",
        "> the finding URL to the declared ground-truth anchors.",
        "",
        "## System under test",
        "",
        f"- Entry point: ``webpent.cli.unified_hunt.run_unified_hunt``",
        f"- Brain engine: **ON** (``ENABLE_BRAIN_ENGINE=true``)",
        f"- Runs per variant: {metrics.get('runs_per_variant')} — "
        f"6 families × 2 variants × N runs",
        f"- Determinism: LLM off, offline embeddings, no RAG, fresh lab +",
        f"  fresh out-of-scope origin per campaign, fresh memory dir",
        "",
        "## Overall (the mission's numbers)",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| campaigns total / completed / error | {o['campaigns_total']} / "
        f"{o['campaigns_completed']} / {o['campaigns_error']} |",
        f"| TP / FP / FN | {o['tp']} / {o['fp']} / {o['fn']} |",
        f"| precision | {round(100 * (o['precision'] or 0), 1)}% |",
        f"| recall | {round(100 * (o['recall'] or 0), 1)}% |",
        f"| declared defects | {o['declared_defects_total']} |",
        f"| replay verified / total | {o['replay']['verified']} / "
        f"{o['replay']['total']} |",
        "",
        "## The brain wiring's own counters (behavioral, per run record)",
        "",
        f"- campaigns with W4 coverage tasks in the live pool: "
        f"{brain['campaigns_with_w4_tasks_in_pool']} / "
        f"{brain['campaigns_completed']}",
        f"- W4 tasks total: {brain['w4_tasks_total']}",
        f"- W5 chain steps total: {brain['w5_steps_total']}",
        f"- research-memory saves: {brain['research_memory_saved_runs']}",
        f"- safe-stopped campaigns: {brain['safe_stopped_runs']} "
        f"(0 expected — labs are in-scope)",
        "",
        "## Per family",
        "",
        "| Family | TP | FP | FN | precision | recall | requests/run | "
        "replay | reproducible |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for fam, f in sorted(metrics["per_family"].items()):
        rep = f.get("reproducibility", {})
        prec = (f"{round(100 * f['precision'], 1)}%"
                if f['precision'] is not None else "n/a (no confirmations)")
        lines.append(
            f"| {fam} | {f['tp']} | {f['fp']} | {f['fn']} | "
            f"{prec} | {round(100 * (f['recall'] or 0), 1)}% | "
            f"{f.get('requests_mean_per_campaign', 'n/a')} | "
            f"{f['replay']['verified']}/{f['replay']['total']} | "
            f"{'yes' if (rep.get('identical_confirmed_counts_vulnerable')
                        and rep.get('identical_confirmed_counts_secure'))
              else 'check record'} |")
    lines += [
        "",
        "## DELTA vs the 46 baseline (M3)",
        "",
        "The only intentional variable: ``ENABLE_BRAIN_ENGINE`` "
        "(46=false, 47=true). Same labs, same ground truth, same runner.",
        "",
        "| Metric | 46 baseline | 47 measured | delta |",
        "|---|---|---|---|",
    ]
    for k, row in delta["overall_table"].items():
        dv = row.get("delta", row.get("delta_points"))
        lines.append(
            f"| {k} | {row['baseline_46']} | {row['measured_47']} | "
            f"{dv} |")
    lines += [
        "",
        "## Maturity statement (M4)",
        "",
        _maturity(metrics, brain),
        "",
        "## Honest caveats",
        "",
        "- The labs are synthetic fixtures with declared ground truth:",
        "  precision/recall measure the engine's attribution against THIS",
        "  ground truth — not a claim about arbitrary real targets.",
        "- Time-to-first metrics are instrumented wall times in a lab",
        "  process (comparative, not absolute).",
        "- Any zero-difference cell is reported as zero — not hidden.",
    ]
    (OUT_DIR / "MEASUREMENT_REPORT.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")


def _maturity(metrics: dict, brain: dict) -> str:
    o = metrics["overall"]
    return (
        f"Measured on this battery: precision "
        f"{round(100 * (o['precision'] or 0), 1)}%, recall "
        f"{round(100 * (o['recall'] or 0), 1)}%, replay {o['replay']['verified']}/"
        f"{o['replay']['total']}. The wiring is behavioral: W4 tasks "
        f"reached the live pool in {brain['campaigns_with_w4_tasks_in_pool']}"
        f"/{brain['campaigns_completed']} completed campaigns. \"Ultimate\" "
        "is a claim about MEASURED numbers on declared ground truth — "
        "this report is that measurement; the numbers above are the "
        "maturity statement, no adjectives attached."
    )


def main() -> int:
    runs = base.RUNS
    args = sys.argv[1:]
    if args and args[0] == "--worker":
        return _worker(args[1], args[2], int(args[3]), args[4])
    if "--from-run-files" in args:
        records = _load_records(runs)
        return _emit(records, runs)
    if "--runs" in args:
        runs = int(args[args.index("--runs") + 1])

    tmp_dir = REPO / "artifacts" / "umdr47_battery_tmp"
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    RUN_DIR.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    try:
        t0 = time.monotonic()
        for family in base.FAMILY_LABS:
            for variant in ("vulnerable", "secure"):
                for run_index in range(1, runs + 1):
                    rec, err = _run_subprocess(
                        family, variant, run_index, tmp_dir)
                    if rec is None:
                        rec = base._error_record(
                            family, variant, run_index,
                            err or "unknown worker failure")
                    # persist the record (redacted by the 46 machinery)
                    safe = json.loads(json.dumps(rec, default=str))
                    (RUN_DIR / f"measurement_{family}_{variant}_"
                     f"run{run_index}.json").write_text(
                        json.dumps(safe, indent=2, default=str),
                        encoding="utf-8")
                    records.append(safe)
                    be = rec.get("brain_engine") or {}
                    print(f"[m-battery] {family}/{variant}/run{run_index}: "
                          f"status={rec['status']} "
                          f"confirmed={rec.get('findings_confirmed')} "
                          f"tp={rec.get('ground_truth', {}).get('tp')} "
                          f"fp={rec.get('ground_truth', {}).get('fp')} "
                          f"w4={be.get('w4_coverage_tasks_in_pool')} "
                          f"mem={be.get('research_memory_saved')}",
                          flush=True)
        print(f"[m-battery] total wall: "
              f"{round(time.monotonic() - t0, 1)}s", flush=True)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return _emit(records, runs)


def _emit(records: list[dict], runs: int) -> int:
    metrics = base.aggregate(records)
    metrics["runs_per_variant"] = runs
    brain = _brain_aggregate(records)
    baseline = (json.loads(BASELINE_46.read_text())
                if BASELINE_46.is_file() else {})
    delta = _delta(metrics, baseline) if baseline else {
        "error": "46 baseline metrics file not found"}

    machine = {
        "schema": "umdr47-measurement-benchmark/v1",
        "battery_version": BATTERY_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mission": "UM-DR-47 Phase M — measurement with the brain ON",
        "system_under_test": {
            "entrypoint": "webpent.cli.unified_hunt.run_unified_hunt",
            "branch_commit": base._git(["rev-parse", "HEAD"]) or None,
            "brain_engine_flag": "ENABLE_BRAIN_ENGINE=true",
            "determinism_env": {
                "LLM_ENABLED": "false", "EMBEDDINGS_OFFLINE": "true",
                "DISABLE_RAG": "true"},
        },
        "brain_wiring": brain,
        "baseline46_delta": delta,
        **metrics,
    }
    (OUT_DIR / "MEASUREMENT_METRICS.json").write_text(
        json.dumps(machine, indent=2, default=str), encoding="utf-8")
    _write_report(metrics, brain, delta, records)

    # DELTA_REPORT.md (M3) — generated from the same machine record
    o = metrics["overall"]
    lines = [
        "# UM-DR-47 — DELTA REPORT (47 wired vs 46 baseline)",
        "",
        "> Generated from MEASUREMENT_METRICS.json — every number is",
        "> computed by code from the machine records, never hand-written.",
        "",
        "## What changed",
        "",
        "The 46 baseline ran the identical six-family battery with the",
        "brain engine OFF (advisory-only). The 47 measurement ran the",
        "same battery with the wiring ACTIVE. Same labs, same ground",
        "truth, same entrypoint, same attribution rules.",
        "",
        "| Metric | 46 baseline | 47 measured | delta |",
        "|---|---|---|---|",
    ]
    for k, row in delta.get("overall_table", {}).items():
        dv = row.get("delta", row.get("delta_points"))
        lines.append(f"| {k} | {row['baseline_46']} | "
                     f"{row['measured_47']} | {dv} |")
    lines += [
        "",
        "## Reading the delta honestly",
        "",
        f"- Precision {round(100 * (o['precision'] or 0), 1)}% and recall "
        f"{round(100 * (o['recall'] or 0), 1)}% are the",
        "  47 numbers against the declared ground truth.",
        f"- The wiring counters: {brain['campaigns_with_w4_tasks_in_pool']}"
        f"/{brain['campaigns_completed']} campaigns had W4 coverage-gap",
        f"  research tasks in the live pool; {brain['w4_tasks_total']} W4",
        f"  tasks and {brain['w5_steps_total']} W5 chain steps total.",
        "- A delta of 0 on a metric is reported as 0 (parity is a fact,",
        "  not a failure — but by law 47-3 parity is NOT proof; the",
        "  behavioral difference evidence is the WIRING_PROOF gate).",
    ]
    (OUT_DIR / "DELTA_REPORT.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")
    print(f"[m-battery] wrote {OUT_DIR}/MEASUREMENT_METRICS.json, "
          f"MEASUREMENT_REPORT.md, DELTA_REPORT.md "
          f"({len(records)} campaign records)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
