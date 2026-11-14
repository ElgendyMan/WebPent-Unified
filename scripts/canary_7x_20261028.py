#!/usr/bin/env python3
# scripts/canary_7x_20261028.py
"""Lab canary — 7 consecutive runs per the roadmap's Definition of Done:

    "canary مختبري مستقر لسبعة تشغيلات متتالية على الأقل، مع مقارنة
     baseline" — stable lab canary for at least SEVEN consecutive runs,
    compared against a baseline.

What each canary run does (deterministic, lab-only, zero network):

1. **Regression set** — the frozen-module gate + every Track 11/12
   module test file, executed via pytest; the run must be green with
   EXACTLY the baseline's collected count (drift = instability).
2. **Functional lab smoke** — an in-process, deterministic end-to-end
   exercise of the Track 12 chain: governor admit/release → worker
   claim + cross-worker dedup → workflow plan + approval digest →
   portfolio admit/spend → OOB token issue/credit → calibration order.
   Every step's observable must match the baseline's values.

Stability criterion: all 7 runs byte-stable against the baseline
(same counts, same smoke outputs, all green). Evidence is written to
reports/canary/ as JSON + a human-readable MD summary.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = REPO / "reports" / "canary"

REGRESSION_FILES = [
    "tests/test_frozen_module_gate.py",
    "tests/test_concurrency_governor.py",
    "tests/test_cross_process_leases.py",
    "tests/test_worker_coordination.py",
    "tests/test_finding_relation_graph.py",
    "tests/test_protection_controls.py",
    "tests/test_portfolio_manager.py",
    "tests/test_confidence_calibration.py",
    "tests/test_business_logic_workflows.py",
    "tests/test_oob_verification.py",
    "tests/test_enterprise_operations.py",
    "tests/vip/test_dedup_gate.py",
    "tests/vip/test_retest.py",
    "tests/vip/test_notifications.py",
]


def run_pytest() -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *REGRESSION_FILES, "-q", "--no-header"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=900,
    )
    tail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    # e.g. "789 passed in 17.17s"
    passed = 0
    duration = 0.0
    for token in tail.split():
        if token.endswith("passed") or token.rstrip(",").isdigit():
            pass
    try:
        parts = tail.split()
        if parts and parts[0].isdigit():
            passed = int(parts[0])
        for part in parts:
            if part.endswith("s") and part[:-1].replace(".", "").isdigit():
                duration = float(part[:-1])
    except (ValueError, IndexError):
        pass
    return {
        "rc": proc.returncode,
        "summary": tail,
        "passed": passed,
        "duration_s": duration,
        "green": proc.returncode == 0,
    }


def collection_gate() -> dict:
    """3أ-2 (0.33.0, PRODUCTION_HARDENING_PLAN_0330): collection gate.

    Proven live 2026-11-01: a recycled environment missing the optional
    deps produced 77 SILENT collection errors — the suite "ran green"
    only because the erroring modules were never collected, which
    separates "environment missing deps" from "code broken" by luck.
    This gate refuses that: `pytest --collect-only tests` must complete
    with ZERO collection errors before any suite/canary result counts.
    Runs once per canary invocation (release-gate step, not per-run).
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "--collect-only", "-q",
         "-p", "no:cacheprovider", "--no-header"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=600,
    )
    collected = 0
    errors = 0
    for line in proc.stdout.splitlines():
        s = line.strip()
        # "-q" summary line: "6783 tests collected in 29.88s"
        if " tests collected" in s and not s.startswith("E "):
            try:
                collected = int(s.split()[0])
            except (ValueError, IndexError):
                pass
        if "error" in s.lower() and ("errors during collection" in s or s.startswith("E ")):
            errors += 1
        if " errors during collection" in s:
            try:
                errors = int(s.strip().split()[0])
            except (ValueError, IndexError):
                pass
    return {
        "rc": proc.returncode,
        "collected": collected,
        "collection_errors": errors,
        "clean": proc.returncode == 0 and errors == 0 and collected > 0,
    }


def functional_lab_smoke() -> dict:
    """Deterministic in-process lab chain (no network, no DB)."""
    import tempfile

    from webpent.production.business_logic_workflows import (
        WorkflowEnvironment,
        WorkflowModel,
        WorkflowStep,
        execution_allowed_for,
        plan_execution,
        record_approval,
    )
    from webpent.production.concurrency_governor import ConcurrencyGovernor
    from webpent.production.confidence_calibration import (
        CalibrationRecord,
        ConfidenceCalibrator,
        HumanDecision,
    )
    from webpent.production.oob_verification import (
        OobServiceConfig,
        OobVerifier,
    )
    from webpent.production.portfolio_manager import (
        AdmissionVerdict,
        BudgetCaps,
        PortfolioManager,
        ProgramEstimate,
    )
    from webpent.production.worker_coordination import (
        ClaimOutcome,
        DedupVerdict,
        WorkerCoordinator,
    )

    results: dict[str, str] = {}

    with tempfile.TemporaryDirectory() as tmp:
        # 1. governor admit → deny → release → admit
        gov = ConcurrencyGovernor(max_global=1, max_per_target=1)
        t1 = gov.try_acquire("camp-1", "https://lab.example.com/")
        results["governor_admit"] = "ok" if t1 is not None else "FAIL"
        results["governor_deny"] = (
            "ok" if gov.try_acquire("camp-2", "https://lab.example.com/") is None else "FAIL"
        )
        gov.release(t1)
        t2 = gov.try_acquire("camp-2", "https://lab.example.com/")
        results["governor_release_admit"] = "ok" if t2 is not None else "FAIL"
        if t2 is not None:
            gov.release(t2)
        snap = gov.snapshot().as_dict()
        results["governor_snapshot_totals"] = (
            f"admitted={snap['admitted_total']},rejected={snap['rejected_total']},active={snap['active_total']}"
        )

        # 2. worker coordination: claim + cross-worker dedup
        coord_a = WorkerCoordinator(f"{tmp}/coord", worker_id="worker-A", claim_ttl_seconds=60)
        coord_b = WorkerCoordinator(f"{tmp}/coord", worker_id="worker-B", claim_ttl_seconds=60)
        claim = coord_a.claim_work("client-1", "scope-1", "unit-1")
        results["claim_first"] = "ok" if claim.outcome is ClaimOutcome.ACQUIRED else "FAIL"
        busy = coord_b.claim_work("client-1", "scope-1", "unit-1").outcome
        results["claim_busy"] = "ok" if busy is ClaimOutcome.BUSY else "FAIL"
        fp = "fp:xss:/search:q"
        first = coord_a.register_result("client-1", "scope-1", fp)
        results["dedup_first"] = "ok" if first is DedupVerdict.FIRST_SEEN else "FAIL"
        second = coord_b.register_result("client-1", "scope-1", fp)
        results["dedup_second"] = "ok" if second is DedupVerdict.DUPLICATE else "FAIL"
        other_client = coord_b.register_result("client-2", "scope-1", fp)
        results["dedup_other_client_first"] = (
            "ok" if other_client is DedupVerdict.FIRST_SEEN else "FAIL"
        )

        # 3. workflow: plan → approval binds to digest
        wf = WorkflowModel(
            name="lab-flow",
            client_id="client-1",
            scope_hash="scope-1",
            steps=[
                WorkflowStep("s1", "login", "/login", ""),
                WorkflowStep("s2", "browse", "/items", ""),
            ],
            environment=WorkflowEnvironment.LAB,
        )
        packet = plan_execution(wf)
        results["workflow_valid"] = (
            "ok" if packet.ok_to_present and not packet.execution_allowed else "FAIL"
        )
        ledger: dict = {}
        record_approval(packet, reviewer="canary", approved=True, approval_ledger=ledger)
        results["workflow_approved_gate"] = (
            "ok" if execution_allowed_for(wf, ledger) else "FAIL"
        )
        wf.steps.append(WorkflowStep("s3", "browse", "/other", ""))
        results["workflow_digest_voids_approval"] = (
            "ok" if not execution_allowed_for(wf, ledger) else "FAIL"
        )

        # 4. portfolio: EV order + caps fail-closed
        pm = PortfolioManager(
            caps=BudgetCaps(total_budget=100, per_client_budget=80, per_campaign_cap=50)
        )
        pm.register_program(
            ProgramEstimate("p-hi", "client-1", expected_reward=1000,
                            success_probability=0.5, estimated_cost=40)
        )
        pm.register_program(
            ProgramEstimate("p-lo", "client-1", expected_reward=100,
                            success_probability=0.2, estimated_cost=40)
        )
        ranked = pm.rank_programs()
        results["portfolio_rank"] = "ok" if ranked[0][0].program_name == "p-hi" else "FAIL"
        results["portfolio_admit_ok"] = (
            "ok"
            if pm.admit("client-1", "p-hi", "k1").verdict is AdmissionVerdict.ADMITTED
            else "FAIL"
        )
        rec, _ = pm.record_spend("client-1", "k1", 40)
        results["portfolio_spend"] = "ok" if rec else "FAIL"
        # After 40 committed: a 50-cost campaign fits the campaign cap
        # (50) but breaches the client budget (40+50 > 80).
        deny2 = pm.admit("client-1", "p-hi", "k2", estimated_cost=50)
        results["portfolio_cap_deny"] = (
            "ok" if deny2.verdict is AdmissionVerdict.DENIED_CLIENT_BUDGET else "FAIL"
        )

        # 5. OOB: gate → token → credit → out-of-scope deny
        verifier_on = OobVerifier(
            OobServiceConfig(
                base_url="https://oob.lab.invalid",
                user_controlled=True,
                explicit_consent=True,
                scope_hash="scope-1",
                allowed_origins=("https://app.example.com",),
            )
        )
        results["oob_enabled_gate"] = "ok" if verifier_on.enabled else "FAIL"
        token = verifier_on.issue_token("camp-1", "f-1", "n1")
        results["oob_token"] = "ok" if token and token.startswith("oob-") else "FAIL"
        credit = verifier_on.record_interaction(token, finding_target_origin="https://app.example.com/x")
        results["oob_credit"] = "ok" if credit.credited else "FAIL"
        deny = verifier_on.record_interaction(token, finding_target_origin="https://evil.example.com/")
        results["oob_scope_deny"] = (
            "ok" if not deny.credited and deny.interaction.decision == "denied_scope" else "FAIL"
        )
        verifier_off = OobVerifier(OobServiceConfig())
        results["oob_default_off"] = "ok" if not verifier_off.enabled else "FAIL"

        # 6. calibration: feedback reorders, bounded
        cal = ConfidenceCalibrator(f"{tmp}/cal")
        for _ in range(30):
            cal.record_decision(
                CalibrationRecord(
                    client_id="c1", vuln_class="xss", decision=HumanDecision.ACCEPTED
                )
            )
        for _ in range(30):
            cal.record_decision(
                CalibrationRecord(
                    client_id="c1", vuln_class="sqli", decision=HumanDecision.REJECTED
                )
            )
        ordered = cal.calibrated_order(
            [("f-sqli", "sqli", 0.8), ("f-xss", "xss", 0.6)], "c1"
        )
        results["calibration_reorder"] = (
            "ok" if ordered and ordered[0][0] == "f-xss" else "FAIL"
        )
        cold = cal.class_multiplier("c1", "cold-class")
        results["calibration_cold_neutral"] = "ok" if cold == 1.0 else "FAIL"

    # Deterministic byte signature of the smoke results.
    blob = json.dumps(results, sort_keys=True, separators=(",", ":"))
    return {
        "steps": results,
        "signature": hashlib.sha256(blob.encode()).hexdigest()[:16],
        "all_ok": all(v == "ok" for k, v in results.items() if k != "governor_snapshot_totals"),
    }


def main() -> int:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print("=== baseline run (run 0) ===", flush=True)
    baseline_tests = run_pytest()
    baseline_smoke = functional_lab_smoke()
    baseline = {
        "passed": baseline_tests["passed"],
        "green": baseline_tests["green"],
        "smoke_signature": baseline_smoke["signature"],
        "smoke_all_ok": baseline_smoke["all_ok"],
    }
    print(f"baseline: {baseline}", flush=True)

    runs = []
    stable = True
    for i in range(1, 8):
        print(f"=== canary run {i}/7 ===", flush=True)
        tests = run_pytest()
        smoke = functional_lab_smoke()
        run_record = {
            "run": i,
            "green": tests["green"],
            "passed": tests["passed"],
            "duration_s": tests["duration_s"],
            "smoke_signature": smoke["signature"],
            "smoke_all_ok": smoke["all_ok"],
            "matches_baseline": (
                tests["green"]
                and tests["passed"] == baseline["passed"]
                and smoke["signature"] == baseline["smoke_signature"]
                and smoke["all_ok"]
            ),
        }
        stable = stable and run_record["matches_baseline"]
        runs.append(run_record)
        print(
        f"run {i}: matches_baseline={run_record['matches_baseline']} "
        f"({tests['summary']})",
        flush=True,
    )

    # ruff hygiene once (part of the release gate, not per-run).
    # 0.27.0 alignment (PRODUCTION_FIX_PLAN_0270 follow-through): the
    # declared BLOCKING ruff gate since 0.26.0 is the ratchet
    # (scripts/check_ruff_ratchet.py + frozen baseline — the same gate
    # CI runs). This script's earlier raw scoped `ruff check` had no
    # baseline, so it re-flagged the repo's baselined pre-existing debt
    # and recorded ruff_clean=False in every window's evidence while
    # the canonical gate was green. The canary now defers to the
    # canonical gate instead of a duplicate un-baselined check.
    ruff = subprocess.run(
        [sys.executable, "scripts/check_ruff_ratchet.py"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
    )
    # 3أ-2 (0.33.0): collection gate — zero silent collection errors
    # allowed (see collection_gate docstring). Release-gate step.
    collect = collection_gate()
    version = (REPO / "pyproject.toml").read_text().split('version = "')[1].split('"')[0]
    evidence = {
        "started_utc": started,
        "finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_head": subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO), capture_output=True, text=True
        ).stdout.strip(),
        "version": (REPO / "pyproject.toml").read_text().split('version = "')[1].split('"')[0],
        "baseline": baseline,
        "runs": runs,
        "stable_7x": stable,
        "ruff_clean": ruff.returncode == 0,
        "collection_clean": collect["clean"],
        "collection_collected": collect["collected"],
        "collection_errors": collect["collection_errors"],
        "regression_files": len(REGRESSION_FILES),
        "baseline_smoke_steps": baseline_smoke["steps"],
    }
    # Version-dynamic evidence name (0.27.0 fix): the hardcoded
    # 0.24.0-era name made every later window OVERWRITE the historical
    # 0.24.0 evidence file. Evidence files are history — never clobber.
    evidence_date = started[:10].replace("-", "")
    out_json = EVIDENCE_DIR / f"CANARY_7X_{evidence_date}_{version}.json"
    out_json.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")

    md = [
        "# Lab Canary — 7x Consecutive Runs (DoD)",
        "",
        f"- date: {evidence['started_utc']} — version {evidence['version']} "
        f"— git {evidence['git_head'][:12]}",
        f"- regression files: {len(REGRESSION_FILES)} — baseline: "
        f"{baseline['passed']} passed, green={baseline['green']}",
        f"- functional lab smoke signature: `{baseline['smoke_signature']}` "
        "(governor → workers → workflow → portfolio → OOB → calibration)",
        "",
        "| run | green | passed | matches baseline |",
        "|-----|-------|--------|------------------|",
    ]
    for r in runs:
        md.append(
            f"| {r['run']} | {str(r['green']).lower()} | {r['passed']} "
            f"| {str(r['matches_baseline']).lower()} |"
        )
    md += [
        "",
        f"**Result: "
        f"{'STABLE — 7/7 consecutive runs byte-identical to baseline' if stable else 'UNSTABLE'}; "
        f"ruff clean = {str(evidence['ruff_clean']).lower()}; "
        f"collection clean = {str(evidence['collection_clean']).lower()} "
        f"({evidence['collection_collected']} collected, "
        f"{evidence['collection_errors']} errors).**",
        "",
        "The canary exercises the lab-facing chain only (no network, no live "
        "targets); the smoke's deterministic signature must match the baseline "
        "exactly, which is the stability criterion of the roadmap's DoD.",
    ]
    report_path = EVIDENCE_DIR / f"CANARY_7X_{evidence_date}_{version}.md"
    report_path.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"=== STABLE={stable} — evidence: {out_json.name} ===", flush=True)  # noqa: E501
    return 0 if stable and evidence["ruff_clean"] and evidence["collection_clean"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
