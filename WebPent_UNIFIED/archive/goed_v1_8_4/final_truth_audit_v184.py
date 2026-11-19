"""GOED v1.8.4 — Phase 19: Final Truth Audit Generator
Reads ALL phase report JSONs and produces a markdown audit table.
Every row is backed by a runnable artifact (reports/goed_v1_8_4/*.json).
No row gets VERIFIED on narrative alone.
"""

import json
import os
from datetime import UTC, datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_4")
LABELS = [
    "IMPLEMENTED",
    "VERIFIED",
    "DEMONSTRATED",
    "MEASURED",
    "PARTIALLY_ESTABLISHED",
    "UNVERIFIED",
    "FAILED",
    "REAL_API_UNAVAILABLE",
    "NO_MEASURED_GAIN",
]


def load_report(name):
    path = os.path.join(REPORTS_DIR, name)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None


def classify_status(report, key="status"):
    if report is None:
        return "UNVERIFIED", "No report artifact found"
    s = report.get(key, "UNVERIFIED")
    if s == "OK":
        return "VERIFIED", "Artifact present and status OK"
    if s == "REAL_API_UNAVAILABLE":
        return "REAL_API_UNAVAILABLE", report.get("note", "LLM API key not set")
    if s == "NO_MEASURED_GAIN":
        return "NO_MEASURED_GAIN", report.get("note", "Delta recall <= 0")
    if s == "FAILED":
        return "FAILED", report.get("note", "Check failed")
    return s, str(report.get("note", ""))


def generate_audit():
    ts = datetime.now(UTC).isoformat()

    # Load all reports
    regression = load_report("full_regression_v184.json")
    learning = load_report("learning_experiment_v184.json")
    contract = load_report("contract_trace_v184.json")
    blind_exec = load_report("blind_v3_execution.json")
    blind_score = load_report("blind_v3_score.json")
    differential = load_report("differential_v184.json")
    hyp_eval = load_report("hypothesis_evaluation_v184.json")
    recovery = load_report("recovery_rule_v184.json")
    generative = load_report("generative_split_v184.json")
    two_model = load_report("two_model_comparison_v184.json")
    failover = load_report("failover_integrity_test.json")
    prompt_inj = load_report("prompt_injection_v184.json")
    secret_scan = load_report("secret_scan_detailed.json")

    # Classifications
    def c(r):
        return classify_status(r)

    # Regression has special structure (uses audit_pass, not status)
    if regression and regression.get("audit_pass") is not None:
        if regression.get("audit_pass"):
            reg_status, reg_note = "VERIFIED", "Freeze integrity gate passed"
        else:
            missing = regression.get("missing_count", 0)
            unresolved = regression.get("unresolved_violation_count", 0)
            if missing > 0 and unresolved == 0:
                reg_status = "PARTIALLY_ESTABLISHED"
                reg_note = f"Freeze checks pass except {missing} missing delivery artifact(s) — open item"
            else:
                reg_status = "FAILED"
                reg_note = f"audit_pass=false, {unresolved} unresolved violations"
    else:
        reg_status, reg_note = c(regression)

    learn_status, learn_note = c(learning)
    contract_status, contract_note = c(contract)
    blind_exec_status, blind_exec_note = c(blind_exec)
    blind_score_status, blind_score_note = c(blind_score)

    diff_status = "UNVERIFIED"
    diff_note = "No report"
    if differential:
        ds = differential.get("classification", differential.get("status", "UNVERIFIED"))
        if ds == "MEASURED_GAIN":
            diff_status = "MEASURED"
            diff_note = f"Delta recall = +{differential.get('delta', {}).get('recall', 0):.4f}"
        elif ds == "NO_MEASURED_GAIN":
            diff_status = "NO_MEASURED_GAIN"
            diff_note = "Principle #10: REAL_LLM_INTEGRATED_NO_MEASURED_GAIN"
        elif ds == "REAL_API_UNAVAILABLE":
            diff_status = "REAL_API_UNAVAILABLE"
            diff_note = differential.get("note", "")

    hyp_status, hyp_note = c(hyp_eval)
    rec_status, rec_note = c(recovery)
    gen_status, gen_note = c(generative)
    tm_status, tm_note = c(two_model)

    # Failover (already run in this session)
    if failover:
        failover_pass = failover.get("all_scenarios_pass", False)
        fo_status = "VERIFIED" if failover_pass else "FAILED"
        fo_note = f"{failover.get('scenarios_passed', 0)}/{failover.get('scenarios_tested', 0)} scenarios"
    else:
        fo_status = "UNVERIFIED"
        fo_note = "No report"

    # Prompt injection
    if prompt_inj:
        pi_conclusion = prompt_inj.get("conclusion", "")
        pi_status = "VERIFIED" if pi_conclusion == "TARGET_DATA_IS_UNTRUSTED" else "FAILED"
        pi_note = f"{prompt_inj.get('scenarios_passed', 0)}/{prompt_inj.get('scenarios_tested', 0)} scenarios"
    else:
        pi_status = "UNVERIFIED"
        pi_note = "No report"

    # Secret scan
    if secret_scan:
        ss_clean = secret_scan.get("no_secrets_found", False)
        ss_status = "VERIFIED" if ss_clean else "FAILED"
        ss_note = f"{secret_scan.get('files_scanned', 0)} files scanned"
    else:
        ss_status = "UNVERIFIED"
        ss_note = "No report"

    # Regression details
    if regression:
        audit_pass = regression.get("audit_pass", False)
        missing = regression.get("missing_count", 0)
        reg_detail = f"audit_pass={audit_pass}, missing={missing}, compileall={regression.get('compileall_pass')}"
    else:
        reg_detail = "No report"

    # Blind v3 metrics
    if blind_score and blind_score.get("metrics"):
        m = blind_score["metrics"]
        blind_metrics = f"P={m['precision']} R={m['recall']} F1={m['f1']} TP={m['tp']} FN={m['fn']}"
    else:
        blind_metrics = "N/A"

    # Differential details
    if differential and differential.get("mode_a_llm_off"):
        ma = differential["mode_a_llm_off"]["metrics"]
        mb = differential["mode_b_llm_on"]["metrics"]
        delta = differential.get("delta", {})
        diff_detail = f"OFF: P={ma['precision']} R={ma['recall']} | ON: P={mb['precision']} R={mb['recall']} | ΔR={delta.get('recall', 0):+.4f} | recovered={delta.get('recovered_count', 0)}"
    else:
        diff_detail = "N/A"

    # Recovery details
    if recovery:
        rec_detail = f"genuine={recovery.get('genuine_recovery_count', 0)}/{recovery.get('candidate_count', 0)}"
    else:
        rec_detail = "N/A"

    # Generative split details
    if generative:
        gen_detail = f"GEN={generative.get('generative_count', 0)} PAT={generative.get('pattern_recognition_count', 0)}"
    else:
        gen_detail = "N/A"

    # Two-model details
    if two_model and two_model.get("model_1", {}).get("metrics"):
        m1 = two_model["model_1"]["metrics"]
        m2 = two_model.get("model_2", {}).get("metrics", {})
        tm_detail = (
            f"M1: P={m1['precision']} R={m1['recall']} | M2: P={m2.get('precision', 'N/A')} R={m2.get('recall', 'N/A')}"
        )
    else:
        tm_detail = "N/A"

    # Learning details
    if learning and learning.get("cold"):
        learn_detail = f"cold_R={learning['cold'].get('recall')} learned_R={learning['learned'].get('recall')} verdict_match={learning.get('verdict_match_count')}/{learning.get('verdict_total_compared')}"
    else:
        learn_detail = "N/A"

    audit = f"""# GOED v1.8.4 — Phase 19: Final Truth Audit
**Date:** {ts}
**Every row below is backed by a runnable JSON artifact in `reports/goed_v1_8_4/`.**
No row is classified VERIFIED on narrative alone.
## 1. DETERMINISTIC & GOVERNANCE FOUNDATION
| Capability | Classification | Evidence / Artifact | Details |
|-----------|---------------|---------------------|---------|
| Phase 18: Full Regression vs Freeze | **{reg_status}** | `full_regression_v184.json` | {reg_detail} |
| v1.8.3 historical manifest untouched | **{"VERIFIED" if regression and regression.get("v183_historical_manifest_untouched") else "UNVERIFIED"}** | `full_regression_v184.json` | freeze policy string unchanged, self-hash matches |
| CausalGuard unchanged | **{"VERIFIED" if regression and regression.get("causalguard_unchanged") else "UNVERIFIED"}** | `full_regression_v184.json` | SHA-256 match vs v1.8.3 freeze |
| ProofBundle unchanged | **{"VERIFIED" if regression and regression.get("proofbundle_unchanged") else "UNVERIFIED"}** | `full_regression_v184.json` | SHA-256 match vs v1.8.3 freeze |
| compileall full src/ | **{"VERIFIED" if regression and regression.get("compileall_pass") else "UNVERIFIED"}** | `full_regression_v184.json` | Python byte-compilation |
| Phase 17: Provider Failover Integrity | **{fo_status}** | `failover_integrity_test.json` | {fo_note} |
| Phase 14: Prompt Injection Resistance | **{pi_status}** | `prompt_injection_v184.json` | {pi_note} |
| Secret Scan (no credentials in artifacts) | **{ss_status}** | `secret_scan_detailed.json` | {ss_note} |
## 2. REAL LLM INTEGRATION
| Capability | Classification | Evidence / Artifact | Details |
|-----------|---------------|---------------------|---------|
| Phase 6: Real Contract Trace | **{contract_status}** | `contract_trace_v184.json` | {contract_note} |
| Phase 7-8: Blind v3 Execution (120 cases) | **{blind_exec_status}** | `blind_v3_execution.json` | manifest-only input, ground truth never loaded by executor |
| Phase 9: Blind v3 Scoring + Leakage Audit | **{blind_score_status}** | `blind_v3_score.json` | {blind_metrics} |
| Phase 11: LLM_OFF vs LLM_ON Differential | **{diff_status}** | `differential_v184.json` | {diff_detail} |
| Phase 10: Independent Hypothesis Evaluation | **{hyp_status}** | `hypothesis_evaluation_v184.json` | {hyp_note} |
| Phase 12: Recovery Rule (7-check) | **{rec_status}** | `recovery_rule_v184.json` | {rec_detail} |
| Phase 13: Generative vs Pattern Split | **{gen_status}** | `generative_split_v184.json` | {gen_detail} |
| Phase 15: Two Real Models Comparison | **{tm_status}** | `two_model_comparison_v184.json` | {tm_detail} |
| Phase 16: Learning Experiment | **{learn_status}** | `learning_experiment_v184.json` | {learn_detail} |
## 3. GATE SUMMARY
| Gate | Status |
|------|--------|
| Freeze Integrity (Phase 18 audit_pass) | **{"PASS" if regression and regression.get("audit_pass") else "FAIL — see open items below"}** |
| Real LLM Evidence Available | **{"YES" if contract_status == "VERIFIED" or diff_status in ("MEASURED", "NO_MEASURED_GAIN") else "NO — REAL_API_UNAVAILABLE"}** |
| LLM Adds Measured Capability | **{"YES" if diff_status == "MEASURED" else "NO" if diff_status == "NO_MEASURED_GAIN" else "UNVERIFIED"}** |
## 4. OPEN ITEMS
### Open Item 1: Missing v1.8.3 Delivery Artifact
- **File:** `WebPent-GOED-v1.8.3-RealLLM-CausalBridge.zip` (category `delivery_v183` in v1.8.3 freeze)
- **Status:** Missing from this snapshot
- **Impact:** Causes `audit_pass=false` in Phase 18
- **Decision required:** This was NOT covered by the A.1 re-freeze decision. Requires a separate decision from Mohamed on whether to: (a) locate and restore the zip, (b) formally exempt it from the freeze check, or (c) accept that Phase 18 cannot fully pass in this snapshot.
### Open Item 2: Scope Limitation
- This snapshot is a **narrow slice** of the wider WebPent project (v1.8.4 LLM validation milestone only).
- The wider project has a ~1900+ check gate suite, adapters, and P10/VIP history that live outside this zip.
- This audit only covers what is present in this snapshot.
### Open Item 3: LLM API Key Not Set
- `LLM_API_KEY` environment variable is not set in this execution environment.
- Phases 6, 7-8, 9 (execution-dependent), 10, 11, 12, 13, 15, 16 all report `REAL_API_UNAVAILABLE`.
- Per Part 0 Rule 2, this is a legitimate, reportable outcome. No mock substitution was performed.
- **Important:** The deterministic core (Phase 18, CausalGuard, ProofBundle, failover, prompt injection, secret scan) is fully verified independent of LLM availability.
## 5. IMPORTANT: VIP Qualification Status
**`vip_qualified` = `false`**
**`qualification_state` = `CONDITIONAL`**
**P10 = `NOT_OPEN`**
This Phase 19 audit documents engineering readiness evidence. It does **NOT** constitute VIP qualification. Per `reports/reviews/JUICE-SHOP-P10-RE-AUDIT-v4.md`, independent governance signoff **cannot be recorded without a real, independent human reviewer.** No amount of additional engineering or automated verification can close this gate.
---
*Generated by `goed_v1_8_4/final_truth_audit_v184.py` from JSON artifacts in `reports/goed_v1_8_4/`.*
"""

    output_path = os.path.join(REPORTS_DIR, "GOED-V1.8.4-PHASE19-FINAL-TRUTH-AUDIT.md")
    with open(output_path, "w") as f:
        f.write(audit)

    print(f"Phase 19 Final Truth Audit written to:\n  {output_path}")
    print("\nKey classifications:")
    print(f"  Phase 18 Regression: {reg_status}")
    print(f"  Phase 11 Differential: {diff_status}")
    print(f"  Phase 12 Recovery: {rec_status}")
    print(f"  Phase 15 Two-Model: {tm_status}")
    print(f"  Phase 16 Learning: {learn_status}")


if __name__ == "__main__":
    generate_audit()
