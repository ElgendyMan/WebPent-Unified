#!/usr/bin/env python3
"""Chain-proof harness — synthetic multi-family evidence through the Chain Engine.

SYNTHETIC PROOF ONLY. No live target, no HTTP, no LLM. Every finding carries a
sealed replay-verified ProofBundle so it is eligible for chain discovery exactly
as a real promoted finding would be. The governed executor is a deterministic
stub representing the M4/AVI/PromotionPipeline path (the real executor lives in
frozen modules and is intentionally not invoked here).

Run:  PYTHONPATH=src python3 scripts/chain_proof_harness.py
Outputs to deliverables/chain_proof/
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault(
    "WEBPENT_AUDIT_SECRET_KEY",
    "chain-proof-harness-2026-with-strong-entropy-9f3a1c7e",
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from webpent.agents.chain_engine import (  # noqa: E402
    CHAIN_PATTERNS,
    ChainEngine,
    ChainExecutionResult,
    discover_chains,
)
from webpent.models.proof_bundle import build_proof_bundle  # noqa: E402

OUT = ROOT / "deliverables" / "chain_proof"
OUT.mkdir(parents=True, exist_ok=True)

EIGHT_GATES = ("g1", "g2", "g3", "g4", "g5", "g6", "g7", "g8")
TARGET = "http://synthetic-chain.test"
ENGAGEMENT = "eng-chain-proof-001"


def _promoted_finding(
    fid: str,
    family: str,
    *,
    capabilities=(),
    severity="5.0",
    route=None,
    metadata=None,
    target=TARGET,
    engagement=ENGAGEMENT,
):
    """Build a PROMOTED finding with a sealed, replay-verified ProofBundle."""
    route = route or f"/api/{fid}"
    bundle = build_proof_bundle(
        engagement_id=engagement,
        finding_id=fid,
        hypothesis_id=f"hyp-{fid}",
        target_fingerprint="synthetic-chain-target-fp",
        scope_context={"target_url": target},
        identity_context={"principal_alias": "owner"},
        evidence=({"status": 200}, {"status": 200}, {"status": 404}),
        evidence_refs=(f"evidence-{fid}-baseline", f"evidence-{fid}-candidate", f"evidence-{fid}-control"),
        negative_control={"status": 404},
        baseline={"status": 200},
        request_evidence=({"method": "GET", "path": route},),
        response_evidence=({"status": 200},),
        causal_oracle={"causal_signal": True, "negative_control_complete": True},
        validator_id=f"validator.{family.lower()}.synthetic",
        validator_version="synthetic.v1",
        replay_metadata={"replayable": True},
        cleanup_status="not_applicable",
    ).seal()
    finding = {
        "id": fid,
        "status": "PROMOTED",
        "family": family,
        "target_url": target,
        "engagement_id": engagement,
        "route": route,
        "severity": severity,
        "capabilities": list(capabilities),
        "metadata": dict(metadata or {}),
        "proof_bundle_ref": bundle.bundle_id,
        "proof_bundle": bundle.model_dump(mode="json"),
        "replay_verified": True,
        "promotion": {"decision": "PROMOTED", "gates_passed": list(EIGHT_GATES)},
    }
    return finding


# ---------------------------------------------------------------------------
# POSITIVE SETS — each should discover exactly one chain
# ---------------------------------------------------------------------------
POSITIVE_SETS = {
    "set_a_info_disclosure_plus_idor": [
        _promoted_finding(
            "disc-userids",
            "INFO_DISCLOSURE",
            capabilities=("user_ids",),
            severity="3.1",
            route="/api/users/list",
            metadata={"disclosed_resource_id": "1042"},
        ),
        _promoted_finding(
            "idor-profile",
            "IDOR",
            capabilities=("user_ids", "other_user_data"),
            severity="6.5",
            route="/api/users/{id}/profile",
            metadata={"resource_template": "/api/users/{id}/profile", "identity_template_candidate": True},
        ),
    ],
    "set_b_xss_plus_missing_csrf": [
        _promoted_finding(
            "xss-reflected",
            "XSS",
            capabilities=("script_execution",),
            severity="5.8",
            route="/search?q=",
            metadata={"state_changing_endpoint": "/api/profile/update", "csrf_token_absent": True},
        ),
    ],
    "set_c_ssrf_internal_access": [
        _promoted_finding(
            "ssrf-metadata",
            "SSRF",
            capabilities=("internal_access",),
            severity="8.0",
            route="/api/fetch?url=",
            metadata={"internal_reached": "169.254.169.254"},
        ),
    ],
}

# ---------------------------------------------------------------------------
# REFUSAL SETS — each must discover NO chain / emit NO combined report
# ---------------------------------------------------------------------------
REFUSAL_SETS = {
    "refuse_idor_alone": [
        _promoted_finding(
            "idor-solo",
            "IDOR",
            capabilities=("user_ids", "other_user_data"),
            severity="6.5",
            route="/api/users/{id}/profile",
        ),
    ],
    "refuse_incompatible_families": [
        # INFO_DISCLOSURE and OPEN_REDIRECT match no chain pattern — neither is
        # a single-requirement pattern (only SSRF / XSS are), and no pair
        # pattern joins them. Must yield ZERO candidates.
        _promoted_finding("disc-a", "INFO_DISCLOSURE", capabilities=("user_ids",), severity="3.0", route="/a"),
        _promoted_finding("openredir-b", "OPEN_REDIRECT", capabilities=("external_redirect",), severity="4.0", route="/b"),
    ],
    "refuse_forged_bundle": [
        # Forged seal digest — must be excluded from discovery entirely.
        _promoted_finding("forged-ssrf", "SSRF", capabilities=("internal_access",), severity="8.0", route="/x"),
    ],
    "refuse_executor_bool_without_proof": [
        _promoted_finding("ssrf-noproof", "SSRF", capabilities=("internal_access",), severity="8.0", route="/api/fetch?url="),
    ],
}


def governed_executor(candidate):
    """Deterministic stub for the M4/AVI/PromotionPipeline governed executor."""
    return ChainExecutionResult(
        chain_id=candidate.chain_id,
        status="chain_confirmed",
        confirmed=True,
        reason="M4/AVI/PromotionPipeline passed — governed chain execution confirmed",
        evidence={
            "authority": "M4/AVI/PromotionPipeline",
            "response_digest": "redacted-synthetic-proof",
            "executor": "deterministic-stub (synthetic proof, not live)",
        },
        proof_bundle_ref=f"chain-proof-{candidate.chain_id}",
        replay_verified=True,
        gates_passed=EIGHT_GATES,
        gates_failed=(),
    )


def bool_without_proof_executor(candidate):
    """Executor that returns confirmed=True but no replay proof / no gates."""
    return {"status": "chain_confirmed", "confirmed": True, "replay_verified": False}


def run_positive():
    summary = {"sets": {}, "chains_discovered": 0, "chains_confirmed": 0, "combined_severity_upgrades": 0}
    all_events = []
    engine = ChainEngine(audit_event=lambda name, details: all_events.append((name, dict(details))))
    for set_name, findings in POSITIVE_SETS.items():
        candidates = engine.discover(findings)
        run = engine.execute(candidates, governed_executor)
        set_dir = OUT / set_name
        set_dir.mkdir(exist_ok=True)
        set_summary = {
            "findings": [{"id": f["id"], "family": f["family"], "severity": f["severity"]} for f in findings],
            "candidates": [c.to_dict() for c in candidates],
            "run": run.to_dict(),
        }
        # capture event slice for this set
        set_events = []
        ev_engine = ChainEngine(audit_event=lambda name, details: set_events.append(name))
        c2 = ev_engine.discover(findings)
        ev_engine.execute(c2, governed_executor)
        set_summary["event_sequence"] = set_events
        for i, report in enumerate(run.reports):
            (set_dir / f"combined_report_{i+1}.json").write_text(json.dumps(report.to_dict(), indent=2))
            (set_dir / f"combined_report_{i+1}.md").write_text(report.to_markdown())
        (set_dir / "run.json").write_text(json.dumps(run.to_dict(), indent=2))
        summary["sets"][set_name] = {
            "candidates_discovered": len(candidates),
            "chains_confirmed": sum(1 for e in run.executions if e.confirmed),
            "combined_reports": len(run.reports),
            "upgraded_severities": [r.combined_severity for r in run.reports],
            "upgraded_cvss": [r.combined_cvss for r in run.reports],
            "event_sequence": set_events,
        }
        summary["chains_discovered"] += len(candidates)
        summary["chains_confirmed"] += sum(1 for e in run.executions if e.confirmed)
        summary["combined_severity_upgrades"] += len(run.reports)
    (OUT / "positive_run_summary.json").write_text(json.dumps(summary, indent=2))
    return summary


def run_refusal():
    results = {}
    # 1. IDOR alone -> no chain
    c = discover_chains(REFUSAL_SETS["refuse_idor_alone"])
    results["idor_alone_candidates"] = len(c)
    # 2. incompatible families -> no chain
    c2 = discover_chains(REFUSAL_SETS["refuse_incompatible_families"])
    results["incompatible_families_candidates"] = len(c2)
    # 2b. forged bundle (bad seal digest) -> excluded from discovery entirely
    forged = REFUSAL_SETS["refuse_forged_bundle"][0]
    forged["proof_bundle"]["seal_digest"] = "sha256:" + "0" * 64
    forged["proof_bundle"]["authenticity_tag"] = "hmac:" + "0" * 64
    c2b = discover_chains([forged])
    results["forged_bundle_candidates"] = len(c2b)
    # 3. executor bool without proof -> candidate discovered but NO report
    engine = ChainEngine()
    c3 = engine.discover(REFUSAL_SETS["refuse_executor_bool_without_proof"])
    run = engine.execute(c3, bool_without_proof_executor)
    results["bool_without_proof_candidates"] = len(c3)
    results["bool_without_proof_reports"] = len(run.reports)
    results["bool_without_proof_combined_upgrades"] = run.to_dict()["combined_severity_upgrades"]
    (OUT / "refusal_run_summary.json").write_text(json.dumps(results, indent=2))
    return results


def main():
    print(f"Chain patterns available: {len(CHAIN_PATTERNS)} -> {[p.name for p in CHAIN_PATTERNS]}")
    pos = run_positive()
    ref = run_refusal()
    print("\n=== POSITIVE (chain proof) ===")
    for name, s in pos["sets"].items():
        print(f"  {name}: discovered={s['candidates_discovered']} confirmed={s['chains_confirmed']} "
              f"reports={s['combined_reports']} sev={s['upgraded_severities']} cvss={s['upgraded_cvss']} "
              f"events={s['event_sequence']}")
    print(f"  TOTAL: discovered={pos['chains_discovered']} confirmed={pos['chains_confirmed']} "
          f"upgrades={pos['combined_severity_upgrades']}")
    print("\n=== REFUSAL (zero false-positive chain) ===")
    for k, v in ref.items():
        print(f"  {k}: {v}")
    # assertions
    assert pos["chains_confirmed"] >= 1, "at least one chain must be confirmed"
    assert pos["combined_severity_upgrades"] >= 1, "at least one combined severity upgrade required"
    assert ref["idor_alone_candidates"] == 0, "IDOR alone must not chain"
    assert ref["incompatible_families_candidates"] == 0, "incompatible families must not chain"
    assert ref["forged_bundle_candidates"] == 0, "forged bundle must be excluded from discovery"
    assert ref["bool_without_proof_reports"] == 0, "executor bool without proof must not emit report"
    print("\nALL ASSERTIONS PASSED — chain proof + refusal proof complete.")
    print(f"Artifacts in: {OUT}")


if __name__ == "__main__":
    main()
