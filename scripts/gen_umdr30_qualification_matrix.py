#!/usr/bin/env python3
"""Generate docs/engineering/UMDR30_FEATURE_QUALIFICATION_MATRIX.json.

Builds on the UM-DR-29 matrix (the canonical qualification record) and
applies the measured UM-DR-30 updates:

  * coverage_intelligence: UNIT_TESTED -> CAMPAIGN_INTEGRATED (the
    coverage_gap_report node, flag-gated fail-closed, wired between the
    reporter and reflection nodes; LangGraph-level survival proven).
  * business_invariant_reasoning: PROPOSED -> CAMPAIGN_INTEGRATED (the
    InvariantChecker wired into the business_logic_fuzzer's workflow
    enrichment; advisory, non-promoting; candidate signals only).
  * NEW family_spine_channel_contract: the 20 formerly-dropped spine
    output keys declared and surviving (R2-graph-03 miss class closed
    family-wide).
  * Gates B and D updated with this window's measurements.
  * Everything else carried over unchanged (honesty: no status improves
    without this window's evidence).

Usage: python3 scripts/gen_umdr30_qualification_matrix.py
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "docs" / "engineering" / "UMDR29_FEATURE_QUALIFICATION_MATRIX.json"
DST = REPO / "docs" / "engineering" / "UMDR30_FEATURE_QUALIFICATION_MATRIX.json"


def main() -> int:
    m = json.loads(SRC.read_text(encoding="utf-8"))

    m["window"] = "UM-DR-30"
    m["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    m["version"] = "0.36.0"

    caps = {c["capability"]: c for c in m["capabilities"]}

    # 1. coverage_intelligence: wired this window.
    caps["coverage_intelligence (gap map)"]["status"] = "CAMPAIGN_INTEGRATED"
    caps["coverage_intelligence (gap map)"]["implementation"] = [
        "src/webpent/coverage/cell_model.py (wired)",
        "src/webpent/coverage/coverage_map.py + gap_detector.py (wired via the new node)",
        "src/webpent/production/coverage_gap_report.py (NEW, UM-DR-30)",
    ]
    caps["coverage_intelligence (gap map)"]["runtime_path"] = (
        "graph/builder.py flag-gated wiring (enable_coverage_gap_report, "
        "fail-closed default False): coverage_gap_report node between the "
        "reporter and reflection nodes; projects the final campaign state "
        "through shared/coverage_ledger.py and emits an explicit, bounded, "
        "advisory gap report on the declared coverage_gap_report channel"
    )
    caps["coverage_intelligence (gap map)"]["limitations"] = (
        "advisory only (no finding vocabulary, no promotion, no confirmation "
        "authority); gap entries capped at 200; not yet consumed by "
        "replanning (the channel is the integration point); internal "
        "fixture validation only"
    )

    # 2. business_invariant_reasoning: wired this window.
    caps["business_invariant reasoning"]["status"] = "CAMPAIGN_INTEGRATED"
    caps["business_invariant reasoning"]["implementation"] = [
        "src/webpent/business_logic/invariant_checker.py (formerly a zero-importer orphan)",
        "src/webpent/agents/business_logic_fuzzer/agent.py::_workflow_enrichment (the wiring point)",
    ]
    caps["business_invariant reasoning"]["runtime_path"] = (
        "inside the business_logic_fuzzer node's workflow enrichment "
        "(enable_workflow_understanding): observations -> InvariantChecker "
        "-> invariant_review advisory channel (merge_lists); strictly "
        "non-promoting — every entry is a candidate_violation whose "
        "required_validation names the causal-guard evidence contract"
    )
    caps["business_invariant reasoning"]["limitations"] = (
        "advisory candidate signals only (never confirms); consumed by "
        "operator review, not yet by replanning; internal fixture "
        "validation only"
    )

    # 3. NEW: the family spine channel contract.
    caps["family_spine_channel_contract"] = {
        "capability": "family_spine_channel_contract",
        "status": "CAMPAIGN_INTEGRATED",
        "implementation": [
            "src/webpent/state/state.py (the 20 declared channels)",
            "src/webpent/families/execution_node.py (the producer)",
        ],
        "runtime_path": (
            "the family_execution node's full output block — 9 family_* "
            "keys + 11 extended advisory keys (attack-graph chain "
            "projections, adversarial-review downgrades, creative-horizon "
            "hypotheses, expanded surface, adaptive defense, self-verify "
            "quality) — now survives LangGraph channel filtering to the "
            "final campaign state (previously ALL were silently dropped; "
            "only findings survived)"
        ),
        "evidence": [
            "tests/test_umdr30_family_channel_contract.py (28 tests: "
            "source contract, LangGraph survival via the real "
            "wire_family_execution over the real PentestState with the "
            "real family_feeds data route, last-write-wins semantics, "
            "advisory-only pins, legacy-checkpoint compatibility)",
        ],
        "limitations": (
            "advisory/auditable only; last-write-wins (single writer per "
            "campaign pass); downstream consumers are the report/export "
            "layer and the operator"
        ),
    }

    # 4. gates B and D.
    m["gates"]["B_functional"] = (
        "PASS for wired capabilities; UM-DR-30 closed three of the "
        "formerly-not-wired capabilities (coverage gap map, invariant "
        "review, family spine channels); knowledge-graph->planning loop "
        "and the isolated adaptive-research-planner layer remain honestly "
        "NOT campaign-wired (see matrix)"
    )
    m["gates"]["D_security"] = (
        "PASS-WITH-NOTES (UM-DR-30: langgraph family audited at ZERO "
        "advisories on the exact-pinned pair (langgraph 1.2.10 / "
        "langchain-core 1.6.7 — the 0.34.2 CVE backlog item closes as "
        "resolved-by-pinning); dnspython remediated 2.8.0 -> 2.9.2 in "
        "uv.lock (CVE-2026-114605, fix >= 2.9.0) with the 128 DNS/SSRF/"
        "rebinding/subdomain tests green; the locked environment pins "
        "remediated versions for the remaining closure packages; "
        "chromadb advisories remain allowlisted under the documented "
        "embedded-only architectural mitigation)"
    )

    # 5. dead_code_disposition: record this window's weak-wiring fixes.
    dcd = m.setdefault("dead_code_disposition", {})
    ww = dcd.setdefault("weak_wiring_fixed", [])
    ww.append({
        "window": "UM-DR-30",
        "items": [
            "family spine non-findings outputs: 20 keys declared (were "
            "silently dropped by LangGraph channel filtering)",
            "coverage_map.py + gap_detector.py: zero-importer orphans -> "
            "campaign-wired behind enable_coverage_gap_report",
            "invariant_checker.py: zero-importer orphan -> wired into the "
            "fuzzer workflow enrichment (advisory, non-promoting)",
            "scripts/run_campaign.sh: rebuilt against the real CLI "
            "contract (--url/--authorization/--scope-file; machine-checked "
            "flag consistency test)",
            "uv.lock: webpent version drift 0.34.0 -> actual; dnspython "
            "2.8.0 -> 2.9.2 (CVE-2026-114605)",
        ],
    })

    m["capabilities"] = list(caps.values())

    DST.write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")
    print(f"OK: {DST.name} written — {len(m['capabilities'])} capabilities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
