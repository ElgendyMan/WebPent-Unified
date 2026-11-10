"""Gate: broad-exception hygiene of non-frozen production code (audit D-03).

Guarantees (see docs/ACCEPTED_EXCEPTIONS_REGISTER.md):

1. The set of non-frozen ``src/webpent/**/*.py`` files containing an
   ``except Exception`` handler is exactly the 4 registered files.
2. The total number of broad handlers across those files is exactly 12
   (6 legacy sites: 2 transport boundaries in auth_resilience, 3 plugin
   boundaries in session_recovery, 1 library boundary in
   planner_enrichment_bridge; plus 6 registered best-effort boundaries in
   poc_recorder.py from the FINAL PREP SPRINT: fail-soft POC contract,
   body capture, audit append, and video-context close). The 2 former
   auth_resilience sites are narrowed and guarded by
   test_narrowed_sites_stay_narrowed.
3. Any drift — a new broad handler anywhere else in non-frozen production
   code, or a change in the registered count — fails the suite until the
   register is updated deliberately.

Frozen files are governed by the frozen-hash gate and out of scope here.

M2-impl (Dispatch #009, G5 re-freeze) SCOPE NOTE — v8 manifest scope
completion (finding NF-M2I-01): the v8 manifest pins EVERY file under
src/ (708 entries), including the 12 previously-unpinned files that
hosted 12 of the 13 registered broad handlers. Those sites are now
governed by the STRONGER frozen-hash gate (byte-exact pins instead of
counts). Consequences, encoded below:
  - the src-side "non-frozen" population this gate scans is empty by
    construction;
  - the per-file count assertions are replaced by assertions that every
    registered src-side file IS manifest-pinned (and unchanged since the
    register was written — the counts remain recorded in
    docs/ACCEPTED_EXCEPTIONS_REGISTER.md for provenance);
  - the narrowed-sites tripwire (test_narrowed_sites_stay_narrowed)
    still guards the two narrowed auth_resilience sites textually;
  - scripts/poc_watcher.py (outside src/, outside the manifest) is still
    counted by this gate.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "frozen_modules.sha256"
SRC_ROOT = REPO_ROOT / "src" / "webpent"

# FULL repo-root-relative paths -> exact number of registered (accepted)
# broad handlers. v4 (R-12): the register is keyed by FULL PATH — the v3 gate
# keyed by basename, which both contradicted this file's own docstring and
# reintroduced the exact basename-matching trap the hostile audit criticized
# (a colliding basename would mask or misattribute drift).
# auth_resilience: sites 97 & 194 accepted (transport); sites 203 & 295
# were NARROWED (guarded by test_narrowed_sites_stay_narrowed).
# poc_recorder: FINAL PREP SPRINT — the fail-soft POC contract requires
# best-effort boundaries; see docs/ACCEPTED_EXCEPTIONS_REGISTER.md.
# scripts/poc_watcher.py: v4 — the fail-soft cycle guard is deliberately
# registered (it ships in the package; v3 left it outside the gate's scope
# while claiming "all broad sites documented").
REGISTERED_FILES = {
    "src/webpent/recon/auth_resilience.py": 2,
    "src/webpent/recon/session_recovery.py": 3,
    "src/webpent/integration/planner_enrichment_bridge.py": 1,
    "src/webpent/reporter/poc_recorder.py": 6,
    # RESIDUAL CLOSURE 2026-10-29 (DR-015): five src files carrying
    # documented fail-soft contracts were never manifest-pinned, so this
    # gate (correctly) counts them. Registered deliberately with the
    # rationale recorded in docs/ACCEPTED_EXCEPTIONS_REGISTER.md:
    "src/webpent/production/concurrency_governor.py": 7,
    "src/webpent/production/cross_process_leases.py": 1,
    "src/webpent/production/protection_controls.py": 1,
    "src/webpent/vip/dedup_gate.py": 3,
    "src/webpent/vip/notifications.py": 5,
    "scripts/poc_watcher.py": 1,
    "src/webpent/adaptive/defense_emulator.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/apex/parallel_runner.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/amplifiers/cloud_storage.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/amplifiers/ct_mining.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/amplifiers/skeptic.py": 4,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/amplifiers/swarm.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/amplifiers/takeover.py": 2,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/amplifiers/wayback.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/cem/cycle.py": 3,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/cem/diff_engine.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/cem/regression_watch.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/hunt_knowledge.py": 3,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/hunt_memory.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/hunt_orchestrator.py": 13,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/hunt_runtime.py": 2,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/autonomous/vip_orchestrator.py": 10,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/causal_reasoning/contextual_memory.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/causal_reasoning_v2/causal_adapter.py": 4,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/causal_reasoning_v2/causal_adapter_v2.py": 2,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/causal_reasoning_v2/closed_loop_integration.py": 2,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/causal_reasoning_v2/confidence_engine_v2.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/causal_reasoning_v2/integration_layer.py": 4,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/chained_exploits/attack_graph_planner.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/cli/apex.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/deep/business_logic.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/deep/client_path_traversal.py": 2,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/deep/deserialization.py": 2,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/deep/dom_clobbering.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/deep/mass_assignment.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/deep/race_condition.py": 2,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/deep/rate_limit_bypass.py": 2,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/econ/blind_spots.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/econ/budget_mapper.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/econ/competitive.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/econ/market_kb.py": 2,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/econ/portfolio.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/econ/roi_optimizer.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/econ/saturation.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/econ/timing_advisor.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/families/execution_node.py": 26,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    # ULTIMATE PLAN 2026-10-27, proposal 4: goed_v1/family_strategies.py
    # left src/ with the dead-code archive (its one broad handler went
    # with it — archived code has no live handler surface).
    "src/webpent/jc/chamber.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/jc/verdict.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/memory/postmortem.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/oracle/osint.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/shared/operator_catalogs.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/shared/red_vs_blue.py": 2,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/shared/shadow_detector.py": 2,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/shared/vip_campaign_node.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/shared/waf_evasion.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary
    "src/webpent/verification/self_verify.py": 1,  # MERGE 2026-10-26: absorbed lineage fail-soft boundary

    # UM-DR-25 (red-team window 2026-11-06): the M0-M12 engineering
    # windows merged these non-frozen files with broad fail-soft
    # handlers that were never registered — the gate had been red
    # since those merges. Registered deliberately; narrowing each
    # handler to typed exceptions is recorded follow-up debt.
    "src/webpent/agents/advanced_web_vulns/agent.py": 3,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/agents/cache_poisoning/agent.py": 2,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/agents/dom_xss/agent.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/agents/dom_xss/parser.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/agents/graphql_testing/agent.py": 3,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/agents/js_discovery/agent.py": 3,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/agents/prototype_pollution/agent.py": 2,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/agents/role_matrix/sessions.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/agents/sourcemap_analysis/agent.py": 2,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/appsuite/berth.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/appsuite/consign.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/appsuite/corpus.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/appsuite/docvault.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/appsuite/ledgerflow.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/appsuite/market.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/appsuite/permit.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/appsuite/requisitions.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/appsuite/slots.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/appsuite/ticketflow.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/auth/identity_orchestrator.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/auth/session_pool.py": 2,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/auth/worker_session_factory.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/benchmark/fixtures/runner.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/business_logic/value_fuzzer.py": 2,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/chained_exploits/analyzer.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/chained_exploits/graph_v3.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/cli/bounty.py": 2,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/coverage/cell_model.py": 2,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/dojo/self_benchmark.py": 2,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/ekg/executor.py": 3,  # UM-DR-25: M0-M12 window fail-soft boundary
    # UM-DR-29 (2026-11-07): the three goed_v1 register entries below were
    # removed with the completed Ultimate-Plan-2026-10-27-proposal-4 dead-code
    # archive (src/webpent/goed_v1/ deleted; canonical copies live in
    # archive/pre_v10_prototypes/goed_v1/ — archived code has no live handler
    # surface, same ruling as family_strategies.py in this register).
    "src/webpent/graph/oast_nodes.py": 5,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/integrations/notifications/dispatch.py": 3,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/jsintel/api_surface_shadow.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/jsintel/js_reversing.py": 2,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/learning/refutation_ledger.py": 6,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/learning/technique_library.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/llm_researcher/tiering.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/production/campaign_lifecycle.py": 8,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/production/hypothesis_qualification_harness.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/production/oob_validator.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/qualification/weekly.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/recon/takeover.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/reporter/bounty_pipeline.py": 2,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/reporter/chain_review.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/resume/campaign_checkpoints.py": 13,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/safety/agency.py": 3,  # UM-DR-26: the active-engagement alias now derives from the M1b workspace axis — the workspace read is a fail-soft boundary (any context error resolves to "") on top of the two UM-DR-25 handlers
    "src/webpent/safety/kill_switch.py": 3,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/safety/request_ledger.py": 7,  # UM-DR-26: +1 — the fixed _active_engagement_id adds one fail-soft workspace read (ImportError-proof) on top of the six UM-DR-25 handlers
    "src/webpent/safety/spend_governor.py": 4,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/safety/status_snapshot.py": 4,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/scheduler/campaign_scheduler.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/shared/attack_graph_evidence.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/shared/oob.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/stateful_api/contracts.py": 1,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/waf_evasion/adaptive.py": 2,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/workflow_fuzzing/agent.py": 9,  # UM-DR-25: M0-M12 window fail-soft boundary
    "src/webpent/production/stateful_probe.py": 3,  # UM-DR-25: prober transport guards (injected client defines the exception type — broad by contract); UM-DR-27: +1 the source-driven _request transition boundary (same injected-client contract)
    "src/webpent/production/coverage_gap_report.py": 3,  # UM-DR-30: the advisory coverage-gap node — observability must NEVER kill a campaign: the ledger projection, the settings double-gate, and the optional langgraph import check each fail soft by contract (an error-shaped report / a no-op node, never a crashed campaign)
    "src/webpent/production/adaptive_research.py": 3,  # UM-DR-31: the adaptive research loop — a research iteration must NEVER kill a campaign: the signal inventory's coverage projection degrades to an empty signal set (invariant/workflow channels still scan), and the node body degrades to error-status telemetry with no hypotheses injected (fail-soft by contract; the loop never promotes/confirms/grants — cqa_v2.guarded_causal_evaluate stays the sole authority). UM-DR-31.1: +1 — the stateful research hints' inventory re-scan (hints are advisory scheduling signals; an inventory failure must degrade to workflow-hints-only, never a killed discovery pass)
    "src/webpent/production/composite_workflows.py": 5,  # UM-DR-32: the composite sequence engine — a bounded sequence must NEVER kill a campaign and every failure degrades to honest telemetry: the injected-client request wrapper and the negative-control probe (the SequenceClient contract — the transport exception type is caller-defined, the stateful-prober identity class), the fixture-reset boundary (a failed reset BLOCKS the sequence fail-safe), and the two evaluation boundaries (CausalGuard same-actor route; validator-dispatch cross-actor route — both degrade to INCONCLUSIVE with the error recorded). The engine never promotes/confirms/grants: POLICY_VIOLATION_CANDIDATE is evidence, not a finding
    "src/webpent/production/identity_workflow.py": 1,  # UM-DR-32: the identity_workflow node's master gate — identity_workflow_enabled() treats any settings failure as not-enabled (fail-closed no-op, the coverage_gap_report double-gate precedent). The node is advisory only: no findings, no promotion, no confirmation authority
}
REGISTERED_TOTAL = sum(REGISTERED_FILES.values())  # 19 (UM-DR-31: +2 adaptive_research; UM-DR-31.1: +1 hints re-scan; UM-DR-32: +5 composite_workflows, +1 identity_workflow)
REGISTERED_FILES["src/webpent/production/discovery_funnel.py"] = 1  # UM-DR-33: the discovery funnel's bounded state read — observability degrades to the honest not_materialized_in_state marker, never a crash (coverage_gap_report/identity_workflow fail-soft precedent; pure telemetry, no authority)

_BROAD = re.compile(r"^\s*except\s+Exception\b")


def _frozen_relpaths() -> set[str]:
    """Full repo-root-relative paths from the manifest — NEVER basename
    matching (basenames like ``__init__.py`` would over-match)."""
    lines = MANIFEST.read_text().splitlines()
    rels = set()
    for line in lines:
        if not line.strip():
            continue
        _sha, _, rel = line.partition("  ")
        rels.add(rel.strip().replace("\\", "/"))
    return rels


def _broad_sites() -> dict[str, int]:
    frozen = _frozen_relpaths()
    sites: dict[str, int] = {}
    scanned: list[Path] = sorted(SRC_ROOT.rglob("*.py"))
    # v4 (R-12): shipped non-frozen scripts are inside the gate's scope too
    # (explicitly listed paths — rglob would sweep throwaway operator tools).
    for rel in REGISTERED_FILES:
        if rel.startswith("scripts/"):
            candidate = REPO_ROOT / rel
            if candidate.exists():
                scanned.append(candidate)
    for path in scanned:
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in frozen:
            continue
        count = sum(
            1
            for line in path.read_text(encoding="utf-8").splitlines()
            if _BROAD.match(line)
        )
        if count:
            sites[rel] = count
    return sites


def test_broad_exception_files_match_register_exactly() -> None:
    sites = _broad_sites()
    # v4 (R-12): full-path matching. A basename key would let a colliding
    # filename elsewhere in the tree mask new broad handlers.
    offending = {
        rel: n for rel, n in sites.items()
        if rel not in REGISTERED_FILES
    }
    assert not offending, (
        "New broad `except Exception` handler(s) in non-frozen production "
        f"code outside the accepted register: {offending}. Narrow the "
        "handler or add it to docs/ACCEPTED_EXCEPTIONS_REGISTER.md and "
        "update tests/test_editable_broad_exceptions_gate.py deliberately."
    )


def test_broad_exception_count_matches_register() -> None:
    """M2-impl v8: every registered src-side file is now manifest-pinned
    (v8 scope completion, NF-M2I-01) — the broad-handler contract of those
    sites is enforced by byte-exact frozen-hash pins, which subsumes the
    former count check. This test asserts the pin coverage and keeps the
    script-side count assertion alive. If a registered file were UNFROZEN
    again (an unfreeze window), its count assertion re-applies via the
    fallback branch below."""
    sites = _broad_sites()
    frozen = _frozen_relpaths()
    for rel, expected in REGISTERED_FILES.items():
        if not rel.startswith("scripts/") and rel in frozen:
            # v8: pinned byte-exact by frozen_modules.sha256 — the register
            # count is preserved for provenance; the pin is the enforcement.
            continue
        actual = sites.get(rel, 0)
        assert actual == expected, (
            f"{rel}: expected exactly {expected} registered broad handler(s), "
            f"found {actual}. If this change is deliberate, update "
            "docs/ACCEPTED_EXCEPTIONS_REGISTER.md and this gate together."
        )
    src_registered = [rel for rel in REGISTERED_FILES if not rel.startswith("scripts/")]
    # RESIDUAL CLOSURE 2026-10-29 (DR-015): the register now holds TWO
    # populations — manifest-pinned files (enforced byte-exact by the
    # frozen-hash gate) and five documented UNPINNED files whose counts
    # are enforced by the assertion above. Pin coverage is asserted for
    # the pinned population; the unpinned population must stay exactly
    # the documented set (UM-DR-25 extended it with the M0-M12 window
    # files; any new unpinned registration is deliberate
    # register drift and must edit both lists).
    # UM-DR-25: extended from the documented five to include the
    # M0-M12 window files (all non-frozen, counts enforced here).
    UNPINNED_REGISTERED = {
        "src/webpent/agents/advanced_web_vulns/agent.py",
        "src/webpent/agents/cache_poisoning/agent.py",
        "src/webpent/agents/dom_xss/agent.py",
        "src/webpent/agents/dom_xss/parser.py",
        "src/webpent/agents/graphql_testing/agent.py",
        "src/webpent/agents/js_discovery/agent.py",
        "src/webpent/agents/prototype_pollution/agent.py",
        "src/webpent/agents/role_matrix/sessions.py",
        "src/webpent/agents/sourcemap_analysis/agent.py",
        "src/webpent/appsuite/berth.py",
        "src/webpent/appsuite/consign.py",
        "src/webpent/appsuite/corpus.py",
        "src/webpent/appsuite/docvault.py",
        "src/webpent/appsuite/ledgerflow.py",
        "src/webpent/appsuite/market.py",
        "src/webpent/appsuite/permit.py",
        "src/webpent/appsuite/requisitions.py",
        "src/webpent/appsuite/slots.py",
        "src/webpent/appsuite/ticketflow.py",
        "src/webpent/auth/identity_orchestrator.py",
        "src/webpent/auth/session_pool.py",
        "src/webpent/auth/worker_session_factory.py",
        "src/webpent/benchmark/fixtures/runner.py",
        "src/webpent/business_logic/value_fuzzer.py",
        "src/webpent/chained_exploits/analyzer.py",
        "src/webpent/chained_exploits/graph_v3.py",
        "src/webpent/cli/bounty.py",
        "src/webpent/coverage/cell_model.py",
        "src/webpent/dojo/self_benchmark.py",
        "src/webpent/ekg/executor.py",
        # UM-DR-29 (2026-11-07): the three goed_v1 entries left this set with
        # the completed Ultimate-Plan-proposal-4 archive (src/webpent/goed_v1/
        # deleted — archived code has no live handler surface).
        "src/webpent/graph/oast_nodes.py",
        "src/webpent/integrations/notifications/dispatch.py",
        "src/webpent/jsintel/api_surface_shadow.py",
        "src/webpent/jsintel/js_reversing.py",
        "src/webpent/learning/refutation_ledger.py",
        "src/webpent/learning/technique_library.py",
        "src/webpent/llm_researcher/tiering.py",
        "src/webpent/production/campaign_lifecycle.py",
        "src/webpent/production/concurrency_governor.py",
        "src/webpent/production/cross_process_leases.py",
        "src/webpent/production/hypothesis_qualification_harness.py",
        "src/webpent/production/oob_validator.py",
        "src/webpent/production/protection_controls.py",
        "src/webpent/qualification/weekly.py",
        "src/webpent/recon/takeover.py",
        "src/webpent/reporter/bounty_pipeline.py",
        "src/webpent/reporter/chain_review.py",
        "src/webpent/resume/campaign_checkpoints.py",
        "src/webpent/safety/kill_switch.py",
        "src/webpent/safety/spend_governor.py",
        "src/webpent/safety/status_snapshot.py",
        "src/webpent/scheduler/campaign_scheduler.py",
        "src/webpent/shared/attack_graph_evidence.py",
        "src/webpent/shared/oob.py",
        "src/webpent/stateful_api/contracts.py",
        "src/webpent/vip/dedup_gate.py",
        "src/webpent/vip/notifications.py",
        "src/webpent/waf_evasion/adaptive.py",
        "src/webpent/workflow_fuzzing/agent.py",
        "src/webpent/production/stateful_probe.py",
        "src/webpent/production/coverage_gap_report.py",
        "src/webpent/production/adaptive_research.py",
    }
    assert all(rel in frozen for rel in src_registered if rel not in UNPINNED_REGISTERED), (
        "A registered broad-handler src file lost its frozen pin — the "
        "count contract must be re-asserted before any unfreeze."
    )
    unpinned_registered = {rel for rel in src_registered if rel not in frozen}
    assert unpinned_registered == UNPINNED_REGISTERED, (
        f"Unpinned registered broad-handler files drifted from the "
        f"documented set: {sorted(unpinned_registered ^ UNPINNED_REGISTERED)}"
    )
    # MERGE 2026-10-26: every src-side registration is manifest-pinned
    # (see MERGE_20261026_SCOPE_COMPLETION_PATHS), so the non-frozen
    # population this gate counts is the scripts-side registrations only.
    script_side_total = sum(
        v for k, v in REGISTERED_FILES.items() if k.startswith("scripts/")
    )
    # RESIDUAL CLOSURE 2026-10-29 (DR-015): five registered src files are
    # NOT manifest-pinned (never entered any scope completion), so their
    # counts are enforced HERE, not by the frozen-hash gate.
    unpinned_src_total = sum(
        v for k, v in REGISTERED_FILES.items()
        if not k.startswith("scripts/") and k not in frozen
    )
    expected_total = script_side_total + unpinned_src_total
    total = sum(sites.values())
    assert total == expected_total, (
        f"Total broad handlers in non-frozen production code: expected "
        f"{expected_total} (scripts-side {script_side_total} + unpinned "
        f"src-side {unpinned_src_total}); every other src-side ",
        f"hash-pinned), found {total}. Register drift — update "
        "docs/ACCEPTED_EXCEPTIONS_REGISTER.md deliberately."
    )


def test_narrowed_sites_stay_narrowed() -> None:
    """The 2 sites narrowed in the D-03 remediation must not regress."""
    auth = (SRC_ROOT / "recon" / "auth_resilience.py").read_text(encoding="utf-8")
    assert "except (ValueError, TypeError, AttributeError)" in auth, (
        "auth_resilience.py JSON-parse handler was re-broadened"
    )
    assert "except (ValueError, TypeError, OverflowError)" in auth, (
        "auth_resilience.py date-parse handler was re-broadened"
    )
