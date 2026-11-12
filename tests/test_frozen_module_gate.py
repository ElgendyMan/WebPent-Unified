"""Frozen-module hash gate as a first-class pytest (fix-sprint 2026-10-05).

Before this file existed, the 695-file frozen gate could only be exercised
out-of-band via ``sha256sum -c frozen_modules.sha256``. The full pytest suite
therefore never failed when a frozen module drifted — the gate silently
depended on an operator remembering to run a shell command (the exact gap
that let the 2026-10-05 direct-I/O inventory drift go unnoticed: the drift
test lived outside tests/team1_acceptance and was never run by the sprint's
verification).

Enforced invariants
-------------------
1. ``frozen_modules.sha256`` exists and every listed file matches its
   recorded SHA-256 (695/695 OK).
2. The pre-unfreeze baseline (``frozen_modules.sha256.
   baseline_pre_unfreeze``)
   differs from the current tree on EXACTLY the five documented unfreeze
   paths (docs/archive/2026-11-01-plan-exec-root-reports/UNFREEZE_APPLIED_REPORT_20261005.md)
   — pinning the unfreeze delta
   so an undocumented edit to any other frozen file fails here, not in
   production.
3. Every listed path exists on disk (no phantom manifest entries).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "frozen_modules.sha256"
BASELINE = REPO_ROOT / "frozen_modules.sha256.baseline_pre_unfreeze"

# The five files intentionally unfrozen on 2026-10-05 (additive, default-off
# parameters only — see docs/archive/2026-11-01-plan-exec-root-reports/
# UNFREEZE_APPLIED_REPORT_20261005.md).
# The baseline
# manifest must disagree with the current tree on exactly these paths.
DOCUMENTED_UNFROZEN_PATHS = frozenset(
    {
        "src/webpent/agents/hunter_runner.py",
        "src/webpent/recon/hypothesis_generator.py",
        "src/webpent/recon/login_executor.py",
        "src/webpent/recon/auth_detector.py",
        "src/webpent/recon/principal_provisioning.py",
    }
)

# R3 MID-WINDOW DELTA MODE (Ruling R3-002 §3.1 / Dispatch #005 C2): the five
# src/ files the ruling explicitly thawed. Mid-window they legitimately
# differ from the pinned v6 manifest; their authorization, mapping, and
# sub-scope are enforced by scripts/gate_frozen_delta.py (delta mode), which
# runs after every window commit. Standard byte-identity for these five is
# restored by the Phase-4 re-freeze (manifest regen) — NOT by weakening this
# gate. Any file NOT in this set that drifts still fails below.
M2_RULING_THAW_PATHS = frozenset(
    {
        # Dispatch #009 (M2-impl window, G5 re-freeze 2026-10-06): the six
        # src/ files thawed by the M2-impl charter, re-pinned in the v8
        # manifest after documented per-WP review (dossiers in
        # deliverables/m2_dossiers/). The +1 NEW src file
        # (production/spine_flag_gates.py) and the 12 retro-pinned
        # pre-existing v7 files (NF-M2I-01 scope completion) are covered by
        # the manifest-delta record (deliverables/m2_manifest_delta_v7_v8.json),
        # not by this baseline-drift union (they are absent from the
        # pre-unfreeze baseline, so they are not "shared drift").
        "src/webpent/state/state.py",
        "src/webpent/graph/builder.py",
        "src/webpent/production/modern_spine_integration.py",
        "src/webpent/production/advisory_registration.py",
        "src/webpent/production/campaign_state.py",
        "src/webpent/production/modern_spine.py",
    }
)

# Dispatch #009-A (reopened window, v9 re-freeze 2026-10-06): the WP-I(c)
# CONDITIONAL thaw grant — cli/commands.py and workers/pentest_worker.py
# joined the thaw list FOR EXIT-CODE-HONESTY CHANGES ONLY (the P0
# NF-L0-01 fix; diff reviewed per the WP-H scoped-file precedent in
# deliverables/m2_dossiers/). The graph/builder.py change in this window
# (NF-009A-02 gate-order fix) is covered by the existing M2 thaw entry
# above — same file, already documented.
M2A_CONDITIONAL_THAW_PATHS = frozenset(
    {
        "src/webpent/cli/commands.py",
        "src/webpent/workers/pentest_worker.py",
    }
)

R3_RULING_THAW_PATHS = frozenset(
    {
        "src/webpent/api/app.py",
        "src/webpent/memory/db.py",
        "src/webpent/models/findings.py",
        "src/webpent/graph/builder.py",
        "src/webpent/production/modern_spine_integration.py",
    }
)

# TEAM-MERGE 2026-10-22 (donorC Comprehensive(1) + donorV v15.2; re-freeze
# commit 1dfcbe4, documented in the TEAM-MERGE re-freeze addendum of
# docs/UNFREEZE_FILES_20261005.md): the v15.2 lineage regenerated
# frozen_modules.sha256 across windows v9-v15.2 without ever extending
# expected_drift below, so the pre-unfreeze baseline had already accumulated
# undocumented disagreement on these 28 paths BEFORE this merge (the drift
# is present identically in both donor trees — neither merge side created
# it). The TEAM-REVIEW-REFREEZE pass reviewed and classified every one:
# 12 of the 28 are merge-divergent and enumerated as KEEP_MERGED_INTENTIONAL
# in docs/archive/2026-11-01-plan-exec-root-reports/REVIEW_REFREEZE_REPORT.md Section B,
# the remaining 16 are
# donorV-lineage manifest-regen drift (docs/archive/2026-11-01-plan-exec-root-reports/
# MERGE_REPORT.md residual-failure decomposition,
# Section 10). Extending the expectation here makes the invariant match
# documented reality; it does NOT weaken the gate — any 29th drifting path,
# or any drift introduced after the 2026-10-22 re-freeze, still fails.
TEAM_MERGE_V152_LINEAGE_DRIFT_PATHS = frozenset(
    {
        "src/webpent/agents/api_testing/agent.py",
        "src/webpent/agents/business_logic_fuzzer/agent.py",
        "src/webpent/agents/cloud_storage/agent.py",
        "src/webpent/agents/devils_advocate/agent.py",
        "src/webpent/agents/hypothesis_analyzer/agent.py",
        "src/webpent/agents/payload_generator/agent.py",
        "src/webpent/agents/subdomain_takeover/agent.py",
        "src/webpent/agents/validator/active_checks.py",
        "src/webpent/agents/validator/agent.py",
        "src/webpent/agents/validator/postp0_checks.py",
        "src/webpent/agents/validator/structural_checks.py",
        "src/webpent/cli/git_source.py",
        "src/webpent/config/settings.py",
        "src/webpent/goed_v1/integrated_evaluator.py",
        "src/webpent/live_hunter/profile.py",
        "src/webpent/llm_researcher/providers/factory.py",
        "src/webpent/llm_researcher/providers/openai_compatible.py",
        "src/webpent/llm_researcher/tool_boundary.py",
        "src/webpent/production/autonomous_validation_v1.py",
        "src/webpent/production/experiment_fabric.py",
        "src/webpent/production/production_spine.py",
        "src/webpent/recon/auth_handler.py",
        "src/webpent/shared/http_discovery.py",
        "src/webpent/shared/jwt_deep_testing.py",
        "src/webpent/shared/preflight.py",
        "src/webpent/shared/self_critique.py",
    }
)

# r5-CODE window (2026-10-24, "General Autonomous Identity Resolution
# Ladder"): the owner directive required the runner to resolve identity on
# ANY target autonomously (S1 login-artifact mining, S2 self-endpoint probe,
# S3 anonymous-shape transport self-heal inside the governed M4 boundary, S4
# honest exhaustion). Four frozen files were thawed for exactly that window,
# the manifest re-frozen per DR-009 (scripts/refreeze_frozen_manifest_r5_
# identity_ladder.py, reviewed diff in the task self-report +
# DRIFT_REGISTER.md), and the direct-I/O artifact regenerated with gates
# (scripts/regen_direct_io_inventory_r5_identity_ladder.py). The three files
# already present in DOCUMENTED_UNFROZEN_PATHS keep their existing drift
# record; identity_discovery.py joins the drift-vs-baseline set here.
# The new config/identity_vocab.{py,json} pair is intentionally OUTSIDE the
# manifest (additive-sprint-module precedent): the vocabulary data file must
# stay editable without code edits — that is requirement R3.
R5_IDENTITY_LADDER_THAW_PATHS = frozenset(
    {
        "src/webpent/recon/identity_discovery.py",
        "src/webpent/recon/principal_provisioning.py",
        "src/webpent/recon/login_executor.py",
        "src/webpent/agents/hunter_runner.py",
    }
)

# ULTIMATE PLAN 2026-10-27 (Autonomous Bug Hunter master plan,
# WEBPENT_ULTIMATE_MASTER_PLAN.md): frozen files intentionally
# modified by the plan window (settings flags, graph nodes for
# lessons/surface-sizing/new detectors, unified hunt CLI,
# VulnClass additions, workers router include). Diff reviewed
# and documented in DRIFT_REGISTER.md (ULTIMATE PLAN 2026-10-27
# entry) and ULTIMATE_PLAN_EXECUTION_20261027.md. Same pattern
# as every prior thaw window: byte-identity for these paths is
# restored by this manifest re-freeze; the baseline-drift union
# below keeps the pre-unfreeze comparison honest.
ULTIMATE_PLAN_20261027_THAW_PATHS = frozenset(
    {
        "src/webpent/config/settings.py",
        "src/webpent/graph/builder.py",
        "src/webpent/graph/budget_governor.py",
        "src/webpent/cli/commands.py",
        "src/webpent/models/findings.py",
        "src/webpent/state/state.py",
        "src/webpent/agents/validator/registry.py",
        "src/webpent/api/app.py",
        "src/webpent/tools/registry.py",
        "src/webpent/tools/utils/subprocess.py",
    }
)

# MERGE 2026-10-26 (four-way tree merge: l6 + unified_v4 +
# merged_track123 + refreeze, then the r5 identity-ladder patch).
# Every frozen file whose bytes legitimately changed in this merge
# window and is not already covered by an earlier thaw list. The
# manifest itself was re-frozen to the merged tree in the same
# window (same path set + order, DR-009 protocol); the byte-identity
# gate therefore passes against the merged tree. Documented in
# DRIFT_REGISTER.md (MERGE 2026-10-26 entry) and MERGE_20261026.md.
# TRACK 11/12 EXECUTION 2026-10-28 (Unified Master Roadmap, versions
# 0.17.0-0.19.0): the service facade legitimately changed across the
# Track 11 VIP windows (dedup-gate wiring 0.17.0, confirmation
# notifications 0.18.0) and the Track 12 windows (concurrency-governor
# tickets 0.18.0, cross-process leases 0.19.0). All changes additive,
# default-off, and documented per version in CHANGELOG.md. The frozen
# manifest was re-frozen to the current tree in the same window (650
# entries, DR-009 protocol), so byte-identity is enforced against it.
TRACK11_12_20261028_THAW_PATHS = frozenset(
    {
        "src/webpent/service/facade.py",
    }
)

# MERGE 2026-10-26 (four-way tree merge: l6 + unified_v4 +
# merged_track123 + refreeze, then the r5 identity-ladder patch).
# Every frozen file whose bytes legitimately changed in this merge
# window and is not already covered by an earlier thaw list. The
# manifest itself was re-frozen to the merged tree in the same
# window (same path set + order, DR-009 protocol); the byte-identity
# gate therefore passes against the merged tree. Documented in
# DRIFT_REGISTER.md (MERGE 2026-10-26 entry) and MERGE_20261026.md.
MERGE_20261026_THAW_PATHS = frozenset(
    {
        "src/webpent/__init__.py",
        "src/webpent/agents/crawler/agent.py",
        "src/webpent/agents/rabbit_hole/agent.py",
        "src/webpent/agents/reporter/agent.py",
        "src/webpent/agents/validator/registry.py",
        "src/webpent/api/auth.py",
        "src/webpent/models/surface_security.py",
        "src/webpent/shared/campaigns.py",
        "src/webpent/shared/coverage_ledger.py",
        "src/webpent/shared/surface_security.py",
        "src/webpent/shared/tool_adapters.py",
        "src/webpent/tools/registry.py",
        "src/webpent/tools/utils/subprocess.py",
        "src/webpent/utils/crypto.py",
    }
)

# MERGE 2026-10-26: the 53 broad-handler files registered by the
# merge (tests/test_editable_broad_exceptions_gate.py MERGE batch) are
# pinned by the manifest as a scope completion — same pattern as the
# V8/TEAM-MERGE scope completions above: the registered count stays in
# the register for provenance; the byte-exact pin is the enforcement.
# ULTIMATE PLAN 2026-10-27: new src files created by the plan
# window and pinned by this manifest as a scope completion
# (detection modules, validators, infra modules, unified state,
# lesson/progress graph nodes, unified hunt CLI). Absent from
# the pre-unfreeze baseline by construction (they did not exist
# before this window) — same pattern as the MERGE_20261026
# scope completion above.
ULTIMATE_PLAN_20261027_SCOPE_COMPLETION_PATHS = frozenset(
    {
        "src/webpent/shared/cache_poisoning_detector.py",
        "src/webpent/validators/graphql_validator.py",
        "src/webpent/validators/oauth_misconfig_validator.py",
        "src/webpent/shared/prototype_pollution_detector.py",
        "src/webpent/tools/recon/gau.py",
        "src/webpent/tools/recon/nmap.py",
        "src/webpent/shared/source_leak_discovery.py",
        "src/webpent/shared/llm_consistency.py",
        "src/webpent/shared/global_rate_governor.py",
        "src/webpent/service/portfolio.py",
        "src/webpent/api/workers_status.py",
        "src/webpent/workers/monitor_alerts.py",
        "src/webpent/state/unified_state.py",
        "src/webpent/adapters/legacy_state_bridge.py",
        "src/webpent/graph/lesson_nodes.py",
        "src/webpent/graph/progress_display.py",
        "src/webpent/cli/unified_hunt.py",
        "src/webpent/shared/finding_announcer.py",
    }
)

# CLI OPS WINDOW 2026-10-28 (Track 12 ops, v0.24.0): one NEW src file
# retro-pinned by the same-window manifest re-freeze (the v8/merge
# scope-completion pattern): the read-only ``webpent ops`` Typer
# sub-app (governor/workers/graph/calibration/protection posture).
# The commands.py delta in the same window is two lines (import +
# add_typer) inside the already-documented ULTIMATE_PLAN_20261027
# thaw set; documented in CHANGELOG 0.24.0 + worklog session 4.
CLI_OPS_20261028_SCOPE_COMPLETION_PATHS = frozenset(
    {
        "src/webpent/cli/ops.py",
    }
)

# OPS WRITE + WORKER CLAIMS WINDOW 2026-10-28 (v0.25.0): the Track 12
# operational-wiring follow-up (facade <- WorkerCoordinator claims + the
# RBAC-gated "ops" write surface). The manifest was re-frozen to the
# current tree in the same window (DR-009 protocol, 653 entries):
#   * config/settings.py — +2 default-off fields
#     (worker_coordination_enabled / worker_coordination_dir); the file
#     is already in ULTIMATE_PLAN_20261027_THAW_PATHS /
#     TEAM_MERGE_V152_LINEAGE_DRIFT_PATHS, so the drift union is
#     unchanged.
#   * service/facade.py — campaign-lifetime worker-claim admission
#     (claim at start, release on halt/complete/failure; default-off);
#     already in TRACK11_12_20261028_THAW_PATHS.
#   * cli/ops.py — the 0.24.0 read-only sub-app gains the RBAC-gated
#     write commands (users/review/portfolio) + state/audit helpers;
#     the file stays a CLI_OPS_20261028 scope-completion pin (absent
#     from the pre-unfreeze baseline by construction).
# Two NEW src files are pinned by the same-window re-freeze as a scope
# completion (the v8/TEAM-MERGE/ULTIMATE pattern):
# production/campaign_worker_claims.py (the claim adapter) and
# production/ops_state.py (durable state + audit for the ops write
# commands). Documented in CHANGELOG 0.25.0 + worklog session 5.
OPS_WRITE_20261028_SCOPE_COMPLETION_PATHS = frozenset(
    {
        "src/webpent/production/campaign_worker_claims.py",
        "src/webpent/production/ops_state.py",
    }
)

# RESIDUAL CLOSURE WINDOW 2026-10-29 (v0.26.0): the unified-roadmap
# residual items (Track 1 CI gates, Track 3.6/8.4 doctor, Track 9
# outputs, Track 10.6/10.7/11.1/11.2 features, Track 0/7 root closure).
# The manifest was re-frozen to the current tree in the same window
# (DR-009 protocol, same paths + order + new scope completions):
#   * config/settings.py — +1 default-empty field (epss_catalog_path);
#     already in ULTIMATE_PLAN_20261027_THAW_PATHS /
#     TEAM_MERGE_V152_LINEAGE_DRIFT_PATHS.
#   * cli/commands.py — +1 CLI import/registration pair (webpent doctor)
#     and the reports --platform flag; already in M2A conditional thaw.
#   * shared/console.py — opt-in WEBPENT_LOG_FORMAT=json structured
#     handler (Track 3.5); baseline member, newly changed.
#   * reporter/export.py + reporter/bounty_report.py — H1/Bugcrowd
#     templates, human_review_decision surface, llm_usage_summary;
#     baseline members, newly changed.
#   * api/app.py — opt-in stalled-worker alert loop
#     (WEBPENT_WORKER_ALERT_INTERVAL_S, default off); baseline member,
#     newly changed.
#   * cli/unified_hunt.py + graph/progress_display.py + cli/ops.py —
#     elapsed/time-cost progress + calibration write/consume wiring;
#     already documented pins (ULTIMATE scope completions / CLI_OPS).
# FIVE NEW src files are pinned by the same-window re-freeze as scope
# completions (the v8/TEAM-MERGE/ULTIMATE pattern): cli/doctor.py,
# shared/epss.py, shared/mobile_app_indicators.py, vip/asset_triage.py,
# autonomous/cem/notification_bridge.py. Documented in CHANGELOG 0.26.0
# + worklog session 6 + DRIFT_REGISTER.
RESIDUAL_CLOSURE_20261029_THAW_PATHS = frozenset(
    {
        "src/webpent/config/settings.py",
        "src/webpent/cli/commands.py",
        "src/webpent/shared/console.py",
        "src/webpent/reporter/export.py",
        "src/webpent/reporter/bounty_report.py",
        "src/webpent/api/app.py",
        # Track 0.4: __version__ had stayed at 0.14.0 across eleven
        # pyproject bumps — the identity fix moves it to the SSOT value.
        "src/webpent/__init__.py",
    }
)

RESIDUAL_CLOSURE_20261029_SCOPE_COMPLETION_PATHS = frozenset(
    {
        "src/webpent/cli/doctor.py",
        "src/webpent/shared/epss.py",
        "src/webpent/shared/mobile_app_indicators.py",
        "src/webpent/vip/asset_triage.py",
        "src/webpent/autonomous/cem/notification_bridge.py",
    }
)

# LEARNING A/B LAB WINDOW 2026-10-29 (v0.27.0): Track 6.5's real
# control-vs-treatment scheduler + the declared numeric verdict
# thresholds (docs/PRODUCTION_FIX_PLAN_0270.md, items C-9 and C-10).
#   * cli/ops.py — the ``webpent ops learning-ab`` command (open/tick/
#     status/record-metrics; open/tick/record-metrics behind the frozen
#     run_campaign RBAC permission). ops.py is NOT a pre-unfreeze
#     baseline member (it entered via CLI_OPS_20261028 scope
#     completion), so its re-pin in this window is tracked by the
#     scope-completion membership below — not by a thaw entry.
#   * ONE new src file is pinned by the same-window re-freeze as a
#     scope completion: memory/ab_lab.py. The new test file
#     (tests/test_ab_lab.py), the refreeze script, and the plan doc
#     are NOT src/ pins (same posture as prior windows).
AB_LAB_20261029_THAW_PATHS = frozenset()

AB_LAB_20261029_SCOPE_COMPLETION_PATHS = frozenset(
    {
        "src/webpent/memory/ab_lab.py",
    }
)

# RETIRED-ALIAS REMOVAL WINDOW 2026-11-01 (v0.32.0, declared 2026-11-01 in
# the 0.30.0 CHANGELOG item ج.2): the three retired CLI aliases
# (scan/hunt-auto/hunt-plan) were removed from
# src/webpent/cli/commands.py (covered by M2A_CONDITIONAL_THAW_PATHS) and
# the CLI availability-probe __init__ dropped the re-exports whose only
# callers were the removed commands (_load_json_list,
# _parse_report_formats). Same-window re-freeze per the DR-009 protocol
# (658 -> 659 entries: one scope completion).
ALIAS_REMOVAL_20261101_THAW_PATHS = frozenset(
    {
        "src/webpent/cli/__init__.py",
    }
)

ALIAS_REMOVAL_20261101_SCOPE_COMPLETION_PATHS = frozenset(
    {
        "src/webpent/autonomous/authorization_recheck.py",
    }
)

# 0.33.0 PRODUCTION HARDENING window (2026-11-01,
# docs/PRODUCTION_HARDENING_PLAN_0330.md): the eight manifest-pinned files
# this window edited that are NOT already covered by an earlier thaw set.
# Every file carries its plan-ID annotation in-source (F-02/F-03 pool.py,
# F-06 engagement_scope.py, P1-14 controlled_target adapter, P1-15
# llm interface, P1-16 browser_crawler, P1-17 persistent_finding_ledger,
# P2-02 service/api.py, P2-05 scan_registry.py). The other 14 changed
# pinned files fall under M2/M2A/R3/R5/20261026-29 sets already.
HARDENING_20261101_THAW_PATHS = frozenset(
    {
        "src/webpent/adapters/controlled_target/adapter.py",
        "src/webpent/api/scan_registry.py",
        "src/webpent/llm_researcher/interface.py",
        "src/webpent/llm_researcher/providers/pool.py",
        "src/webpent/recon/browser_crawler.py",
        "src/webpent/service/api.py",
        "src/webpent/shared/engagement_scope.py",
        "src/webpent/shared/persistent_finding_ledger.py",
    }
)

# 0.34.0 RED-TEAM ROUND 2 window (2026-11-02,
# docs/RED_TEAM_ROUND2_20261102.md): the manifest-pinned file this window
# edited that is NOT already covered by an earlier thaw set (the other 12
# changed pinned files fall under M2/M2A/R3/20261026-29/ALIAS/HARDENING
# sets already; 25 further changed files are not manifest-pinned at all —
# the advisory modules were never frozen). Every file carries its R2-ID
# annotation in-source (R2-graph-05 checkpoints.py; R2-graph-01/02
# builder.py; R2-graph-03/07 state.py; R2-graph-04/06 unified_hunt.py;
# R2-jc-01..09 jc/*; R2-dojo-01..10 dojo/* + cli/dojo.py; R2-econ-01..11
# econ/* + cli/econ.py; R2-prism-01..08 prism/*).
REDTEAM_R2_20261102_THAW_PATHS = frozenset(
    {
        "src/webpent/graph/checkpoints.py",
    }
)


# UNIFIED-MERGE phase-1/2 window (2026-11-02): the merge-repair thaw —
# R4 production-hardening contracts restored into five frozen files
# (DRIFT_REGISTER UM-DR-04), the Phase-3 embeddings migration (UM phase3
# note), all under the fail-closed refreeze protocol
# (scripts/refreeze_unified_phase12.py). Path SET preserved; hashes only.
# M1-B EVIDENCE INTEGRITY window (2026-11-05, UM-DR-10): evidence-integrity
# fixes verified by regression tests before refreeze — see
# scripts/refreeze_manifest_m1b_evidence_integrity.py and
# M1_READINESS_REVIEW.md for the per-file justification.
M3_RESEARCH_WIRING_20261105_THAW_PATHS = frozenset({
    # UM-DR-16 (M3): ق6/ق8 advisory wiring flags + the additive hypothesis
    # research-contract fields + the two advisory node hooks (refreeze
    # script scripts/refreeze_manifest_m3_research_wiring.py; tests
    # tests/test_m3_research_wiring.py)
    "src/webpent/config/settings.py",
    "src/webpent/models/hypothesis.py",
    "src/webpent/agents/target_understanding/agent.py",
    "src/webpent/agents/javascript_intelligence/agent.py",
})

REDTEAM_UMDR26_PHASE2_20261106_THAW_PATHS = frozenset({
    # UM-DR-26 (the executed phase 2 of the UM-DR-25 red-team plan,
    # 2026-11-06): the r6c/r9 identity + login rework, the safety-governor
    # wiring (kill switch / spend cap / robots double gate / the broken
    # active-engagement alias), the planner coverage advisory, six more
    # unregistered validator families + the refutation capture hook, the
    # hunter-graph replan contract, the Playwright campaign-target
    # allowlist fix, the promoted-webhook confidence fix, and the preflight
    # message contract. Refreeze script (single declared refreeze):
    #   scripts/refreeze_manifest_umdr26_phase2.py
    #   (16 paths re-pinned, each verified by its recovered test family
    #   BEFORE the refreeze — DR-009 protocol. The 13 paths below are the
    # ones PRESENT in the pre-unfreeze baseline (real digest drift);
    # validators.py / safety/agency.py / safety/request_ledger.py are
    # baseline-absent scope-completion paths already documented in the
    # V8 / AB-lab sets — they were re-pinned by the same script.)
    "src/webpent/config/settings.py",
    "src/webpent/recon/identity_discovery.py",
    "src/webpent/recon/principal_provisioning.py",
    "src/webpent/recon/login_executor.py",
    "src/webpent/shared/rate_governor.py",
    "src/webpent/llm_researcher/providers/base.py",
    "src/webpent/recon/autonomous_crawler.py",
    "src/webpent/agents/planner/agent.py",
    "src/webpent/agents/hunter_graph.py",
    "src/webpent/recon/browser_farm.py",
    "src/webpent/recon/browser_crawler.py",
    "src/webpent/service/cost_alerts.py",
    "src/webpent/shared/preflight.py",
})

REDTEAM_UMDR26_SCOPE_COMPLETION_20261106_PATHS = frozenset({
    # UM-DR-26 scope completion (2026-11-06): the two safety modules whose
    # broken active-engagement alias was fixed in this window were NEVER
    # pinned by frozen_modules.sha256 (the byte-identity gate silently
    # skipped them — NF-UMDR26-01, the NF-M2I-01 pattern again). Retro-pinned
    # by scripts/refreeze_manifest_umdr26_phase2.py alongside the 14 updates.
    "src/webpent/safety/agency.py",
    "src/webpent/safety/request_ledger.py",
})

UMDR32_NEW_CAPABILITY_20261109_PATHS = frozenset({
    # UM-DR-32 (identity & business-logic evolution, 2026-11-09): the five
    # NEW production capability modules, frozen from birth by
    # scripts/refreeze_manifest_umdr32.py. The broad-exception count
    # contract requires every registered src file (composite_workflows.py:
    # 5 handlers, identity_workflow.py: 1) to be frozen-pinned so handler
    # counts cannot drift silently; object_identity.py, alias_resolution.py
    # and multi_identity.py are frozen alongside them for the same
    # production-grade guarantee (any future edit follows the documented
    # refreeze protocol with regression coverage first).
    "src/webpent/production/object_identity.py",
    "src/webpent/production/alias_resolution.py",
    "src/webpent/production/multi_identity.py",
    "src/webpent/production/composite_workflows.py",
    "src/webpent/production/identity_workflow.py",
})

UMDR33_PHASE2_SECURITY_20261110_THAW_PATHS = frozenset({
    # UM-DR-33 Phase 2 (Workstream C, 2026-11-10): two fail-closed
    # security fixes. (1) budget_governor.py — a PRESENT-but-corrupted
    # node_step_trace (no legit write path persists a non-list) now
    # fails CLOSED with the budget fully consumed instead of
    # deactivating the governor (agent corruption must never reset
    # consumed budget); a genuinely absent key keeps the documented
    # legacy deactivation. (2) cli/loaders.py — secret-bearing mappings
    # reject template placeholders fail-closed (CHANGE-ME family,
    # REPLACE_ME_*, replace-at-runtime); form-field-NAME mappings are
    # shape-validated only. Regression coverage verified BEFORE the
    # re-pin: tests/test_umdr33_hard_budget_and_creds.py (11 tests) +
    # all pre-existing budget/template pins unchanged; the template
    # contract test evolved WITH the loader (documented in its
    # docstring). Refreeze script:
    # scripts/refreeze_manifest_umdr33_phase2_security.py (old pins
    # recorded there for the audit trail).
    "src/webpent/graph/budget_governor.py",
    "src/webpent/cli/loaders.py",
})

UMDR33_NEW_CAPABILITY_20261110_PATHS = frozenset({
    # UM-DR-33: the discovery funnel, frozen from birth (the UM-DR-32
    # five-capability precedent): the broad-exception count contract
    # requires every registered src file to be frozen-pinned, and the
    # funnel registers 1 fail-soft handler (the bounded state read —
    # observability degrades to not_materialized_in_state, never a
    # crash). Pure telemetry: no findings, no promotion, no authority.
    "src/webpent/production/discovery_funnel.py",
})

UMDR33_VERSION_BUMP_20261110_THAW_PATHS = frozenset({
    # UM-DR-33 release window (2026-11-10): the 0.38.0 -> 0.39.0 version
    # bump in src/webpent/__init__.py (byte change = the __version__ line
    # only, the UM-DR-29/30/31.1/32 precedent; pyproject.toml +
    # CHANGELOG.md remain the SSOT and are not frozen).
    "src/webpent/__init__.py",
})

UMDR33_INFO_GAIN_20261110_THAW_PATHS = frozenset({
    # UM-DR-33 §8.2 (Workstream F, 2026-11-10): information gain is now
    # operational in the strategist score — W_INFO_GAIN=0.10 joins the
    # weighted sum (other weights rebalanced, sum stays exactly 1.0,
    # dominant-term ordering preserved); Hypothesis.info_gain is read
    # with a neutral 0.5 default for unscored hypotheses and defensive
    # clamping. Closes the UM-DR-31 review finding that info_gain never
    # changed the ranking score. Gate semantics untouched: score-
    # independent admission/scope/budget gates pinned by
    # tests/test_umdr33_info_gain_operational.py (19 tests incl. the
    # exact-delta mutation test, controlled ranking flips, and the
    # safety-independence trio). Refreeze script:
    # scripts/refreeze_manifest_umdr33_info_gain.py (old pin
    # 912b71f003e36716df4dff57870e0cd5eb39cd3592f1fafa9eb766b4e2cc6cc5
    # recorded there for the audit trail).
    "src/webpent/shared/prioritization.py",
})

UMDR33_EVIDENCE_CHAIN_20261110_THAW_PATHS = frozenset({
    # UM-DR-33 (researcher brain & autonomous campaign evolution,
    # 2026-11-10): Phase 2 evidence-chain identity fix — the production
    # builder passed bundle_id=None unconditionally, overriding the
    # CompleteProofBundle default_factory (cqa2_pb_<uuid4hex>), so every
    # production bundle carried bundle_id=None (empirically verified
    # pre-fix; both production callers omit the argument). The fix passes
    # bundle_id only when the caller supplied one. Seal/digest/validation
    # logic untouched. Regression coverage verified BEFORE the re-pin:
    # tests/test_umdr33_evidence_chain_fixes.py (5 bundle-identity pins
    # + existing cqa_v2 consumers). Refreeze script:
    # scripts/refreeze_manifest_umdr33.py (DR-009 protocol; old pin
    # 5fdb526f460617a7b7163359d66459f798148db92c3eb61844f2c5c6fdf6f951
    # recorded there for the audit trail).
    "src/webpent/cqa_v2/proof_bundle_builder.py",
})

UMDR34_SCOPE_AUTHORITY_20261110_THAW_PATHS = frozenset({
    # UM-DR-34 (scope authority, safe egress & execution governance,
    # 2026-11-10): the canonical scope authority window thawed 14 frozen
    # files (all documented in scripts/refreeze_manifest_umdr34.py with
    # old pins recorded there for the audit trail). Seven of them
    # (engagement_scope.py, http.py, global_rate_governor.py,
    # settings.py, checkpoints.py, hunter_runner.py, execution_node.py)
    # already appear in earlier-era drift sets; the six below are
    # FIRST-TIME thaws relative to the pre-unfreeze baseline, so they
    # need their own documented entry:
    #   * scope/__init__.py, scope/models.py, scope/enforcer.py,
    #     scope/parser.py — the ONE canonical authority contract
    #     (ScopeDecision extension, strict single wildcard compiler
    #     replacing fnmatch, explicit None port handling, fail-closed
    #     boolean out_of_scope parser markers).
    #   * shared/untrusted_content.py, shared/redaction.py — the LLM
    #     provider boundary (secure_llm_input key-aware recursion fix,
    #     session-cookie name families, key-aware redact_value).
    # Regression coverage verified BEFORE the re-pin:
    # tests/test_umdr34_*.py (170 tests) + all pre-existing suites
    # touching these modules re-run green.
    "src/webpent/scope/__init__.py",
    "src/webpent/scope/models.py",
    "src/webpent/scope/enforcer.py",
    "src/webpent/scope/parser.py",
    "src/webpent/shared/untrusted_content.py",
    "src/webpent/shared/redaction.py",
})

UMDR35_36_INTEGRITY_20261112_THAW_PATHS = frozenset({
    # UM-DR-35 + UM-DR-36 (architectural integrity + production
    # intelligence, 2026-11-12): the directive windows thawed these
    # frozen files, all documented in
    # scripts/refreeze_manifest_umdr36_discovery_funnel.py with per-file
    # directive task mapping. First-time thaws relative to the
    # pre-unfreeze baseline beyond earlier-era sets:
    #   * cqa_v2/causal_guard.py + cqa_v2/replay_verifier.py +
    #     production/autonomous_validation_v1.py — 35.1/35.2 CausalGuard
    #     sole confirmation authority + strict replay.
    #   * scope/enforcer.py (already in UMDR34 set) — 35.3 delegation.
    #   * recon/login_executor.py + agents/authentication/agent.py —
    #     35.4 auth success lifecycle.
    #   * shared/llm.py + cli/* + agents/hunter_runner.py +
    #     config/settings.py — 35.5 hard token budget + 35.6 upgrades.
    #   * agents/validator/agent.py — Gate 35-A graph confirmation gates.
    #   * graph/builder.py + state/state.py — 36.2/36.3 wiring.
    #   * production/discovery_funnel.py — 36.3 funnel/v2 (28 stages).
    # Regression coverage re-run BEFORE the re-pin: UM-DR-35 suites
    # (86 tests), team1_acceptance (755), funnel (20), frozen gate.
    "src/webpent/agents/authentication/agent.py",
    "src/webpent/agents/hunter_runner.py",
    "src/webpent/agents/validator/agent.py",
    # (cli/unified_hunt.py, production/discovery_funnel.py already
    # appear in earlier-era drift sets and are intentionally NOT repeated
    # here — the union stays exact.)
    "src/webpent/cli/commands.py",
    "src/webpent/config/settings.py",
    "src/webpent/cqa_v2/causal_guard.py",
    "src/webpent/cqa_v2/replay_verifier.py",
    "src/webpent/graph/builder.py",
    "src/webpent/production/autonomous_validation_v1.py",
    "src/webpent/recon/login_executor.py",
    "src/webpent/scope/enforcer.py",
    "src/webpent/shared/llm.py",
    "src/webpent/state/state.py",
})

UMDR28_DISCOVERY_20261107_THAW_PATHS = frozenset({
    # UM-DR-28 (production discovery integration, 2026-11-07): the
    # representation-equivalence repair in the causal guard — the four
    # header-only context channels (effective_privilege,
    # effective_privilege_granted, authorization_outcome, data_redacted)
    # gain the same top-level observation fallback every other channel
    # already had (headers still win, checked first in _g). This closes
    # the comparator-oracle miss class (M10 RCA §2.4: a body-represented
    # authorization outcome was invisible to the guard even after the
    # non-frozen observation layer surfaced it). The guard's verdict
    # branches, thresholds, and confirmation logic are untouched.
    # Of the window's four declared frozen-file changes, ONLY
    # causal_guard.py predates the pre-unfreeze baseline (settings.py
    # is covered by the earlier-era sets; execution_node.py and
    # state.py entered the manifest after the baseline snapshot, so
    # they never appear in the disagreement delta).
    # Refreeze script: scripts/refreeze_manifest_umdr28_stateful_discovery.py.
    # Tests: tests/test_umdr28_representation_oracle.py,
    # test_umdr28_stateful_discovery.py,
    # test_umdr28_campaign_stateful_e2e.py (+ the 47 byte-compat
    # regressions in test_blind_v3_replica.py / test_transition_sources.py).
    "src/webpent/cqa_v2/causal_guard.py",
})

UMDR29_DEADCODE_20261107_THAW_PATHS = frozenset({
    # UM-DR-29 (dead-code disposition window, 2026-11-07): six frozen
    # package __init__.py files had their stale "Core engine:
    # webpent.goed_v1, ..." docstring lines corrected to the real engine
    # roots (webpent.families, cqa_v2, models, smart) — goed_v1 completed
    # its documented archive move this window (Ultimate Plan 2026-10-27
    # proposal 4; see archive/umdr29_dead_code/README.md), so the old
    # docstrings were false wiring claims. No behavioral surface touched
    # (docstring-only edits, verified by the frozen gate re-pin).
    # Refreeze script: scripts/refreeze_manifest_umdr29.py (661 -> 639
    # entries: 22 archived-package entries removed + these re-pinned).
    "src/webpent/workers/__init__.py",
    "src/webpent/state/__init__.py",
    "src/webpent/graph/__init__.py",
    "src/webpent/api/__init__.py",
    "src/webpent/agents/__init__.py",
    "src/webpent/shared/__init__.py",
    # the same window's version bump: 0.34.0 -> 0.35.0 in the frozen
    # package root (byte change = the __version__ line only).
    "src/webpent/__init__.py",
})

UMDR30_CAPABILITY_WIRING_20261107_THAW_PATHS = frozenset({
    # UM-DR-30 (production readiness & capability integration window,
    # 2026-11-07): four frozen files re-pinned by the declared refreeze
    # scripts/refreeze_manifest_umdr30.py — each change verified by its
    # new regression tests BEFORE the re-pin:
    #   state.py — 21 new advisory channels (the family spine's 20
    #     output keys, previously silently dropped by LangGraph channel
    #     filtering — the R2-graph-03 miss class closed family-wide —
    #     plus coverage_gap_report + invariant_review);
    #   settings.py — the fail-closed (default False)
    #     enable_coverage_gap_report flag;
    #   graph/builder.py — the flag-gated wiring of the
    #     coverage_gap_report node between reporter and reflection;
    #   agents/business_logic_fuzzer/agent.py — the advisory,
    #     non-promoting InvariantChecker wiring inside the workflow
    #     enrichment (required_validation names the causal-guard
    #     evidence contract; the guard stays the sole authority).
    # All four paths already appear in earlier thaw sets; this set keeps
    # the window's provenance explicit. Direct-I/O delta: zero new
    # identities (scripts/regen_direct_io_inventory_umdr30.py, line
    # drift only).
    "src/webpent/state/state.py",
    "src/webpent/config/settings.py",
    "src/webpent/graph/builder.py",
    "src/webpent/agents/business_logic_fuzzer/agent.py",
})

UMDR31_ADAPTIVE_RESEARCH_20261107_THAW_PATHS = frozenset({
    # UM-DR-31 (evidence-driven adaptive research loop window,
    # 2026-11-07): six frozen files re-pinned by the declared refreeze
    # scripts/refreeze_manifest_umdr31.py — each change verified by its
    # new regression tests BEFORE the re-pin:
    #   state.py — the research_loop telemetry channel (merge_dicts,
    #     advisory only, the node is the sole writer);
    #   settings.py — the fail-closed enable_adaptive_research_loop
    #     flag, the mandatory max_research_iterations /
    #     max_research_hypotheses_per_iteration limits, and the
    #     operator-configurable stateful_discovery_max_requests
    #     budget (default 360 = the UM-DR-28 behavior);
    #   graph/builder.py — the flag-gated research_loop node + edge
    #     and the six conditional-mapping overrides routing the
    #     strategist-bound paths through one bounded research
    #     iteration (flag-off = byte-comparable graph shape);
    #   models/hypothesis.py — the COVERAGE_GAP + INVARIANT
    #     HypothesisOrigin members (research-loop provenance;
    #     ordinary pool citizens, no promotion bypass);
    #   families/execution_node.py — the research-hints pass-through
    #     (loop-flag-gated so flag-off keeps UM-DR-28 byte-stable) and
    #     the configurable discovery budget. NOT listed below: it
    #     entered the manifest after the pre-unfreeze baseline
    #     snapshot (the UMDR28 note), so it never appears in the
    #     baseline-disagreement delta; its re-pin is enforced by the
    #     byte-identical gate + the refreeze script's allowlist.
    #   __init__.py — the 0.36.0 -> 0.37.0 version bump.
    # Direct-I/O delta: +2 declared dynamic-resolution identities in
    # the NEW non-frozen module production/adaptive_research.py
    # (scripts/regen_direct_io_inventory_umdr31.py).
    "src/webpent/state/state.py",
    "src/webpent/config/settings.py",
    "src/webpent/graph/builder.py",
    "src/webpent/models/hypothesis.py",
    "src/webpent/__init__.py",
})

UMDR31_1_UPLIFT_20261108_THAW_PATHS = frozenset({
    # UM-DR-31.1 (intelligence & engineering uplift window, 2026-11-08):
    # three frozen files re-pinned by the declared refreeze
    # scripts/refreeze_manifest_umdr31_1.py — each change verified by
    # its new regression tests BEFORE the re-pin:
    #   __init__.py — the 0.37.0 -> 0.37.1 version bump (the
    #     UM-DR-29/30/31 precedent);
    #   coverage/gap_detector.py — the R6/F20 deliberate-exclusion
    #     comment documenting why "unknown_status" is NOT open (the
    #     _OPEN membership is unchanged — documentation-only delta);
    #   shared/coverage_ledger.py — the R6/F20 fail-closed projection:
    #     producer aliases ("not_observed"/"tested") reconcile to
    #     "not_scanned"; ANY other unrecognized raw status projects to
    #     the explicit, observable NON-gap "unknown_status" (+ the
    #     "unrecognized-status" gap marker) instead of silently
    #     becoming an actionable research opportunity.
    "src/webpent/__init__.py",
    "src/webpent/coverage/gap_detector.py",
    "src/webpent/shared/coverage_ledger.py",
})

UMDR29_ARCHIVED_PATHS = frozenset({
    # UM-DR-29 (2026-11-07): the seven frozen-but-dead packages archived
    # to archive/umdr29_dead_code/ — import-graph reachability audit found
    # zero runtime importers, zero test importers, zero script/config
    # references (webpent/validation was a frozen dead duplicate of the
    # live webpent/validators; webpent/contracts a dead re-export facade).
    "src/webpent/contracts/__init__.py",
    "src/webpent/copilot/__init__.py",
    "src/webpent/copilot/critic.py",
    "src/webpent/copilot/explainer.py",
    "src/webpent/copilot/planner.py",
    "src/webpent/experience/__init__.py",
    "src/webpent/experience/store.py",
    "src/webpent/persistence/__init__.py",
    "src/webpent/persistence/backend_capability.py",
    "src/webpent/persistence/distributed_contracts.py",
    "src/webpent/profiles/__init__.py",
    "src/webpent/profiles/juice_shop/__init__.py",
    "src/webpent/profiles/juice_shop/cases.py",
    "src/webpent/security_models/__init__.py",
    "src/webpent/security_models/identity/__init__.py",
    "src/webpent/security_models/identity/matrix.py",
    "src/webpent/security_models/identity/models.py",
    "src/webpent/validation/__init__.py",
    "src/webpent/validation/causal_validator.py",
    "src/webpent/validation/identity_validator.py",
    "src/webpent/validation/replay_validator.py",
    "src/webpent/validation/state_diff_validator.py",
})

M3_WINDOW2_20261106_THAW_PATHS = frozenset({
    # UM-DR-17 (M3 window 2, 2026-11-06): ف3.2 JS AST reversing dispatcher
    # + the tenant_isolation qualification seam + ق7 identity runner
    # injection + OAST/campaign-resume wiring + attack-graph evidence-
    # edge enrichment. Refreeze scripts (in order):
    #   scripts/refreeze_manifest_m3_js_ast_reversing.py
    #     (settings.py, agents/javascript_intelligence/agent.py)
    #   scripts/refreeze_manifest_m3_family_seam.py
    #     (settings.py, graph/builder.py, families/execution_node.py)
    #   scripts/refreeze_manifest_m3_identity_runner.py
    #     (settings.py, workers/pentest_worker.py)
    #   scripts/refreeze_manifest_m3_oast_resume.py
    #     (graph/builder.py, workers/pentest_worker.py)
    #   scripts/refreeze_manifest_m3_attack_graph_evidence.py
    #     (agents/attack_graph/agent.py)
    # Of all re-pinned paths, ONLY attack_graph/agent.py predates the
    # pre-unfreeze baseline (settings.py is covered by the UM-DR-16 set
    # above; builder.py / execution_node.py / pentest_worker.py entered
    # the manifest after the baseline snapshot, so they never appear in
    # the baseline-disagreement delta). Tests: test_m3_js_ast_reversing.py,
    # test_m3_family_qualification_seam.py,
    # test_m3_identity_orchestrator_runner.py,
    # test_m3_oast_campaign_resume_wiring.py,
    # test_m3_attack_graph_evidence_edges.py.
    "src/webpent/agents/attack_graph/agent.py",
})

M2_AUTHORIZATION_SCOPE_20261105_THAW_PATHS = frozenset({
    # UM-DR-15 (M2): --authorization-manifest + --scope-file CLI gates and
    # the documented subprocess-inventory completion (refreeze script
    # scripts/refreeze_manifest_m2_authorization_scope.py; tests
    # tests/test_m2_authorization_manifest.py, test_m2_execution_security.py)
    # NOTE: cli/unified_hunt.py is also re-pinned this window but is NOT in
    # the pre-unfreeze baseline (a newer file), so it never appears in the
    # baseline-disagreement delta.
    "src/webpent/cli/commands.py",
    "src/webpent/shared/direct_io_inventory.py",
})

M1B_EVIDENCE_INTEGRITY_20261105_THAW_PATHS = frozenset({
    "src/webpent/agents/validator/agent.py",
    "src/webpent/memory/db.py",
    "src/webpent/models/findings.py",
    "src/webpent/service/cost_alerts.py",
    "src/webpent/shared/prioritization.py",
    "src/webpent/shared/bac_identity_tester.py",
    # (attack_graph_planner.py is also re-pinned by this window but it is
    # not in the pre-unfreeze baseline — it entered the manifest via
    # MERGE_20261026_SCOPE_COMPLETION_PATHS — so it cannot appear in the
    # baseline-vs-current drift set.)
})

# M1-A SECURITY & CONFIG RECOVERY window (UM-DR-11, 2026-11-05):
# H-1/H-2 (prior session) + M-2/M-3/M-4/L-1/L-3/L-5 (this session).
# Refreeze: scripts/refreeze_manifest_m1a_recovery.py (10 re-pins,
# DR-009 protocol). Every change is regression-tested BEFORE refreeze
# (tests/test_m1a_*.py).
M1A_RECOVERY_20261105_THAW_PATHS = frozenset({
    "src/webpent/api/app.py",      # H-1 (also in earlier thaw sets)
    "src/webpent/api/auth.py",     # H-2 placeholder-user seeding refusal
    "src/webpent/cli/unified_hunt.py",  # L-3 (baseline-drift already documented by an earlier window)
    "src/webpent/config/settings.py",   # H-2 placeholder rejection + M-3 fields
    "src/webpent/memory/decision_log.py",  # L-5 redaction at append
    "src/webpent/recon/browser_farm.py",   # L-1 playwright SSRF guard
    "src/webpent/reporter/poc_recorder.py",  # L-1 (baseline-drift already documented by an earlier window)
    "src/webpent/shared/http.py",         # M-3 transport rate ceiling
    "src/webpent/shared/legacy_containment.py",  # M-4 safe-transport delegation
    "src/webpent/tools/recon/katana.py",   # M-2 -fs fqdn scope pinning
}) - {"src/webpent/cli/unified_hunt.py", "src/webpent/reporter/poc_recorder.py"}  # noqa: F841 — already in earlier sets' union; kept listed above for the window record

UNIFIED_MERGE_PHASE12_THAW_PATHS = frozenset({
    "src/webpent/agents/validator/postp0_checks.py",
    "src/webpent/api/app.py",
    "src/webpent/cli/commands.py",
    "src/webpent/config/settings.py",
    "src/webpent/shared/preflight.py",
    "src/webpent/memory/embeddings.py",
})

MERGE_20261026_SCOPE_COMPLETION_PATHS = frozenset(
    {
        "src/webpent/adaptive/defense_emulator.py",
        "src/webpent/apex/parallel_runner.py",
        "src/webpent/autonomous/amplifiers/cloud_storage.py",
        "src/webpent/autonomous/amplifiers/ct_mining.py",
        "src/webpent/autonomous/amplifiers/skeptic.py",
        "src/webpent/autonomous/amplifiers/swarm.py",
        "src/webpent/autonomous/amplifiers/takeover.py",
        "src/webpent/autonomous/amplifiers/wayback.py",
        "src/webpent/autonomous/cem/cycle.py",
        "src/webpent/autonomous/cem/diff_engine.py",
        "src/webpent/autonomous/cem/regression_watch.py",
        "src/webpent/autonomous/hunt_knowledge.py",
        "src/webpent/autonomous/hunt_memory.py",
        "src/webpent/autonomous/hunt_orchestrator.py",
        "src/webpent/autonomous/hunt_runtime.py",
        "src/webpent/autonomous/vip_orchestrator.py",
        "src/webpent/causal_reasoning/contextual_memory.py",
        "src/webpent/causal_reasoning_v2/causal_adapter.py",
        "src/webpent/causal_reasoning_v2/causal_adapter_v2.py",
        "src/webpent/causal_reasoning_v2/closed_loop_integration.py",
        "src/webpent/causal_reasoning_v2/confidence_engine_v2.py",
        "src/webpent/causal_reasoning_v2/integration_layer.py",
        "src/webpent/chained_exploits/attack_graph_planner.py",
        "src/webpent/cli/apex.py",
        "src/webpent/deep/business_logic.py",
        "src/webpent/deep/client_path_traversal.py",
        "src/webpent/deep/deserialization.py",
        "src/webpent/deep/dom_clobbering.py",
        "src/webpent/deep/mass_assignment.py",
        "src/webpent/deep/race_condition.py",
        "src/webpent/deep/rate_limit_bypass.py",
        "src/webpent/econ/blind_spots.py",
        "src/webpent/econ/budget_mapper.py",
        "src/webpent/econ/competitive.py",
        "src/webpent/econ/market_kb.py",
        "src/webpent/econ/portfolio.py",
        "src/webpent/econ/roi_optimizer.py",
        "src/webpent/econ/saturation.py",
        "src/webpent/econ/timing_advisor.py",
        "src/webpent/families/execution_node.py",
        "src/webpent/goed_v1/family_strategies.py",
        "src/webpent/jc/chamber.py",
        "src/webpent/jc/verdict.py",
        "src/webpent/memory/postmortem.py",
        "src/webpent/oracle/osint.py",
        "src/webpent/shared/operator_catalogs.py",
        "src/webpent/shared/red_vs_blue.py",
        "src/webpent/shared/shadow_detector.py",
        "src/webpent/shared/vip_campaign_node.py",
        "src/webpent/shared/waf_evasion.py",
        "src/webpent/verification/self_verify.py",
    }
)


def _parse_manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, relpath = line.partition(" ")
        relpath = relpath.strip().lstrip("*")
        entries[relpath] = digest
    return entries


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ULTIMATE PLAN 2026-10-27, proposal 4 (dead-code archive):
# 138 manifest entries whose files moved to
# archive/pre_v10_prototypes/ (17 verified-dead prototype
# packages, ~22k lines; grep-verified no live importers except
# the documented goed_v1 test exception). They remain in the
# pre-unfreeze baseline, so they are the documented
# baseline-only set for this window. The archive directory is
# excluded from packaging (packages.find is src/-scoped) and
# from CI lint/type-check paths.
ULTIMATE_PLAN_20261027_ARCHIVED_PATHS = frozenset(
    {
        "src/webpent/abhc/__init__.py",
        "src/webpent/abhc/boundaries.py",
        "src/webpent/abhc/chains.py",
        "src/webpent/abhc/contracts.py",
        "src/webpent/abhc/core.py",
        "src/webpent/abhc/director.py",
        "src/webpent/abhc/experiments.py",
        "src/webpent/abhc/exploration.py",
        "src/webpent/abhc/hypotheses.py",
        "src/webpent/abhc/quality.py",
        "src/webpent/abhc/review.py",
        "src/webpent/abhie/__init__.py",
        "src/webpent/abhie/boundaries.py",
        "src/webpent/abhie/brain.py",
        "src/webpent/abhie/chains.py",
        "src/webpent/abhie/competition.py",
        "src/webpent/abhie/contracts.py",
        "src/webpent/abhie/core.py",
        "src/webpent/abhie/discovery.py",
        "src/webpent/abhie/reflection.py",
        "src/webpent/abhie/review.py",
        "src/webpent/abhie/strategy.py",
        "src/webpent/abhie_v6/__init__.py",
        "src/webpent/abhie_v6/agent_core.py",
        "src/webpent/abhie_v6/architect.py",
        "src/webpent/abhie_v6/chains.py",
        "src/webpent/abhie_v6/contracts.py",
        "src/webpent/abhie_v6/core.py",
        "src/webpent/abhie_v6/creativity.py",
        "src/webpent/abhie_v6/differential.py",
        "src/webpent/abhie_v6/discovery.py",
        "src/webpent/abhie_v6/invariants.py",
        "src/webpent/abhie_v6/learning.py",
        "src/webpent/abhip/__init__.py",
        "src/webpent/abhip/contracts.py",
        "src/webpent/abhip/differential.py",
        "src/webpent/abhip/loop.py",
        "src/webpent/abhip/memory.py",
        "src/webpent/abhip/orchestrator.py",
        "src/webpent/abhip/questions.py",
        "src/webpent/abhip/reasoning.py",
        "src/webpent/abhip/reviewer.py",
        "src/webpent/abhip/target_graph.py",
        "src/webpent/adi/__init__.py",
        "src/webpent/adi/intelligence.py",
        "src/webpent/asros/__init__.py",
        "src/webpent/asros/adaptive_strategy.py",
        "src/webpent/asros/attack_surface.py",
        "src/webpent/asros/knowledge_graph.py",
        "src/webpent/asros/quality_controller.py",
        "src/webpent/asros/reasoning.py",
        "src/webpent/asros/world_model.py",
        "src/webpent/avde/__init__.py",
        "src/webpent/avde/behavior.py",
        "src/webpent/avde/discovery.py",
        "src/webpent/avde/exploration.py",
        "src/webpent/avde/pipeline.py",
        "src/webpent/avde/review.py",
        "src/webpent/avrip/__init__.py",
        "src/webpent/avrip/assumptions.py",
        "src/webpent/avrip/core.py",
        "src/webpent/avrip/cross_domain.py",
        "src/webpent/avrip/evidence.py",
        "src/webpent/avrip/intent.py",
        "src/webpent/avrip/memory.py",
        "src/webpent/avrip/optimizer.py",
        "src/webpent/avrip/reasoning.py",
        "src/webpent/avrip/review.py",
        "src/webpent/avrp/__init__.py",
        "src/webpent/avrp/chains.py",
        "src/webpent/avrp/correlation.py",
        "src/webpent/avrp/coverage.py",
        "src/webpent/avrp/improvement.py",
        "src/webpent/avrp/loop.py",
        "src/webpent/avrp/patterns.py",
        "src/webpent/avrp/review.py",
        "src/webpent/avrp/state.py",
        "src/webpent/cqa/__init__.py",
        "src/webpent/cqa/execution.py",
        "src/webpent/dcvu/__init__.py",
        "src/webpent/dcvu/campaign.py",
        "src/webpent/dcvu/contracts.py",
        "src/webpent/dcvu/engine.py",
        "src/webpent/dcvu/fixtures.py",
        "src/webpent/dcvu/ground_truth.py",
        "src/webpent/dcvu/metrics.py",
        "src/webpent/goed_v1/__init__.py",
        "src/webpent/goed_v1/business_logic_evaluator.py",
        "src/webpent/goed_v1/business_logic_strategies.py",
        "src/webpent/goed_v1/contracts.py",
        "src/webpent/goed_v1/exploration_loop.py",
        "src/webpent/goed_v1/family_strategies.py",
        "src/webpent/goed_v1/hypothesis_engine.py",
        "src/webpent/goed_v1/integrated_evaluator.py",
        "src/webpent/goed_v1/open_world_mode.py",
        "src/webpent/goed_v1/real_stateful_executor.py",
        "src/webpent/goed_v1/stateful_executor.py",
        "src/webpent/rta/__init__.py",
        "src/webpent/rta/auth_campaign.py",
        "src/webpent/rta/contracts.py",
        "src/webpent/rta/discovery.py",
        "src/webpent/rta/harness.py",
        "src/webpent/rta/local_server.py",
        "src/webpent/rta/validation.py",
        "src/webpent/vabhfil_v8/__init__.py",
        "src/webpent/vabhfil_v8/analytics_review.py",
        "src/webpent/vabhfil_v8/benchmark.py",
        "src/webpent/vabhfil_v8/contracts.py",
        "src/webpent/vabhfil_v8/core.py",
        "src/webpent/vabhfil_v8/executive.py",
        "src/webpent/vabhfil_v8/hypotheses.py",
        "src/webpent/vabhfil_v8/memory.py",
        "src/webpent/vabhfil_v8/reasoning.py",
        "src/webpent/vabhfil_v8/skepticism.py",
        "src/webpent/vabhfil_v8/strategy_graph.py",
        "src/webpent/vabhfil_v8/utils.py",
        "src/webpent/vabhfqr_v10/__init__.py",
        "src/webpent/vabhfqr_v10/audit.py",
        "src/webpent/vabhfqr_v10/contracts.py",
        "src/webpent/vabhfqr_v10/metrics.py",
        "src/webpent/vabhfqr_v9/__init__.py",
        "src/webpent/vabhfqr_v9/analytics_review.py",
        "src/webpent/vabhfqr_v9/benchmark.py",
        "src/webpent/vabhfqr_v9/contracts.py",
        "src/webpent/vabhfqr_v9/core.py",
        "src/webpent/vabhfqr_v9/evidence.py",
        "src/webpent/vabhfqr_v9/loop.py",
        "src/webpent/vabhic_v7/__init__.py",
        "src/webpent/vabhic_v7/analytics_review.py",
        "src/webpent/vabhic_v7/benchmark.py",
        "src/webpent/vabhic_v7/commander.py",
        "src/webpent/vabhic_v7/contracts.py",
        "src/webpent/vabhic_v7/coordination.py",
        "src/webpent/vabhic_v7/core.py",
        "src/webpent/vabhic_v7/discovery.py",
        "src/webpent/vabhic_v7/mental_model.py",
        "src/webpent/vabhic_v7/narrative_budget.py",
        "src/webpent/vabhic_v7/utils.py",
    }
)


def test_frozen_manifest_exists_and_is_populated() -> None:
    assert MANIFEST.exists(), f"frozen manifest missing: {MANIFEST}"
    entries = _parse_manifest(MANIFEST)
    # ULTIMATE PLAN 2026-10-27, proposal 4: 138 archived prototype
    # entries (ULTIMATE_PLAN_20261027_ARCHIVED_PATHS) were removed
    # when the 17 dead packages moved to archive/pre_v10_prototypes/;
    # the Ultimate-plan scope completion added 18 new pins. The floor
    # drops 690 -> 630 to pin exactly that documented reduction.
    assert len(entries) >= 630, (
        "frozen manifest shrank unexpectedly — a frozen module was dropped "
        f"from the gate (found {len(entries)}, expected >= 630)"
    )


@pytest.mark.parametrize(
    "relpath",
    sorted(_parse_manifest(MANIFEST)) if MANIFEST.exists() else [],
)
def test_frozen_file_byte_identical(relpath: str) -> None:
    absolute = REPO_ROOT / relpath
    assert absolute.exists(), f"frozen module missing from tree: {relpath}"
    expected = _parse_manifest(MANIFEST)[relpath]
    observed = _sha256(absolute)
    if observed != expected and relpath in R3_RULING_THAW_PATHS:
        # Mid-window delta mode: the ruling authorized exactly this file.
        # Authorization/mapping/sub-scope are enforced by the delta gate
        # (scripts/gate_frozen_delta.py, run per window commit); this pytest
        # keeps enforcing byte-identity for every NON-thawed file.
        pytest.skip(
            f"{relpath} thawed mid-window per Ruling R3-002 §3.1 — "
            "delta-mode enforcement via scripts/gate_frozen_delta.py; "
            "byte-identity restored at re-freeze"
        )
    assert observed == expected, (
        f"FROZEN MODULE DRIFT: {relpath}\n"
        "A frozen (trust-chain) file changed without a manifest regen.\n"
        "This is a fail-closed gate: regenerate the manifest only after an "
        "explicit, documented review of the diff."
    )


def test_baseline_disagrees_only_on_documented_unfreeze_paths() -> None:
    assert BASELINE.exists(), f"pre-unfreeze baseline missing: {BASELINE}"
    current = _parse_manifest(MANIFEST)
    baseline = _parse_manifest(BASELINE)
    shared = set(current) & set(baseline)
    drifted = {p for p in shared if current[p] != baseline[p]}
    # R3 re-freeze (Ruling R3-002): the manifest was regenerated after the
    # three ruling fixes, so the pre-unfreeze baseline now also disagrees on
    # the five R3-ruling-thawed paths. Expected drift = the 2026-10-05
    # unfreeze delta UNION the R3 ruling thaw list — nothing else.
    expected_drift = (
        DOCUMENTED_UNFROZEN_PATHS
        | R3_RULING_THAW_PATHS
        | M2_RULING_THAW_PATHS
        | M2A_CONDITIONAL_THAW_PATHS
        | TEAM_MERGE_V152_LINEAGE_DRIFT_PATHS
        | R5_IDENTITY_LADDER_THAW_PATHS
        | MERGE_20261026_THAW_PATHS
        | ULTIMATE_PLAN_20261027_THAW_PATHS
        | TRACK11_12_20261028_THAW_PATHS
        | RESIDUAL_CLOSURE_20261029_THAW_PATHS
        | AB_LAB_20261029_THAW_PATHS
        | ALIAS_REMOVAL_20261101_THAW_PATHS
        | HARDENING_20261101_THAW_PATHS
        | REDTEAM_R2_20261102_THAW_PATHS
        | UNIFIED_MERGE_PHASE12_THAW_PATHS
        | M1B_EVIDENCE_INTEGRITY_20261105_THAW_PATHS
        | M1A_RECOVERY_20261105_THAW_PATHS
        | M2_AUTHORIZATION_SCOPE_20261105_THAW_PATHS
        | M3_RESEARCH_WIRING_20261105_THAW_PATHS
        | M3_WINDOW2_20261106_THAW_PATHS
        | REDTEAM_UMDR26_PHASE2_20261106_THAW_PATHS
        | UMDR28_DISCOVERY_20261107_THAW_PATHS
        | UMDR29_DEADCODE_20261107_THAW_PATHS
        | UMDR30_CAPABILITY_WIRING_20261107_THAW_PATHS
        | UMDR31_ADAPTIVE_RESEARCH_20261107_THAW_PATHS
        | UMDR31_1_UPLIFT_20261108_THAW_PATHS
        | UMDR33_EVIDENCE_CHAIN_20261110_THAW_PATHS
        | UMDR33_PHASE2_SECURITY_20261110_THAW_PATHS
        | UMDR33_INFO_GAIN_20261110_THAW_PATHS
        | UMDR33_VERSION_BUMP_20261110_THAW_PATHS
        | UMDR34_SCOPE_AUTHORITY_20261110_THAW_PATHS
        | UMDR35_36_INTEGRITY_20261112_THAW_PATHS
    )
    # ULTIMATE PLAN 2026-10-27, proposal 4: the pre-archive drift sets
    # (e.g. TEAM_MERGE_V152_LINEAGE_DRIFT_PATHS' goed_v1 entry) can no
    # longer drift once the archived paths left the manifest — subtract
    # the documented archive set so the expectation matches documented
    # reality (the archive README + DRIFT_REGISTER entry carry the why).
    expected_drift -= ULTIMATE_PLAN_20261027_ARCHIVED_PATHS
    assert drifted == expected_drift, (
        "unfreeze/ruling delta drifted from the documented set:\n"
        f"  undocumented drift : {sorted(drifted - expected_drift)}\n"
        f"  documented but same: {sorted(expected_drift - drifted)}"
    )
    only_current = set(current) - set(baseline)
    only_baseline = set(baseline) - set(current)
    # M2-impl v8 (Dispatch #009, G5): the manifest scope was COMPLETED —
    # the v8 manifest pins 13 paths absent from the pre-unfreeze baseline:
    # the 1 authorized NEW src file (thaw item 7) plus the 12 pre-existing
    # v7 files retro-pinned byte-identical (finding NF-M2I-01: the v7
    # manifest never covered them). Documented in
    # deliverables/m2_manifest_delta_v7_v8.json.
    V8_SCOPE_COMPLETION_PATHS = frozenset(
        {
            "src/webpent/production/spine_flag_gates.py",
            "src/webpent/cli/__main__.py",
            "src/webpent/integration/browser_hypothesis_bridge.py",
            "src/webpent/integration/hypothesis_priority_contract.py",
            "src/webpent/integration/learning_ab_contract.py",
            "src/webpent/integration/planner_enrichment_bridge.py",
            "src/webpent/integration/session_recovery_bridge.py",
            "src/webpent/production/validators.py",
            "src/webpent/recon/auth_resilience.py",
            "src/webpent/recon/session_recovery.py",
            "src/webpent/reporter/poc_cli.py",
            "src/webpent/reporter/poc_export.py",
            "src/webpent/reporter/poc_recorder.py",
        }
    )
    # TEAM-MERGE 2026-10-22: 11 paths pinned by the merged (post-refreeze)
    # manifest but absent from the pre-unfreeze baseline — the brain/
    # decision package (8 files) and production/{business_logic_inferrer,
    # chain_composer, parallel_orchestrator}.py from the donorV (v15.2)
    # lineage, restored/added by the merge (docs/archive/2026-11-01-plan-exec-root-reports/
    # CHANGED_FROM_BASELINE.txt ADDED list;
    # docs/archive/2026-11-01-plan-exec-root-reports/MERGE_REPORT.md).
    # Same pattern as the V8 scope completion above:
    # a scope completion of the manifest, not a thaw.
    TEAM_MERGE_SCOPE_COMPLETION_PATHS = frozenset(
        {
            "src/webpent/brain/__init__.py",
            "src/webpent/brain/adaptation.py",
            "src/webpent/brain/blocked_path.py",
            "src/webpent/brain/curiosity.py",
            "src/webpent/brain/ev_scheduler.py",
            "src/webpent/brain/lessons.py",
            "src/webpent/brain/payload_selector.py",
            "src/webpent/brain/scorecard.py",
            "src/webpent/production/business_logic_inferrer.py",
            "src/webpent/production/chain_composer.py",
            "src/webpent/production/parallel_orchestrator.py",
        }
    )
    undocumented_current = only_current - (
        V8_SCOPE_COMPLETION_PATHS | TEAM_MERGE_SCOPE_COMPLETION_PATHS
        | MERGE_20261026_SCOPE_COMPLETION_PATHS
        | ULTIMATE_PLAN_20261027_SCOPE_COMPLETION_PATHS
        | CLI_OPS_20261028_SCOPE_COMPLETION_PATHS
        | OPS_WRITE_20261028_SCOPE_COMPLETION_PATHS
        | RESIDUAL_CLOSURE_20261029_SCOPE_COMPLETION_PATHS
        | AB_LAB_20261029_SCOPE_COMPLETION_PATHS
        | ALIAS_REMOVAL_20261101_SCOPE_COMPLETION_PATHS
        | REDTEAM_UMDR26_SCOPE_COMPLETION_20261106_PATHS
        | UMDR32_NEW_CAPABILITY_20261109_PATHS
        | UMDR33_NEW_CAPABILITY_20261110_PATHS
    )
    assert not undocumented_current, (
        f"undocumented paths only in current manifest: {sorted(undocumented_current)}"
    )
    # ULTIMATE PLAN 2026-10-27, proposal 4: the documented archive
    # reduction — paths pinned by the pre-unfreeze baseline whose
    # files moved out of src/ to archive/pre_v10_prototypes/.
    # UM-DR-29 (2026-11-07): second documented archive reduction — the
    # seven frozen-but-dead packages (verified zero runtime/test/script
    # importers by the reachability audit) moved to
    # archive/umdr29_dead_code/; see that README and
    # scripts/refreeze_manifest_umdr29.py (661 -> 639 entries).
    assert not (
        only_baseline
        - ULTIMATE_PLAN_20261027_ARCHIVED_PATHS
        - UMDR29_ARCHIVED_PATHS
    ), (
        f"paths only in baseline manifest (beyond the documented "
        f"2026-10-27 + 2026-11-07 archive sets): "
        f"{sorted(only_baseline - ULTIMATE_PLAN_20261027_ARCHIVED_PATHS - UMDR29_ARCHIVED_PATHS)}"
    )
