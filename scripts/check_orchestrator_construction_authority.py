#!/usr/bin/env python3
"""Sprint R1 FIX 1 — Static single-construction-authority checker.

Fails on any ``ModernOrchestrator(`` construction call outside the one
authoritative factory module, or outside the explicit test allowlist below.

Contract enforced:
  webpent.production.production_spine.resolve_production_spine() is the
  ONE place ModernOrchestrator may be constructed in production code. Any
  other literal occurrence of the substring ``ModernOrchestrator(`` in a
  ``.py`` file under this repo is either:
    (a) production_spine.py itself (the factory's own construction call), or
    (b) a file in TEST_ALLOWLIST below — existing unit tests that construct
        ModernOrchestrator directly to exercise it in isolation, relying on
        the explicit test-only escape hatch (see modern_spine.py
        _TEST_ESCAPE_ENV, set for the whole suite by tests/conftest.py).
  Anything else is a violation: either a new production bypass of the
  factory, or a new test that needs to be added to TEST_ALLOWLIST after
  deliberate review (not silently).

Reviews confirmed there are no dynamic (importlib/getattr/partial)
construction paths for ModernOrchestrator, so this literal-substring static
check is sufficient — no AST/bytecode analysis needed.

Usage:
  python scripts/check_orchestrator_construction_authority.py            # human-readable report
  python scripts/check_orchestrator_construction_authority.py --quiet    # CI: exit 1 on violation
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERN = "ModernOrchestrator("

# The factory module: the ONE approved production construction site.
FACTORY_FILE = ROOT / "src" / "webpent" / "production" / "production_spine.py"

# Approved test allowlist — existing unit tests that legitimately construct
# ModernOrchestrator directly (test-only escape hatch; see
# tests/conftest.py::_allow_direct_orchestrator_construction_in_tests).
# Adding a new file here requires deliberate review, not just running this
# script until it's quiet.
TEST_ALLOWLIST: frozenset[Path] = frozenset(
    ROOT / "tests" / "team1_acceptance" / name
    for name in (
        "test_a_modern_production_path.py",
        "test_avi_v1_1_real_target_qualification.py",
        "test_avi_v1_production_release.py",
        "test_closed_loop_research.py",
        "test_durable_research_state.py",
        "test_fabric_automatic_dispatch.py",
        "test_fabric_critical_fixes.py",
        "test_fabric_graph_wiring_final.py",
        "test_fabric_production_integration.py",
        "test_h_integrated_run.py",
        "test_half1_behavioral.py",
        "test_half2_production_dataflow.py",
        "test_hmac_proof_authority.py",
        "test_production_research_loop_activation.py",
        "test_production_runtime_closure.py",
        "test_teamt2_hostile_fixes.py",
        "test_validator_coverage_v1.py",
        "test_validator_execution_fabric_v2.py",
        "test_vulnerability_family_expansion.py",
        "test_vuln_arsenal_sprint_a.py",
        "test_sprint_i2_e2e_walking_skeleton.py",
        "test_sprint_i2_hotfix_regression.py",
        "test_sprint_i3_e2e_flow_vertical.py",
    )
) | {
    # Round 4 (Accountability Spine): tests/test_verdict_bridge.py constructs
    # ModernOrchestrator with the conftest test escape to drive the real
    # dispatch path end-to-end and assert the verdict bridge gate is recorded
    # in the campaign result. Reviewed as part of the Round-4 wiring; the
    # test targets a loopback URL and sets no production-side state.
    ROOT / "tests" / "test_verdict_bridge.py",
    # Wave 3 (CAMPAIGN integration, docs/reviews/round7_campaign_wave3_seal_update.md):
    # tests/test_campaign_wiring.py constructs ModernOrchestrator directly
    # (test-only escape, loopback URL) to drive run_autonomous_validation_campaign
    # end-to-end and assert the campaign bridge block (brief PENDING for the
    # operator, approved-plan advisory surface) is carried on the dispatch
    # result and the "campaign_advisory_plan" trace stage is recorded. Reviewed
    # as part of the Wave-3 wiring; the escape is the AVI class's run_campaign,
    # the store is tmp_path via WEBPENT_CAMPAIGN_STORE, and no production-side
    # state is set.
    ROOT / "tests" / "test_campaign_wiring.py",
    # This gate's own regression test: intentionally constructs
    # ModernOrchestrator directly (with the test escape unset) to prove the
    # runtime guard actually raises. Reviewed alongside this script, not a
    # drive-by addition.
    ROOT / "tests" / "test_orchestrator_construction_authority.py",
    # Sprint I-1b, item 1.1 (this gate's first-ever CI wiring surfaced this
    # PRE-EXISTING, previously-unenforced violation): scripts/team2_common.py
    # is an archived TEAM-2 independent-validation harness for a past sprint
    # (AVI V1.2 post-closure validation) -- NOT live production code, NOT a
    # currently-collected test. Its own docstring declares "NO source
    # modification" as a founding rule of that validation exercise, and it
    # hardcodes an absolute path to a different machine
    # (/home/z/my-project/avi_v12/webpent-goed) that does not exist in this
    # or any other current environment -- it cannot actually run here or in
    # CI regardless of this gate. Direct ModernOrchestrator construction was
    # the DELIBERATE POINT of that validation (re-deriving evidence via a
    # path independent of production's own resolve_production_spine()
    # wiring, as a cross-check) -- rewiring it now would mean editing a file
    # whose entire premise was "no source modification," to fix something
    # that isn't live. Allowlisted here rather than either silently ignored
    # or destructively "fixed."
    ROOT / "scripts" / "team2_common.py",
    # 0.33.0 hardening window (docs/PRODUCTION_HARDENING_PLAN_0330.md, P1-13):
    # tests/test_hardening_0330_b3.py constructs ModernOrchestrator directly
    # (test-only escape, engagement_id fixture, no scope law) to pin the new
    # graceful `research_step_bounded` contract: a decision-limit exhaustion
    # must degrade to a bounded stop on the engine loop instead of detonating
    # the enclosing phase, while the direct-call RuntimeError contract stays
    # frozen by the team1 behavioral test. Reviewed as part of the 0.33.0
    # window; no production-side state is set.
    ROOT / "tests" / "test_hardening_0330_b3.py",
}

# This checker script itself necessarily contains the literal pattern text
# (in its docstring, PATTERN constant, and report strings) — it is not a
# construction site and must not be scanned.
SELF_FILE = Path(__file__).resolve()

# Directories never scanned: VCS metadata, virtualenvs, build artifacts, and
# vendored/legacy trees that are not part of this sprint's scope.
EXCLUDED_DIR_NAMES = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".mypy_cache", ".pytest_cache", "build", "dist",
}


def find_violations() -> list[tuple[Path, int, str]]:
    """Return (file, line_number, line_text) for every disallowed occurrence."""
    violations: list[tuple[Path, int, str]] = []
    for path in ROOT.rglob("*.py"):
        if any(part in EXCLUDED_DIR_NAMES for part in path.parts):
            continue
        if path == FACTORY_FILE or path in TEST_ALLOWLIST or path == SELF_FILE:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if PATTERN not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if PATTERN in line:
                violations.append((path, lineno, line.strip()))
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="CI mode: no output on success, exit 1 on violation")
    args = parser.parse_args()

    violations = find_violations()

    if not violations:
        if not args.quiet:
            print("OK: 'ModernOrchestrator(' appears only in "
                  f"{FACTORY_FILE.relative_to(ROOT)} and the approved test allowlist "
                  f"({len(TEST_ALLOWLIST)} files).")
        return 0

    print(f"FAIL: {len(violations)} disallowed 'ModernOrchestrator(' construction "
          f"site(s) found outside {FACTORY_FILE.relative_to(ROOT)} and the test allowlist:",
          file=sys.stderr)
    for path, lineno, line in violations:
        print(f"  {path.relative_to(ROOT)}:{lineno}: {line}", file=sys.stderr)
    print(
        "\nRoute production callers through "
        "webpent.production.production_spine.resolve_production_spine(). "
        "If this is a genuinely new test that needs direct construction, add it "
        "to TEST_ALLOWLIST in this script after review — do not weaken the check.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
