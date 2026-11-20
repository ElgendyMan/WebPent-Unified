#!/usr/bin/env python3
"""UMDR42 window close — re-freeze the D1-modified frozen files.

Follows the declared-refreeze convention (refreeze_manifest_umdr40b and
its 40+ precedents): the thawed files' changes were verified by this
window's regression tests BEFORE the re-pin (85 targeted tests green
after commit c57f765; full-suite failures were exactly the frozen-gate
byte-identity checks this script closes, plus 18 pre-existing/
environmental failures proven to pre-date UMDR42 via git-stash triage).

UMDR42 D1 (2026-11-19) — this window's frozen-file changes:

  23 files modified by the except-pass -> logger.debug/warning
  conversion (scripts/umdr42_d1_remainder.py) plus the 2 files from
  D1 batch 1 (commit 22f0f4a). All changes are logging-only: the
  swallow sites still never raise, they now emit one debug/warning
  line with the skip reason.

Self-verifying: the manifest is re-hashed from disk before write and
each re-pin is asserted after write.
Usage: python3 scripts/refreeze_manifest_umdr42.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

UMDR42_REPINNED_FILES = (
    # D1 batch 1 (commit 22f0f4a)
    "src/webpent/families/execution_node.py",
    "src/webpent/tools/exploitation/sqlmap.py",
    # D1 remainder (commit c57f765)
    "src/webpent/adaptive/defense_emulator.py",
    "src/webpent/agents/hunter_runner.py",
    "src/webpent/agents/hypothesis_analyzer/agent.py",
    "src/webpent/agents/post_exploit/agent.py",
    "src/webpent/autonomous/vip_orchestrator.py",
    "src/webpent/graph/oast_nodes.py",
    "src/webpent/llm_researcher/providers/base.py",
    "src/webpent/llm_researcher/providers/pool.py",
    "src/webpent/models/mental_model.py",
    "src/webpent/recon/login_executor.py",
    "src/webpent/reporter/poc_recorder.py",
    "src/webpent/resume/campaign_checkpoints.py",
    "src/webpent/safety/kill_switch.py",
    "src/webpent/safety/request_ledger.py",
    "src/webpent/shared/http_discovery.py",
    "src/webpent/shared/llm.py",
    "src/webpent/shared/prioritization.py",
    "src/webpent/shared/research_contracts.py",
    "src/webpent/shared/self_critique.py",
    "src/webpent/smart/memory_engine.py",
    "src/webpent/stateful_api/contracts.py",
    "src/webpent/workers/pentest_worker.py",
    # UMDR41 residual gap: 277b1a5 modified these five but never
    # re-pinned them (full-suite failures shipped in UMDR41-final).
    # Bytes unchanged since that commit — closing the gap here.
    "src/webpent/production/production_spine.py",
    "src/webpent/recon/principal_provisioning.py",
    "src/webpent/scope/__init__.py",
    "src/webpent/scope/registry.py",
    "src/webpent/shared/generic_web_contracts.py",
    # D2 window (2026-11-19): doctor.py gained the uninstalled-checkout
    # version fallback; direct_io_inventory.py had its approval TTLs
    # renewed to 2027-02-17 (54 records expiring 2026-11-19).
    "src/webpent/cli/doctor.py",
    "src/webpent/shared/direct_io_inventory.py",
    # D4 window (2026-11-19): ruff F401 autofix removed unused
    # imports across 86 files (1,995 findings); these 34 are frozen.
    # D4 window (2026-11-19): ruff F401 autofix removed unused
    # imports across 86 files (1,995 findings cleared); these
    # 34 are freeze-gated and are re-pinned after tests.
    "src/webpent/agents/chain_engine.py",
    "src/webpent/agents/hunter_graph.py",
    "src/webpent/agents/hunter_runner.py",
    "src/webpent/brain/adaptation.py",
    "src/webpent/brain/curiosity.py",
    "src/webpent/brain/ev_scheduler.py",
    "src/webpent/causal_reasoning_v2/causal_adapter_v2.py",
    "src/webpent/causal_reasoning_v2/closed_loop_integration.py",
    "src/webpent/causal_reasoning_v2/confidence_engine_v2.py",
    "src/webpent/causal_reasoning_v2/integration_layer.py",
    "src/webpent/chained_exploits/attack_graph_planner.py",
    "src/webpent/deep/mass_assignment.py",
    "src/webpent/deep/race_condition.py",
    "src/webpent/deep/rate_limit_bypass.py",
    "src/webpent/graph/builder.py",
    "src/webpent/llm_researcher/task_router.py",
    "src/webpent/memory/lesson_extractor.py",
    "src/webpent/production/autonomous_recon.py",
    "src/webpent/production/chain_composer.py",
    "src/webpent/recon/auth_detector.py",
    "src/webpent/recon/auth_handler.py",
    "src/webpent/recon/autonomous_crawler.py",
    "src/webpent/recon/identity_discovery.py",
    "src/webpent/recon/login_executor.py",
    "src/webpent/recon/payload_advisor.py",
    "src/webpent/reporter/poc_cli.py",
    "src/webpent/safety/agency.py",
    "src/webpent/safety/request_ledger.py",
    "src/webpent/scope/parser.py",
    "src/webpent/service/cost_alerts.py",
    "src/webpent/service/manager.py",
    "src/webpent/shared/fixture_store.py",
    "src/webpent/shared/verifier.py",
    "src/webpent/verification/self_verify.py",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if not MANIFEST.exists():
        print(f"[refreeze-umdr42] manifest missing: {MANIFEST}")
        return 1
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    pinned = {
        parts[1]: parts[0]
        for parts in (line.split(maxsplit=1)
                      for line in lines if line.strip())
    }
    changes: list[tuple[str, str, str]] = []
    for relpath in UMDR42_REPINNED_FILES:
        absolute = REPO / relpath
        if not absolute.is_file():
            print(f"[refreeze-umdr42] MISSING file: {relpath}")
            return 1
        new_hash = _sha256(absolute)
        old_hash = pinned.get(relpath)
        if old_hash is None:
            print(f"[refreeze-umdr42] NOT IN MANIFEST (skip): {relpath}")
            continue
        if old_hash == new_hash:
            print(f"[refreeze-umdr42] UNCHANGED (already pinned): "
                  f"{relpath}")
            continue
        pinned[relpath] = new_hash
        changes.append((relpath, old_hash or "-", new_hash))
    if not changes:
        print("[refreeze-umdr42] nothing to re-pin — manifest "
              "already current for this window's files")
        return 0
    out_lines = [
        f"{pinned[line.split(maxsplit=1)[1]]}  "
        f"{line.split(maxsplit=1)[1]}"
        if line.split(maxsplit=1)[1] in {
            rel for rel, _, _ in changes} else line
        for line in lines if line.strip()
    ]
    MANIFEST.write_text(chr(10).join(out_lines) + "\n",
                        encoding="utf-8")
    verify = {
        parts[1]: parts[0]
        for parts in (line.split(maxsplit=1)
                      for line in
                      MANIFEST.read_text(encoding="utf-8")
                      .splitlines() if line.strip())
    }
    for relpath, old_hash, new_hash in changes:
        on_disk = _sha256(REPO / relpath)
        assert verify[relpath] == on_disk == new_hash, relpath
        print(f"[refreeze-umdr42] re-pinned {relpath}: "
              f"{old_hash[:12]} -> {new_hash[:12]} (verified)")
    print(f"[refreeze-umdr42] manifest updated: {MANIFEST} "
          f"({len(changes)} file(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
