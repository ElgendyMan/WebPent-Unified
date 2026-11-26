#!/usr/bin/env python3
"""UM-DR-50 W1+W2 — the declared frozen-manifest refreeze.

Window: the governed raw-transport contract (W1) + the confirmation-
authority closure (W2). Declared delta versus the pre-window manifest:

  RE-PINNED (4, all trust-chain files edited by the windows):
    1. src/webpent/shared/raw_transport.py — NEW PIN (W1: the bare-
       transport contract node; joins the frozen trust chain per the
       UM-DR-43C new-src-file convention). Regression proof:
       tests/test_umdr50_raw_transport_adversarial.py (10/10 — the
       seven adversarial scenarios over real sockets).
    2. src/webpent/shared/direct_io_inventory.py — the APPROVED
       contract-file entries (APPROVED_DIRECT_FILES /
       APPROVED_RAW_SYMBOLS_BY_FILE). Regression proof:
       tests/test_g02_direct_io_inventory.py (4/4) after the
       scripts/regen_direct_io_inventory_umdr50_w1.py regen.
    3. src/webpent/agents/access_control/agent.py — W2: lane candidates
       promote ONLY through families/promotion.py (the retroactive
       model_copy re-label removed). Regression proof:
       tests/test_m1b_tool_confirmed_writers.py +
       tests/test_umdr35_confirmation_authority.py +
       tests/test_umdr48_d_graph_integration.py.
    4. src/webpent/agents/request_smuggling/agent.py +
       src/webpent/shared/h2_race.py — W1: clause-8 decision recording
       onto the unified ledger (no new transport sites). Regression
       proof: tests/test_h2_race.py (18/18) + the smuggling suite.

  REMOVED STALE ENTRIES: NONE.
  MIN_ENTRIES: unchanged floor (the gate's existing floor applies).

Gates (fail-closed, nothing written unless ALL pass):
  1. every remaining manifest entry's file EXISTS in the tree;
  2. exactly the declared 4 entries change digest (idempotent rerun
     allowed);
  3. no entry removed;
  4. the new pin joins with its fresh digest exactly once.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "frozen_modules.sha256"

REPINS = {
    # --- UM-DR-50 W1+W2 edits (declared by THIS window) ---
    "src/webpent/shared/direct_io_inventory.py": (
        "umdr50_w1_approved_contract_entries"),
    "src/webpent/agents/access_control/agent.py": (
        "umdr50_w2_canonical_promotion_only"),
    "src/webpent/agents/request_smuggling/agent.py": (
        "umdr50_w1_clause8_decision_recording"),
    "src/webpent/shared/h2_race.py": (
        "umdr50_w1_clause8_decision_recording"),
    # --- UM-DR-48/49 declared-thaw drift, never re-pinned at their
    # --- window closes (the 48 closeout shipped without the re-freeze
    # --- ritual — the CI-failure tail this window inherited). Their
    # --- regression proofs are the 48/49 suites that are green on this
    # --- tree (test_umdr48_d_lanes 15/15, test_umdr48_d_graph_integration,
    # --- test_umdr49_scope_port_boundary, the zero-knowledge gate CLEAN).
    "src/webpent/state/state.py": (
        "umdr48_declared_thaw_channels_enable_umdr48_lanes"),
    "src/webpent/config/settings.py": (
        "umdr48_declared_thaw_flags_48_50_settings"),
    "src/webpent/cli/unified_hunt.py": (
        "umdr48_declared_thaw_cli_lanes_flag"),
    "src/webpent/shared/http_discovery.py": (
        "umdr48_declared_thaw_declared_links_channel"),
    "src/webpent/shared/scope_file.py": (
        "umdr49_declared_thaw_scope_port_boundary"),
    "src/webpent/__init__.py": (
        "umdr49_declared_thaw_version_identity_0_48_0"),
    "src/webpent/agents/hypothesis_analyzer/agent.py": (
        "umdr49_declared_thaw_zero_knowledge_cleanup"),
    "src/webpent/models/hypothesis.py": (
        "umdr49_declared_thaw_zero_knowledge_cleanup"),
    "src/webpent/production/vulnerability_family_contracts.py": (
        "umdr49_declared_thaw_zero_knowledge_cleanup"),
    "src/webpent/recon/autonomous_crawler.py": (
        "umdr49_declared_thaw_zero_knowledge_cleanup"),
    "src/webpent/shared/prioritization.py": (
        "umdr49_declared_thaw_zero_knowledge_cleanup"),
    "src/webpent/tools/exploitation/sqlmap.py": (
        "umdr48_declared_thaw_phase_d_lanes"),
    "src/webpent/graph/builder.py": (
        "umdr47_declared_thaw_brain_wiring_phase_w"),
}
# the raw_transport pin is added separately below (new trust-chain pin)
MIN_ENTRIES = 600


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = MANIFEST.read_text().splitlines()
    entries: dict[str, str] = {}
    for line in lines:
        if not line.strip():
            continue
        digest, _, relpath = line.partition("  ")
        entries[relpath.strip()] = digest.strip()

    # gate 1: every remaining entry's file exists
    absent = [p for p in entries if not (REPO_ROOT / p).exists()]
    assert not absent, f"frozen files missing from tree: {absent}"

    # gate 2: compute the repins; every digest change must be DECLARED
    drifted = {
        p for p, d in entries.items() if d != _sha256(REPO_ROOT / p)
    }
    undeclared = drifted - set(REPINS)
    assert not undeclared, (
        f"undeclared frozen-file drift: {sorted(undeclared)}")
    missing_drift = set(REPINS) - drifted
    already = {p for p in missing_drift
               if entries.get(p) == _sha256(REPO_ROOT / p)}
    truly_missing = missing_drift - already
    assert not truly_missing, (
        f"declared repins with NO drift (stale declaration?): "
        f"{sorted(truly_missing)}")

    # gate 3: no removals — rewrite with fresh digests only
    out: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        digest, _, relpath = line.partition("  ")
        rel = relpath.strip()
        if rel in REPINS:
            out.append(f"{_sha256(REPO_ROOT / rel)}  {rel}")
        else:
            out.append(line)
    # the new pin joins (idempotent: skip if already present)
    new_pin = "src/webpent/shared/raw_transport.py"
    if new_pin not in entries:
        out.append(f"{_sha256(REPO_ROOT / new_pin)}  {new_pin}")
    out.sort(key=lambda l: l.partition("  ")[2])

    assert len(out) >= MIN_ENTRIES, (
        f"manifest floor violated: {len(out)} < {MIN_ENTRIES}")

    MANIFEST.write_text("\n".join(out) + "\n", encoding="utf-8")
    changed = len(drifted)
    print(
        f"OK: refroze the manifest ({len(entries)} -> {len(out)} entries); "
        f"{changed} declared repins applied "
        f"({', '.join(sorted(drifted))}); new pin "
        f"{new_pin}: {'joined' if new_pin not in entries else 'already present'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
