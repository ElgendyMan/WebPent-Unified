#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the M1b CONTRACTS & MODELS
window AND the M1-C/M1-D CAPABILITY WIRING & LEGACY DISPOSITION
window (both 2026-11-05) per the DR-009 protocol.
DRIFT_REGISTER entries: UM-DR-11 (retroactive M1-A), UM-DR-12
(M1-C + M1-D) and UM-DR-13 (M1b).

M1b change (verified by tests/test_m1b_domain_contracts.py BEFORE
refreeze):

  - src/webpent/state/unified_state.py
    (state-consistency fix: removed the five plain re-declarations
    that shadowed PentestState Annotated channels - surface_metrics,
    lesson_priority_adjustments, consulted_lessons,
    extracted_lessons, detector_results - restoring
    merge_lists/merge_dicts semantics in unified runs; the channels
    are declared ONCE on the parent)

Original M1-C/M1-D header follows.
LEGACY DISPOSITION window (2026-11-05) per the DR-009 protocol.
DRIFT_REGISTER entries: UM-DR-11 (retroactive M1-A documentation) and
UM-DR-12 (this window).

  * the window declares EXACTLY these frozen-tree changes (all M1-C,
    each verified by new regression tests run BEFORE this refreeze):

      - src/webpent/config/settings.py
        (M1-C flag declarations: enable_oast + the OAST settings contract
        (oast_domain / oast_poll_endpoint / oast_collector_bind_host /
        oast_collector_bind_port / oast_dns_listen_port),
        enable_causal_chain_candidates, enable_campaign_resume — all
        fail-closed defaults; M1_READINESS_REVIEW §5.5)

      - src/webpent/shared/http.py
        (M1-C loopback-trusted-endpoint exemption: context-scoped,
        LOOPBACK-ONLY, default-off; fixes the M-5 regression that vetoed
        the documented loopback OOB collector/receiver rule — 4 live OAST
        test failures; tests test_m1c_loopback_trusted_endpoint.py)

      - src/webpent/agents/validator/agent.py
        (M1-C Proposal 2 Phase 1: causal-chain-candidate wiring behind
        enable_causal_chain_candidates — ADVISORY-only, structurally
        absent when off, fail-soft; tests test_causal_chain_candidates.py)

      - src/webpent/cli/commands.py
        (M1-C §5.5 CLI surfaces: webpent bounty (ق10 preview-only) and
        webpent portfolio (ق11 wave-ordering-only) sub-apps; tests
        test_m1c_cli_surfaces.py)

  * NO manifest-path removals (the M1-D deletions — 5 verified-duplicated
    .orig files and the superseded api/live_stream.py — were all OUTSIDE
    the frozen manifest by construction);
  * NO scope completions (new modules cli/bounty.py, cli/portfolio.py are
    new files outside the frozen gate);
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_m1c_m1d_wiring_disposition.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

WINDOW_REMOVED_FILES: list[str] = []
WINDOW_SCOPE_COMPLETION: list[str] = []

# Run AFTER the edits — hashes re-read from the current tree.
WINDOW_CHANGED_FILES = [
    # The four M1-C/D files were re-pinned by the UM-DR-12 refreeze
    # (scripts/refreeze_manifest_m1c_m1d_wiring_disposition.py) and no
    # longer drift; THIS window re-pins exactly the M1b file.
    "src/webpent/state/unified_state.py",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            print(f"ABORT: unparsable manifest line: {line!r}", file=sys.stderr)
            return 1
        digest, relpath = parts[0], parts[1].strip()
        entries.append((digest, relpath))
        seen.add(relpath)

    for relpath in WINDOW_REMOVED_FILES:
        if relpath not in seen:
            print(f"ABORT: declared removed file is not pinned: {relpath}", file=sys.stderr)
            return 1
        if (REPO / relpath).exists():
            print(f"ABORT: declared removed file still exists in the tree: {relpath}", file=sys.stderr)
            return 1
        entries = [(d, p) for d, p in entries if p != relpath]
        seen.discard(relpath)
        print(f"  {relpath} (removed)")

    for relpath in WINDOW_CHANGED_FILES:
        if relpath not in seen:
            print(f"ABORT: declared changed file is not pinned: {relpath}", file=sys.stderr)
            return 1

    for relpath in WINDOW_SCOPE_COMPLETION:
        if relpath in seen:
            continue
        if not (REPO / relpath).is_file():
            print(f"ABORT: scope-completion file missing from tree: {relpath}", file=sys.stderr)
            return 1
        entries.append(("NEW", relpath))
        seen.add(relpath)

    out_lines: list[str] = []
    changed_count = 0
    for digest, relpath in entries:
        absolute = REPO / relpath
        if not absolute.is_file():
            print(f"ABORT: pinned path missing from tree: {relpath}", file=sys.stderr)
            return 1
        current = sha256(absolute)
        if current != digest:
            if relpath not in WINDOW_CHANGED_FILES:
                print(
                    f"ABORT: UNDECLARED drift on pinned file {relpath} "
                    "(this window's protocol covers only the files listed "
                    "in WINDOW_CHANGED_FILES)",
                    file=sys.stderr,
                )
                return 1
            changed_count += 1
            out_lines.append(f"{current}  {relpath}")
            print(f"  re-pinned {relpath}")
        else:
            out_lines.append(f"{digest}  {relpath}")

    unexpected = changed_count != len(WINDOW_CHANGED_FILES)
    if unexpected:
        print(
            f"ABORT: expected to re-pin exactly {len(WINDOW_CHANGED_FILES)} "
            f"file(s), re-pinned {changed_count}",
            file=sys.stderr,
        )
        return 1

    MANIFEST.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    total = len(out_lines)

    # Self-check: re-read and re-verify every entry after write.
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, relpath = line.split(None, 1)
        if sha256(REPO / relpath.strip()) != digest:
            print(f"ABORT: post-write self-check failed for {relpath}", file=sys.stderr)
            return 1

    print(
        f"OK: re-pinned {changed_count} file(s); manifest now pins "
        f"{total} file(s); post-write self-check passed."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
