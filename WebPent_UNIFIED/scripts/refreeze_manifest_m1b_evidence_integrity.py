#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the M1-B EVIDENCE INTEGRITY window
(2026-11-05) per the DR-009 protocol. DRIFT_REGISTER entry: UM-DR-10.

  * the window declares EXACTLY these frozen-tree changes (all M1-B,
    every one an evidence-integrity fix verified by new regression
    tests — see M1_READINESS_REVIEW.md §1.3/§4 and the M1-B commits):

      - src/webpent/agents/validator/agent.py
        (H-3/1.3d + §6.2/§6.3: LLM supervisor ADVISORY-ONLY in every
        promotion decision; dead llm_confirmed co-gate term removed from
        the sqli reauth gate; causal_signal deterministic-only;
        E-1: tool_confirmed_by provenance)

      - src/webpent/models/findings.py
        (E-1: model-level proof requirement for confidence_level=
        "Tool-Confirmed" — evidence_bundle OR naming the confirming gate)

      - src/webpent/memory/db.py
        (E-1: mark_oob_confirmed stamps oob provenance into evidence;
        _row_to_finding loads unproven pre-M1 Tool-Confirmed rows
        FAIL-CLOSED as Needs Human Review)

      - src/webpent/service/cost_alerts.py
        (E-1: lifecycle notification objects no longer stamped
        Tool-Confirmed — Pending + evidence.lifecycle_status)

      - src/webpent/shared/prioritization.py
        (E-2: dead IDOR entry removed from
        _DETERMINISTIC_STRUCTURAL_CLASSES — exclusion now lives in the
        set itself, not in statement order)

      - src/webpent/shared/bac_identity_tester.py
        (E-1: explicit tool_confirmed_by provenance on the identity
        differential confirmation gate)

      - src/webpent/chained_exploits/attack_graph_planner.py
        (H-3/1.3b: control_replay passthrough to the hardened
        exploit_chain validator)

  * NO manifest-path removals;
  * NO scope completions (new test files are outside the frozen gate by
    construction);
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_m1b_evidence_integrity.py
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
    "src/webpent/agents/validator/agent.py",
    "src/webpent/models/findings.py",
    "src/webpent/memory/db.py",
    "src/webpent/service/cost_alerts.py",
    "src/webpent/shared/prioritization.py",
    "src/webpent/shared/bac_identity_tester.py",
    "src/webpent/chained_exploits/attack_graph_planner.py",
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
