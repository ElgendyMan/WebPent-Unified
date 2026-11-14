#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the UM-DR-25 red-team window
(2026-11-06) per the DR-009 protocol. DRIFT_REGISTER entry: UM-DR-25.

The window declares EXACTLY these frozen-tree changes (each verified by
the recovered/regenerated test suites BEFORE this refreeze — the red
baseline was 310 failures + 19 errors; every family touched below is
green post-fix):

  - src/webpent/config/settings.py
    (UM-DR-25: 33 subsystem flag-gate reads and 20 bounded-knob reads
    referenced get_settings().X fields that were never declared — every
    gate read raised AttributeError and the subsystems were dead on
    arrival (~250 test failures). Declared with fail-closed defaults;
    consumer-validated knobs deliberately carry no pydantic bounds so
    the typed refusal stays observable at the call site.)
  - src/webpent/memory/db.py
    (UM-DR-25: DatabaseOOBStore's five-method contract implemented —
    register_oob_binding / get_oob_binding / record_oob_callback /
    get_oob_callbacks_for_token / prune_oob_callbacks — plus the two
    always-bootstrap OOB tables outside Alembic, following the
    finding_status_history pattern. 45 OOB tests green.)
  - src/webpent/production/validators.py
    (UM-DR-25: the blind OOB family (oob_validator.py) and the
    privilege-differential family (privilege_validator.py) registered
    into the canonical VALIDATORS dispatch — merged with validators
    implemented and tested but never registered, so every
    run_validator('BLIND_*'/'PRIVILEGE_DIFFERENTIAL') raised
    ValidatorError on arrival. Lazy import guards the circular edge.)
  - src/webpent/models/findings.py
    (UM-DR-25: VulnClass members BLIND_SSRF / XXE_OOB / BLIND_SQLI /
    PRIVILEGE_DIFFERENTIAL — outside EXPLOITABLE_CLASSES by the
    callback-differential/structural posture; remediation tables
    extended for all four.)
  - src/webpent/production/chain_composer.py
    (UM-DR-25: the third deterministic chain type
    (CHAIN_TYPE_IDOR_MASS_ASSIGNMENT) and the declarative
    ChainTypeSpec registration seam — tests shipped with the full
    contract but the rules were never merged; 17 dead tests recovered,
    44/44 green including the v1 exfiltration suite.)
  - src/webpent/agents/payload_generator/agent.py
    (UM-DR-25: attach_oob_probes wired flag-gated at the node tail —
    merged with contract + tests but never called; flag-off is
    byte-identical.)
  - src/webpent/workers/pentest_worker.py
    (UM-DR-25: flag-gated session-pool fleet snapshot in the worker
    status return; the gate precedes every snapshot use and the import
    is lazy — flag-off carries no sessions key.)
  - src/webpent/api/workers_status.py
    (UM-DR-25: the operator visibility gate
    (enable_worker_status_endpoint, default False -> 404) on both
    router routes, layered WITH the F-05 viewer auth.)
  - src/webpent/shared/http.py
    (UM-DR-25: three broad handlers narrowed to typed exceptions per
    the P-1 critical-module hygiene contract — the loopback-flag
    ContextVar resets, the settings load, and the rate-governor
    fail-OPEN seam.)
  - src/webpent/agents/validator/agent.py
    (UM-DR-25: the causal-chain seam's three broad handlers narrowed
    to typed exceptions per the same P-1 contract.)

  * NO manifest-path removals; NO scope completions;
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_umdr25_redteam.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

WINDOW_REMOVED_FILES: list[str] = []
WINDOW_SCOPE_COMPLETION: list[str] = []

WINDOW_CHANGED_FILES = [
    "src/webpent/config/settings.py",
    "src/webpent/memory/db.py",
    "src/webpent/production/validators.py",
    "src/webpent/models/findings.py",
    "src/webpent/production/chain_composer.py",
    "src/webpent/agents/payload_generator/agent.py",
    "src/webpent/workers/pentest_worker.py",
    "src/webpent/api/workers_status.py",
    "src/webpent/shared/http.py",
    "src/webpent/agents/validator/agent.py",
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
        new_digest = sha256(absolute)
        if new_digest != digest:
            if relpath not in WINDOW_CHANGED_FILES and relpath not in WINDOW_SCOPE_COMPLETION:
                print(
                    f"ABORT: undeclared change detected in pinned file: {relpath}",
                    file=sys.stderr,
                )
                return 1
            changed_count += 1
            print(f"  re-pinned: {relpath}")
        out_lines.append(f"{new_digest}  {relpath}")

    if changed_count != len(WINDOW_CHANGED_FILES):
        print(
            f"ABORT: expected exactly {len(WINDOW_CHANGED_FILES)} re-pinned "
            f"entries, found {changed_count}",
            file=sys.stderr,
        )
        return 1
    if len(out_lines) != len(entries):
        print("ABORT: output line count mismatch", file=sys.stderr)
        return 1

    MANIFEST.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    verification_failures: list[str] = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, relpath = line.split(None, 1)
        absolute = REPO / relpath.strip()
        if not absolute.is_file() or sha256(absolute) != digest:
            verification_failures.append(relpath.strip())
    if verification_failures:
        print(
            f"ABORT: post-write self-check failed for: {verification_failures}",
            file=sys.stderr,
        )
        return 1

    print(f"OK: manifest re-frozen with exactly {changed_count} declared changes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
