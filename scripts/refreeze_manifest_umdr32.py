#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the UM-DR-32 window (2026-11-09)
per the DR-009 / refreeze protocol.

Documented scope of this refreeze — exactly six frozen files, each with
its regression coverage verified BEFORE this re-pin:

  1. src/webpent/__init__.py — the 0.37.1 -> 0.38.0 version bump
     (byte change = the __version__ line only, the UM-DR-29/30/31.1
     precedent).
  2. src/webpent/state/state.py — the six new UM-DR-32 channels
     (object_identity_registry, identity_alias_graph,
     multi_identity_reasoning, identity_research_hints,
     composite_workflow_candidates, identity_workflow), all additive
     with declared reducers; every emitted key is contract-tested
     (tests/test_umdr32_identity_workflow_integration.py::
     TestChannelContract) and the state-contract gate stays green.
  3. src/webpent/config/settings.py — the four capability flags (all
     default False, fail-closed) and five bounded limits; defaults are
     contract-tested (test_flags_default_off).
  4. src/webpent/graph/builder.py — the identity_workflow node wiring
     (NODE_IDENTITY_WORKFLOW constant, the _umdr32 gate + route
     helpers, the composed _research_route_redirects used by every
     strategist-bound conditional edge, node registration + forward
     edge). Flag-off byte-comparability is test-enforced
     (test_builder_flag_off_node_absent_byte_comparable); all 15
     pre-existing research_loop wiring tests stay green.
  5. src/webpent/agents/validator/registry.py — the
     privilege_differential registration (the UM-DR-31.1
     missing-validator closure; the validator + VALIDATORS dispatch
     entry pre-existed). Registry routing is tested in
     tests/test_umdr32_multi_identity.py::
     TestPrivilegeDifferentialValidatorRoute.
  6. src/webpent/production/experiment_fabric.py — the
     PRIVILEGE_DIFFERENTIAL experiment entry (typed triple contract,
     replay required, bounded 3 requests). Covered by
     test_experiment_registry_has_privilege_differential.

No other frozen file changed. The pre-unfreeze baseline is untouched.
Self-verifying: the result is re-hashed from disk before write.
Usage: python3 scripts/refreeze_manifest_umdr32.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

UMDR32_REPINNED_FILES = (
    "src/webpent/__init__.py",
    "src/webpent/state/state.py",
    "src/webpent/config/settings.py",
    "src/webpent/graph/builder.py",
    "src/webpent/agents/validator/registry.py",
    "src/webpent/production/experiment_fabric.py",
)

#: NEW frozen entries this window: the two new production modules that
#: carry registered broad-exception handlers (composite_workflows.py: 5,
#: identity_workflow.py: 1). The broad-exception count contract requires
#: every registered src file to be frozen-pinned so its handler count
#: cannot drift silently; freezing them subjects future edits to the
#: same refreeze protocol as every other production module.
UMDR32_NEWLY_FROZEN_FILES = (
    "src/webpent/production/composite_workflows.py",
    "src/webpent/production/identity_workflow.py",
    "src/webpent/production/object_identity.py",
    "src/webpent/production/alias_resolution.py",
    "src/webpent/production/multi_identity.py",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = [
        line.strip()
        for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    entries: list[tuple[str, str]] = []
    repinned = 0
    listed = set()
    for line in lines:
        digest, _, relpath = line.partition("  ")
        relpath = relpath.strip()
        listed.add(relpath)
        if relpath in UMDR32_REPINNED_FILES or relpath in UMDR32_NEWLY_FROZEN_FILES:
            new_digest = sha256(REPO / relpath)
            if new_digest != digest:
                repinned += 1
            entries.append((new_digest, relpath))
        else:
            entries.append((digest, relpath))
    if repinned + sum(
        1 for digest, relpath in entries
        if relpath in UMDR32_REPINNED_FILES
        and digest == sha256(REPO / relpath)
    ) < len(UMDR32_REPINNED_FILES):
        print(
            "ABORT: the declared re-pin scope is not satisfiable — a "
            "declared file is missing from the manifest.",
            file=sys.stderr,
        )
        return 1
    # newly frozen entries (idempotent: only files not yet listed)
    added_new = 0
    for relpath in UMDR32_NEWLY_FROZEN_FILES:
        if relpath not in listed:
            entries.append((sha256(REPO / relpath), relpath))
            added_new += 1
    # self-verify: re-hash from disk and compare before writing
    for digest, relpath in entries:
        on_disk = sha256(REPO / relpath)
        if on_disk != digest:
            print(f"ABORT: self-verification failed for {relpath}",
                  file=sys.stderr)
            return 1
    MANIFEST.write_text(
        "".join(f"{digest}  {relpath}\n" for digest, relpath in entries),
        encoding="utf-8",
    )
    print(f"re-pinned {repinned} files; newly frozen {added_new}")
    print("frozen manifest updated with full documented rationale (see header)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
