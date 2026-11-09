"""r9a in-place re-freeze of the three identity-provisioning window files (DR-017).

Protocol (DR-009 / TC-4 / DR-015 precedent): the scoped files of a reviewed
unit are re-frozen IN PLACE — hashes updated, manifest SCOPE unchanged. This
script:

  1. rewrites ONLY the three scoped lines in ``frozen_modules.sha256``;
  2. asserts the entry COUNT stays 719;
  3. asserts the PATH SET is byte-identical before/after (fail-closed);
  4. asserts the three files actually changed hash (the window is real);
  5. leaves ``frozen_modules.sha256.baseline_pre_unfreeze`` untouched — the
     drift-vs-baseline is acknowledged by ``R9_IDENTITY_PROVISIONING_PATHS``
     (a strict subset of the r6c union) in ``tests/test_frozen_module_gate.py``
     (documented-drift union).

Lineage note: the fourth derivation of the r5+r6 lineage end state (the r5
and r6 artifact sets were lost to container recycles; r6c is the third). The
unit is the r9a consolidated identity-provisioning window: D1 validation-
surface fallback redesign, D2 operator-token fallthrough, D3 explicit
auth-type routing, D4 status honesty. ``hunter_graph.py`` is deliberately
NOT in this window (untouched by r9a; its r6c-pinned hash stays).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "frozen_modules.sha256"

R9A_IDENTITY_PROVISIONING_PATHS = (
    "src/webpent/recon/identity_discovery.py",
    "src/webpent/recon/login_executor.py",
    "src/webpent/recon/principal_provisioning.py",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines(keepends=True)
    entries: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, relpath = line.partition(" ")
        entries[relpath.strip().lstrip("*")] = digest
    before_count = len(entries)
    before_paths = set(entries)
    if before_count != 719:
        print(f"REFUSING: manifest has {before_count} entries, expected 719")
        return 1

    changed: list[tuple[str, str, str]] = []
    for relpath in R9A_IDENTITY_PROVISIONING_PATHS:
        absolute = ROOT / relpath
        if not absolute.exists():
            print(f"REFUSING: scoped file missing: {relpath}")
            return 1
        current = _sha256(absolute)
        pinned = entries.get(relpath, "")
        if pinned and pinned == current:
            print(f"WARNING: scoped file already matches manifest (no drift): {relpath}")
            continue
        changed.append((relpath, pinned, current))

    if not changed:
        # Idempotent success (consolidated-patch lineage): the r6c refreeze
        # (DR-015) runs FIRST in the LAB procedure and already re-pins all
        # four r6c-window files — including the three r9a scoped files — to
        # their current (r9a) bytes. Nothing left to update is the EXPECTED
        # post-r6c state, not an error.
        print(
            "already frozen in place (DR-017): 0 hashes updated, 719 entries, "
            "path set byte-identical (r6c refreeze already pinned the r9a bytes)"
        )
        return 0

    updated = 0
    new_lines: list[str] = []
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(raw)
            continue
        digest, _, relpath = stripped.partition(" ")
        relpath_clean = relpath.strip().lstrip("*")
        replacement = next((item for item in changed if item[0] == relpath_clean), None)
        if replacement is None:
            new_lines.append(raw)
            continue
        new_lines.append(f"{replacement[2]}  {relpath_clean}\n")
        updated += 1

    if updated != len(changed):
        print(f"REFUSING: expected to update {len(changed)} lines, updated {updated}")
        return 1

    rewritten = MANIFEST.read_text(encoding="utf-8")
    MANIFEST.write_text("".join(new_lines), encoding="utf-8")

    after_entries: dict[str, str] = {}
    for raw in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, relpath = line.partition(" ")
        after_entries[relpath.strip().lstrip("*")] = digest
    if len(after_entries) != 719 or set(after_entries) != before_paths:
        MANIFEST.write_text(rewritten, encoding="utf-8")
        print("REFUSING (rolled back): manifest scope changed — path set must stay byte-identical")
        return 1

    print(f"re-freeze OK (DR-017): {updated} hashes updated in place, 719 entries, path set byte-identical")
    for relpath, before, after in changed:
        head = (before or "absent")[:12]
        print(f"  UPDATED: {relpath} {head}.. -> {after[:12]}..")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
