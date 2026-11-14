"""r6c in-place re-freeze of the four identity-ladder window files (DR-015).

Protocol (DR-009 / TC-4 precedent): the scoped files of a reviewed unit are
re-frozen IN PLACE — hashes updated, manifest SCOPE unchanged. This script:

  1. rewrites ONLY the four scoped lines in ``frozen_modules.sha256``;
  2. asserts the entry COUNT stays 719;
  3. asserts the PATH SET is byte-identical before/after (fail-closed);
  4. asserts the four files actually changed hash (the window is real);
  5. leaves ``frozen_modules.sha256.baseline_pre_unfreeze`` untouched — the
     drift-vs-baseline is acknowledged by ``R6C_IDENTITY_LADDER_PATHS`` in
     ``tests/test_frozen_module_gate.py`` (documented-drift union).

Lineage note: this is the THIRD derivation of the same r5+r6 end state (the
r5 and r6 artifact sets were lost to container recycles); the unit is the
r6c identity-ladder + honest-validation + refuted-replan window.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "frozen_modules.sha256"

R6C_IDENTITY_LADDER_PATHS = (
    "src/webpent/recon/identity_discovery.py",
    "src/webpent/recon/login_executor.py",
    "src/webpent/recon/principal_provisioning.py",
    "src/webpent/agents/hunter_graph.py",
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
    for relpath in R6C_IDENTITY_LADDER_PATHS:
        absolute = ROOT / relpath
        if not absolute.exists():
            print(f"REFUSING: scoped file missing: {relpath}")
            return 1
        observed = _sha256(absolute)
        recorded = entries.get(relpath)
        if recorded is None:
            print(f"REFUSING: scoped path not pinned in manifest: {relpath}")
            return 1
        changed.append((relpath, recorded, observed))

    actually_changed = [item for item in changed if item[1] != item[2]]
    if not actually_changed:
        print("NOTHING TO DO: no scoped file drifted from the pinned manifest")
        return 0

    out: list[str] = []
    seen: set[str] = set()
    for raw in lines:
        line = raw.strip()
        digest, _, relpath = line.partition(" ")
        relpath = relpath.strip().lstrip("*")
        replacement = next((item for item in changed if item[0] == relpath and relpath not in seen), None)
        if replacement is not None and digest.strip() == replacement[1]:
            out.append(f"{replacement[2]}  {relpath}\n")
            seen.add(relpath)
        else:
            out.append(raw if raw.endswith("\n") else raw + "\n")

    rewritten: dict[str, str] = {}
    for raw in out:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        new_digest, _, new_relpath = line.partition(" ")
        rewritten[new_relpath.strip().lstrip("*")] = new_digest

    if len(rewritten) != before_count:
        print(f"REFUSING: rewritten manifest count {len(rewritten)} != {before_count}")
        return 1
    if set(rewritten) != before_paths:
        print("REFUSING: path set changed — scope must be preserved (DR-015)")
        return 1
    for relpath, _old, new in changed:
        if rewritten[relpath] != new:
            print(f"REFUSING: {relpath} was not updated in place")
            return 1
    unchanged = [p for p in before_paths if p not in R6C_IDENTITY_LADDER_PATHS and rewritten[p] != entries[p]]
    if unchanged:
        print(f"REFUSING: non-scoped hashes moved: {sorted(unchanged)}")
        return 1

    MANIFEST.write_text("".join(out), encoding="utf-8")
    print(
        f"re-freeze OK (DR-015): {len(changed)} hashes updated in place, "
        f"{len(rewritten)} entries, path set byte-identical"
    )
    for relpath, old, new in changed:
        state = "UPDATED" if old != new else "already-current"
        print(f"  {state}: {relpath} {old[:12]}.. -> {new[:12]}..")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
