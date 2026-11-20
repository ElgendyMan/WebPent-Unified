"""R4 production-hardening window in-place re-freeze (DR-020).

Protocol (DR-009 / TC-4 / DR-015 / DR-017 precedent): the scoped files of a
reviewed unit are re-frozen IN PLACE — hashes updated, manifest SCOPE
unchanged. This script:

  1. rewrites ONLY the eight scoped lines in ``frozen_modules.sha256``;
  2. asserts the entry COUNT stays 719;
  3. asserts the PATH SET is byte-identical before/after (fail-closed);
  4. asserts the eight files actually changed hash (the window is real);
  5. leaves ``frozen_modules.sha256.baseline_pre_unfreeze`` untouched — the
     drift-vs-baseline is acknowledged by ``R4_PRODUCTION_HARDENING_PATHS``
     in ``tests/test_frozen_module_gate.py`` (documented-drift union).

The unit is the R4 production-hardening window (operator-authorized:
strict production key guard + attack-detector wiring, which per the
documented queue process also clears the re-freeze queue):

  * W1 strict key guard:        src/webpent/shared/preflight.py
  * W2 detector wiring:         src/webpent/models/findings.py,
                                src/webpent/agents/validator/registry.py,
                                src/webpent/agents/validator/agent.py,
                                src/webpent/agents/validator/postp0_checks.py,
                                src/webpent/graph/builder.py
  * W3 queue items:             src/webpent/cli/commands.py (--version/--build-info),
                                src/webpent/api/app.py (security headers)

NOT re-frozen (not in the manifest, library-stage modules): the two detector
node hosts src/webpent/agents/prototype_pollution/agent.py and
src/webpent/agents/cache_poisoning/agent.py — their node additions are
documented in DR-020 and covered by the full test suite + the G-02
regeneration (scripts/regen_direct_io_inventory_r4_20261102.py).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "frozen_modules.sha256"

R4_PRODUCTION_HARDENING_PATHS = (
    "src/webpent/api/app.py",
    "src/webpent/cli/commands.py",
    "src/webpent/graph/builder.py",
    "src/webpent/agents/validator/agent.py",
    "src/webpent/agents/validator/postp0_checks.py",
    "src/webpent/agents/validator/registry.py",
    "src/webpent/models/findings.py",
    "src/webpent/shared/preflight.py",
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
    for relpath in R4_PRODUCTION_HARDENING_PATHS:
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
        print("already frozen in place (DR-020): 0 hashes updated, 719 entries, path set byte-identical")
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

    print(f"re-freeze OK (DR-020): {updated} hashes updated in place, 719 entries, path set byte-identical")
    for relpath, before, after in changed:
        head = (before or "absent")[:12]
        print(f"  UPDATED: {relpath} {head}.. -> {after[:12]}..")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
