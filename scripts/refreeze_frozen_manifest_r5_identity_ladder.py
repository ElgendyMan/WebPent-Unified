#!/usr/bin/env python3
"""r5-CODE window re-freeze of frozen_modules.sha256 (DR-009 protocol).

Re-pins the manifest at the current tree bytes after the documented
r5-CODE identity-ladder window.  Gates (fail-closed):
  1. the path SET is preserved exactly (no additions, no removals) — the two
     new config files (config/identity_vocab.py/.json) stay intentionally
     OUTSIDE the manifest per the additive-sprint-module precedent
     (FROZEN_HASH_VERIFICATION.txt: "session_recovery_bridge.py: NOT in
     frozen manifest (additive sprint module)"); the vocabulary data file is
     designed to be extended WITHOUT code edits, so freezing it would defeat
     requirement R3;
  2. only the four scoped files may change hash values;
  3. every listed path must exist.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "frozen_modules.sha256"

SCOPED_CHANGED = {
    "src/webpent/recon/identity_discovery.py",
    "src/webpent/recon/principal_provisioning.py",
    "src/webpent/recon/login_executor.py",
    "src/webpent/agents/hunter_runner.py",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    old_paths: list[str] = []
    old_hashes: dict[str, str] = {}
    for line in lines:
        if not line.strip():
            continue
        value, _, path = line.partition("  ")
        old_paths.append(path)
        old_hashes[path] = value
    output: list[str] = []
    changed: list[str] = []
    for path in old_paths:
        absolute = ROOT / path
        if not absolute.exists():
            print(f"REFUSE: manifest path missing from tree: {path}")
            return 1
        observed = _sha256(absolute)
        if observed != old_hashes[path]:
            if path not in SCOPED_CHANGED:
                print(f"REFUSE: out-of-scope drift in frozen file: {path}")
                return 1
            changed.append(path)
        output.append(f"{observed}  {path}")
    unexpected = SCOPED_CHANGED - set(changed)
    if unexpected:
        print(f"REFUSE: scoped file did not drift (stale window record?): {sorted(unexpected)}")
        return 1
    MANIFEST.write_text("\n".join(output) + "\n", encoding="utf-8")
    print(f"OK: re-froze {MANIFEST.name} ({len(output)} entries); updated hashes for:")
    for path in sorted(changed):
        print(f"  - {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
