#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the UM-DR-33 window (2026-11-10)
per the DR-009 / refreeze protocol.

Documented scope of this refreeze — exactly ONE frozen file:

  1. src/webpent/cqa_v2/proof_bundle_builder.py — the evidence-chain
     identity fix (UM-DR-33 Phase 2, Workstream B §4.3): the production
     builder passed ``bundle_id=None`` unconditionally into
     ``CompleteProofBundle(...)``, which OVERRODE the dataclass
     ``default_factory`` (``cqa2_pb_<uuid4hex>``) — every bundle built by
     ``build_complete_proof_bundle`` carried ``bundle_id=None``
     (empirically verified pre-fix; both production callers —
     cqa_v2/pipeline.py:153 and cqa_v2/autonomous_loop.py:235 — omit the
     argument). The fix passes ``bundle_id`` only when the caller
     supplied one, so the factory fires exactly as designed. Explicit
     ids are still honored. The seal/digest/validation logic is
     untouched.

Regression coverage verified BEFORE this re-pin:
  tests/test_umdr33_evidence_chain_fixes.py
    - test_default_bundle_id_is_generated_not_none  (the defect pin)
    - test_explicit_bundle_id_is_honored
    - test_two_default_builds_get_distinct_ids
    - test_bundle_still_seals_and_validates
    - test_direct_construction_and_builder_agree_on_factory_behavior
  Plus the pre-existing cqa_v2 consumers stay green
  (test_proof_bundle.py, test_cem_digest.py, test_causal_reasoning.py).

Old pin (recorded for the audit trail):
  5fdb526f460617a7b7163359d66459f798148db92c3eb61844f2c5c6fdf6f951

No other frozen file changed. The pre-unfreeze baseline is untouched.
Self-verifying: the result is re-hashed from disk before write.
Usage: python3 scripts/refreeze_manifest_umdr33.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

UMDR33_REPINNED_FILES = (
    "src/webpent/cqa_v2/proof_bundle_builder.py",
)

OLD_PINS = {
    "src/webpent/cqa_v2/proof_bundle_builder.py":
        "5fdb526f460617a7b7163359d66459f798148db92c3eb61844f2c5c6fdf6f951",
}


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
        if relpath in UMDR33_REPINNED_FILES:
            new_digest = sha256(REPO / relpath)
            if OLD_PINS[relpath] == new_digest:
                print(f"ERROR: {relpath} unchanged on disk — nothing to re-pin")
                return 1
            entries.append((new_digest, relpath))
            repinned += 1
            print(f"re-pinned {relpath}\n  old {OLD_PINS[relpath]}\n  new {new_digest}")
        else:
            entries.append((digest, relpath))
        listed.add(relpath)

    missing = set(UMDR33_REPINNED_FILES) - listed
    if missing:
        print(f"ERROR: declared re-pin files absent from manifest: {sorted(missing)}")
        return 1
    if repinned != len(UMDR33_REPINNED_FILES):
        print(f"ERROR: expected {len(UMDR33_REPINNED_FILES)} re-pins, did {repinned}")
        return 1

    # self-verify: every digest re-hashed from disk matches what we will write
    for digest, relpath in entries:
        if sha256(REPO / relpath) != digest:
            print(f"ERROR: self-verification failed for {relpath}")
            return 1

    MANIFEST.write_text(
        "\n".join(f"{digest}  {relpath}" for digest, relpath in entries) + "\n",
        encoding="utf-8",
    )
    print(f"manifest written: {len(entries)} entries ({repinned} re-pinned this window)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
