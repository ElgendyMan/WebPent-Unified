# Verification Report — FULL SWEEP 2026-10-20 (Phase 5, independent)

Every check below was executed after the last fix commit, by means
independent of the fix's own tests (PoC re-runs, greps, gate runs,
seal hashes, fresh suite runs).

## Ground truth after the fixes

- **Full suite**: 4,337 passed, 0 failed (monotonic: 4,329 + 8 new
  tests — 5 forge-integration, 2 encoding-engine, 1 deep-bridge).
- **verify_all.py**: 145/145 PASSED.
- **Construction-authority gate**: exit 0.
- **Isolated packages unchanged**: verdict 60 passed; emulator 17
  passed + 16 skipped; rehearsal 10 passed.
- **Direct-I/O inventory**: the campaign/forge/deep additions carry
  zero `getattr` (grep: 0) — inventory 4/4, no drift, no
  regeneration needed.
- **Seals UNMOVED**: modern_spine.py `d10783ec422b…`,
  profile.py `30fd86c61156…` (sha256 this run).
- **ruff**: clean on every touched file (forge/integration.py,
  forge/schemas.py, forge/encoding_engine.py, deep/bridge.py).

## Fix-by-fix independent verification (PoC re-runs, not the fix tests)

1. **F-01**: PoC re-run — campaign-minus-forge is exactly
   {BOLA, IDOR, AUTH_BYPASS, INFO_DISCLOSURE};
   `UNMAPPABLE_CAMPAIGN_FAMILIES` equals that set exactly; the
   schemas docstring now states "Not a superset" and names the
   divergence. A BOLA-only phase returns [] without raising.
2. **F-03**: grep of forge/integration.py source — zero `hasattr`,
   zero `getattr`; a plain-string family hypothesis still produces
   bundles (the duck-typed contract preserved).
3. **F-04**: a broken encoder raising RuntimeError now propagates
   out of `generate_variants` (previously swallowed); a
   lone-surrogate payload skips only the unencodable encodings
   (base64 absent) and all other variants still render.
4. **F-02**: `finding_to_hypothesis` on a family "RACE_CONDITION"
   finding raises `DeepBridgeError` naming the family — the raw
   KeyError is gone; a mapped family (Tier-1) still converts.

## Cross-cutting re-checks

- Zero network imports in forge/deep beyond urllib.parse (pure).
- No new `except Exception` anywhere in the recent packages.
- Suite warnings unchanged (pre-existing capture warnings only).

## Conclusion

Every fix verified independently. No regression found; all gates,
seals and suites hold.
