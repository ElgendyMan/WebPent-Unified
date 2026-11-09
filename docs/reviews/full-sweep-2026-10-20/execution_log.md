# Execution Log — FULL SWEEP 2026-10-20 (Phase 5)

Every fix executed red-first and committed separately. Commit order
matches the plan; the baseline commit precedes all of them.

1. `review baseline: full-sweep 2026-10-20 discovery+sweeps+findings+plan`
   — the tree as discovered, plus all sweep documents.

2. **F-01 (HIGH)** — forge/schemas.py Family docstring corrected
   ("Not a superset…", naming the divergence both directions);
   forge/integration.py gained the module-level
   `UNMAPPABLE_CAMPAIGN_FAMILIES` frozenset, referenced explicitly in
   `get_payloads_for_phase` (replacing the accidental KeyError
   `continue` path) with a docstring stating the skip is documented.
   Red: pin test failed on import; the docstring-correction test
   failed while the false claim stood. Green: 13/13 in
   tests/forge/test_integration.py. One follow-up commit pinned the
   corrective wording (the first assertion was the over-broad word
   ban `"superset" not in source`, which the corrective sentence
   itself contains — corrected to assert the correction).

3. **F-03 (MEDIUM)** — forge/integration.py `hasattr(h.family, "value")`
   replaced with a direct `isinstance(h.family, enum.Enum)` read;
   red: the source-scan test failed with hasattr still present.
   Green: 13/13; string-family hypothesis still yields bundles.
   (Amended once to move `import enum` and the constant block below
   the imports for ruff E402 — no behavior change.)

4. **F-04 (MEDIUM)** — forge/encoding_engine.py `except Exception`
   narrowed to `except (TypeError, UnicodeError)` with a comment
   naming the contract; red: the RuntimeError-propagation test failed
   while the broad except stood. Green: 9/9 in
   tests/forge/test_encoding_engine.py (incl. the surrogate
   regression lock).

5. **F-02 (HIGH)** — deep/bridge.py gained `DeepBridgeError(ValueError)`
   and `finding_to_hypothesis` now raises it, naming the family, for
   any DEEP family outside `DEEP_FAMILY_TO_CAMPAIGN`; red: the typed-
   error test failed on ImportError. Green: tests/bridge/test_deep_bridge.py
   fully green.

## Honest deviations during execution

- The first F-01 commit carried the not-yet-green red tests for F-03
  (same test file, appended together). The red-first evidence for
  each fix is in this log and in the test run transcripts above;
  no fix was committed before its own red test was seen failing.
- The F-01 assertion about the word "superset" was itself wrong
  (it banned the corrective sentence too); fixed in the follow-up
  commit and recorded here.

## Protocol violations: none

No new features (the BOLA/IDOR/AUTH_BYPASS/INFO_DISCLOSURE corpus
equivalents stay roadmap). No core touches (modern_spine.py /
profile.py seals re-verified unmoved). No test modified to pass —
the only test change was correcting a defective assertion before it
was ever green, with the reason recorded. No merged fixes. No
skipped tests.
