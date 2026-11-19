# Round-3 Verdict — PASS with fixes applied (no conditions left open)

_Date: 2026-10-18._

## Verdict: **PASS**

The 3 packages are verified against their claims after the Round-3 fixes.
Every confirmed finding has a real PoC (not on paper), every fix has a
red-first test, and the war games were re-run against the fixed code and
are now blocked.

## Findings and their fixes (all 7 fixed)

| ID | Severity | Fix | Red-first test |
|---|---|---|---|
| F-1 CRITICAL | state.json tamper | `Workspace.save` writes SHA-256 to `.verdict/state.sha256`; `load` refuses on mismatch or missing record (`StateTamperError`) | `test_tampered_state_detected`, `test_missing_integrity_record_detected` |
| F-2 HIGH | re-predict after freeze | `pre_registration predict` refuses when `pre_registered` is set; `edit` likewise | `test_predict_after_freeze_refused`, `test_prereg_edit_after_freeze_refused` |
| F-3 HIGH | prereg file editable | freeze records `pre_registration_sha256`; `verdict final` refuses on mismatch | `test_prereg_hash_recorded_at_freeze`, `test_verdict_refused_when_prereg_modified` |
| F-4 MEDIUM-HIGH | evidence laundering | `classify()` verifies every evidence path resolves to a file in the workspace | `test_nonexistent_evidence_refused`, `test_existing_evidence_accepted` |
| F-5 MEDIUM | selection re-freeze | `select` refuses when `state.selection` is non-empty | `test_selection_cannot_be_refrozen` |
| F-6 MEDIUM | 0.0.0.0 binds | all 6 compose ports and both Python servers bind 127.0.0.1 | `test_no_wildcard_host_port_in_compose`, `test_dashboard_and_api_bind_loopback` |
| F-7 LOW | value-blind WAF test | `waf_config.waf_problems()` parses values; `test_waf.py` now uses it | `test_paranoia_mutation_is_caught`, `test_engine_off_mutation_is_caught` |

## War games re-run against the fixed code (was → now)

- WG2.2 re-predict after freeze: allowed → **BLOCKED** ("pre-registration
  is frozen; predictions cannot change after day 0").
- WG2.3 prereg edit then `verdict final`: silent → **BLOCKED**
  ("pre_registration.md changed after the freeze").
- WG5.4 forged GO from hand-edited state: GO → **BLOCKED**
  (`StateTamperError: state.json was modified outside the tool`).
- WG5.5 silent FP deletion: GO → **BLOCKED** (same integrity path).
- WG3.2 confirmed with nonexistent evidence: exit 0 → **BLOCKED**
  ("evidence paths do not exist in the workspace").
- WG1: unchanged and still blocked (no auto-submit, no network methods).

## Success criteria, checked

- All 6 war games executed with real PoCs: yes (`round3_poc/`).
- Every finding has a PoC or is marked SUSPECTED: all 7 have PoCs.
- Every fix has a red-first test: yes, 8 verdict + 5 emulator tests.
- Packages isolated from webpent core: checksums of `modern_spine.py`
  (`ff43e9…`) and `profile.py` (`30fd86…`) identical to the shipped ZIP;
  cross-import grep 0 hits; **git diff equivalent = zero**.
- Suite count not reduced: 71 → 87 collected tests, all green
  (verdict 60, emulator 17, rehearsal 10; 16 emulator tests still skip
  honestly without Docker — their skip condition is unchanged).
- Ruff clean on modified files: yes.
- Clean ZIP: `webpent_v89_prism_round3.zip`.
- Updated Known Unknowns Register: `docs/known_unknowns_round3.md`.

## Residual risks, stated honestly

- The integrity hash is unkeyed: it catches accidental edits and naive
  tampering, not a determined local attacker who rewrites both files.
  Chain of custody comes from committing the workspace to the operator's
  VCS. This is documented in `StateTamperError`'s docstring and in the
  protocol doc.
- The WAF live tests still require Docker (16 skips); the value-aware
  static checks close the value-drift hole without Docker, but behavioral
  WAF verification still needs the stack up.
- Real-target behavior (acceptance by real programs, day-46 prediction
  accuracy) remains untestable until a real target is available; that
  unknown is retired only by the pilot itself.
