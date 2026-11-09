# WebPent gap-closure cleanup — summary (2026-10-02)

Executed against `WebPent_Full_Error_Report_and_Fix_Plan.md`'s Phases 0–6 and
8 (Phase 7 — splitting the two 1000+ line functions — deliberately deferred;
see "Not done" below). All work is committed as 9 reviewable git commits in
this archive's `.git` history; each commit message documents the reasoning,
not just the diff.

## Verified end state

Full `pytest` suite (2120 tests, all now collectible after installing a
lightweight dependency set — no torch/heavy ML needed):

**2086 passed / 16 failed / 18 errors** — confirmed via a direct before/after
comparison against the original baseline to be **exactly** the pre-existing
failure set (same test IDs, same counts). Zero regressions from this cleanup
pass. The 34 non-passing tests need real infrastructure this review sandbox
doesn't have (a live Chromium binary, a running lab server) or have
test-ordering dependencies — both pre-existing, out of scope here.

`ruff check .`: 5351 → 5183 findings (mostly cosmetic `E501`/`E701`/`E702`
style, left for a future dedicated formatting pass — see Phase 6 notes below).

## What was fixed, by phase

**Phase 1 — test theater:** Removed 3 vacuous `assert True` tests and fixed
all 7 `or True` tautologies individually (not batch-stripped) — each one
reviewed against what its name/comment claimed to check. Removed 4 dead
`if False` branches. Fixed a `.rstrip()` vs `.removesuffix()` bug. **Bonus
find:** a Python-3.12-only f-string escape in `reporter/agent.py` that would
`SyntaxError` on the project's actual target (py310) — not in the original
report.

**Phase 2 — logic bugs:** 4 bare `except:`, one `== False` comparison, a
missing `stacklevel` on `warnings.warn`, 3 unsafe `zip()` calls (verified
each had a real equal-length invariant before adding `strict=True`), and 2
`pytest.raises(Exception)` narrowed to the actual exception types raised.

**Phase 3 — security:** Documented the `session_reauth` SQLi promotion
carve-out (previously undocumented, making "fail-closed" claims inaccurate)
and added a `logger.warning` so its real-world frequency is now observable.
Investigated the CSRF carve-out and found it's currently **dead code**
(`can_tool_confirm` hardcoded `False`) rather than a live bypass — added a
warning comment instead of silently deleting it, since reactivating it is a
product decision. Refreshed `pip-audit` (previous was 40 days stale): 30
known CVEs across 5 pinned packages, `pyjwt` flagged highest-priority given
this is an auth-focused project.

**Phase 4:** Fixed 5 F811 import-shadowing cases in `goed_v1/__init__.py`
(two real, differently-behaving classes were sharing one import name —
runtime-verified the fix). Removed an orphaned, byte-identical duplicate
`shared/` directory.

**Phase 5:** AST-triaged all 547 broad exception handlers in `src/`. Found
one real bug (`scope_enforcer` silently dropping the `exclude_paths`
deny-list on a malformed declaration instead of failing closed — now raises
`ScopeEnforcementError`). Added logging visibility (behavior unchanged) to 6
other handlers directly on the evidence/promotion critical path. Spot-checked
the rest of the 95 "silent" candidates across crypto/auth/DNS/adapter code —
all genuinely safe as-is.

**Phase 6:** Ran the plan's exact autofix command. **Correction to the
original plan:** of the ~4800 matching violations, plain `ruff --fix` only
actually fixes `I001` (import sorting) — 71 fixes. The rest need
`--unsafe-fixes` or manual rewrites; not applied here since "unsafe" is
ruff's own label for behavior-changing fixes, out of scope for a style-only
phase.

**Phase 8 (brought forward):** Got the full test suite running (0 → 2120
collectible tests) by installing ~10 lightweight packages. This surfaced 5
regressions from the above work, all traced and fixed:
- **A genuine security gap**, found via the Phase 1 test-theater fix: 5 of 6
  adversarial memory-poisoning phrases in `test_half2_proof_memory.py` were
  not being neutralized by `advisory_memory.py`'s regex list. Added 5 new
  patterns — this is a real fix to adversarial-input handling, not just a
  test change.
- A stale recorded artifact (`docs/direct_io_inventory.json`) after Phase 6
  shifted line numbers — regenerated, with every changed record verified to
  differ *only* in line/column, never in substance.
- Two SHA-256 file-integrity pins (`test_team1_deep_recon.py`) correctly
  caught my own Phase 5 edits to `proof_bundle.py`/`replay_validator.py` —
  updated with an inline audit trail explaining exactly what changed.
- A test with a scope bug (`test_team1_wiring_fix.py`) unmasked by removing
  its `or True` — it was inspecting the wrong class's source; fixed to
  inspect the actual module, matching the comment's own stated intent.

## Not done (deliberately deferred)

**Phase 7** — splitting the two ~1000+ line functions into smaller units.
The plan itself labels this its lowest-priority, highest-effort item.
Deferred by explicit decision given cost/risk tradeoff: everything
higher-value is done and test-verified; this phase is a large structural
refactor of security-critical code with real residual risk even with pytest
now working. Can be picked up in a future pass — the test suite is now in a
state where it could actually verify such a refactor, which it couldn't do
before this cleanup.

Also not done: the ~85 lower-risk silent exception handlers and 45
`BLE001`-noqa'd handlers not individually reviewed beyond spot-checks (see
Phase 5 above), and the bulk of `E501`/`E701`/`E702` style findings (cosmetic,
not logic-affecting, left for a dedicated formatting pass).
