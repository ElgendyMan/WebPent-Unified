# Round-4 Verification Log — everything works, wired, non-conflicting

_Date: 2026-10-18. Part 1 of the current directive (verification) plus
the execution record for Parts 2-4 (proposal, plan, execution — see
docs/accountability_spine_proposal.md and docs/reviews/round4_seal_update.md)._

## Part 1 — what was verified before anything changed

- **Byte-compile**: `compileall` across `src/`, `verdict/`, `emulator/`,
  `rehearsal/` — clean.
- **The 3 new packages** (from the Round-3 close, unchanged since):
  verdict 60 passed, emulator 17 passed + 16 honest Docker skips,
  rehearsal 10 passed. Isolation re-verified: no webpent imports
  anywhere in the three packages.
- **Cross-wiring audit**: `grep` for verdict/emulator/rehearsal
  references across `src/webpent/` — zero. The three packages were
  parallel islands; nothing fed the 47-day protocol from the campaign
  loop. That gap is what Part 2's proposal addresses.
- **Unified audit** (`verify_all.py`): started at 145 checks with 7
  FAIL. Each failure was triaged against the actual files; all 7 were
  stale audit-script expectations, not real breakage:
  - F4c: the Dockerfile copies `entrypoint.sh` after `COPY . .` —
    intentional and harmless (single file, correct exec perms); the
    check demanded `COPY . .` be literally last. Now checks that no
    broad COPY follows the source COPY.
  - U1d: the Dockerfile opens with a `# syntax=docker/dockerfile:1`
    directive and a comment header — valid practice; the check demanded
    FROM be the literal first line. Now checks the first meaningful
    line.
  - U4f: tool discovery is lazy now (`ensure_discovered()` on first
    lookup, side-effect-free import) — an improvement; the check
    demanded import-time `auto_discover()`. Now asserts the lazy
    contract.
  - U4g: three of the nine tool wrappers use multi-line
    `@register_tool(` decorators — valid; the check matched only the
    single-line form. Now accepts both.
  - DX8e: `memory/db.py` stamps the actual head revision instead of the
    literal string `"head"` (its own docstring explains why: a literal
    stamp would falsely claim schema integrity). Now asserts the actual
    revision is stamped and the literal is never used.
  After the fixes: **145 PASS, 0 FAIL — V6 DX-FINAL UNIFIED AUDIT
  PASSED.**
- **Full suite**: 3,855 tests collected across `tests/`; full run before
  the Round-4 changes: 3,854 passed + the 1 failure that was the
  construction-authority gate correctly catching the new bridge test
  (resolved by the gate's own documented allowlist procedure).

## Part 4 — execution record (proposal → plan → code, all green)

- **Red**: `tests/test_verdict_bridge.py` — 13 tests written first, all
  failing (module did not exist).
- **Green**: `src/webpent/production/verdict_bridge.py` implemented
  (gate + registration + evidence packaging, zero imports of the
  verdict package). 13/13 green.
- **Wiring**: the two marked touch points in
  `run_autonomous_validation_campaign` (pre-flight gate, post-campaign
  registration). Wiring test green: a loopback campaign result carries
  `verdict_bridge.gate = exempt_loopback`.
- **Authority gate**: new test allowlisted through the gate's own
  reviewed procedure; `test_orchestrator_construction_authority.py`
  green.
- **Lint**: ruff clean on every file created or modified this round
  (`verdict_bridge.py`, `test_verdict_bridge.py`, and the edited ranges
  of `modern_spine.py`); the 39 pre-existing violations elsewhere in
  `modern_spine.py` were left alone deliberately (not this round's
  diff).
- **Seal update**: new `modern_spine.py` SHA-256 recorded in
  `docs/reviews/round4_seal_update.md`; `profile.py` untouched.

## Final state (after the Round-4 changes)

- Full suite: 3,868 tests (3,855 + 13 new), all passed, one honest
  background of pre-existing skips (Docker-dependent emulator tests).
  After Round 4.1: 3,870 (the two red-first bridge tests added).
- `verify_all.py`: 145/145 PASS.
- verdict / emulator / rehearsal suites: unchanged and green; their
  checksums are untouched by this round.

## Round 4.1 — the bridge under attack (post-closeout continuation)

The delivered ZIP's bridge was then attacked directly (mini war games):

- **WG-R4.1**: `finding_id = "../escaped_evil"` → confirmed: registered
  + evidence written. Fixed red-first with the finding-id allowlist
  (`_validate_finding_id`), before filesystem or CLI contact.
- **WG-R4.2**: refused registration → confirmed: orphan
  `evidence/<id>.json` left behind. Fixed red-first by registering
  before writing evidence.
- Hostname-parser differentials (octal/decimal/hex/trailing-dot
  loopback forms) — all fail-closed, no finding.
- Bridge suite: 15/15 green (13 + 2 red-first). Core checksums did not
  move (`modern_spine.py` still `ef551212…`, `profile.py` still
  `30fd86c6…`).
- Full project re-verification after the fixes: 3,870 passed; the
  direct-I/O drift check caught the two verdict_bridge.py records
  moving lines (the allowlist patch) and the artifact was regenerated
  deliberately with a verified reviewable diff (identities and counts
  unchanged); `verify_all.py` 145/145; package suites verdict 60 /
  emulator 17+16 skips / rehearsal 10 — unchanged.

## Known Unknowns — unchanged, but the pipe now exists

The register (docs/known_unknowns_round3.md) is not edited: no unknown
is retired by this round. What changed is structural: every future
real-target campaign must open with a frozen pre-registration and ends
with its promoted findings in the verdict workspace with real evidence
— the 47-day protocol is now fed by the loop it judges instead of by
hand.
