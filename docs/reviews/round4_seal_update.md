# Round-4 Seal Update — core integrity register

_Date: 2026-10-18._

Round 3 sealed the core with the rule: zero touch on `modern_spine.py`
and `profile.py`; any finding needing a core change escalates to the
operator. The current directive ("تأكد أن كل حاجة شغالة… اقترح اقتراح
مركزي… نفذ الخطة كلها") explicitly supersedes that rule for this round:
a central wiring proposal was requested and executed.

## What changed in the core, exactly

Two marked touch points in
`src/webpent/production/modern_spine.py::run_autonomous_validation_campaign`,
both clearly commented `Round 4 touch point`:

1. **Pre-flight gate** (before the loop): calls
   `verdict_bridge.verdict_preflight(target_url)` and records the gate
   decision in the spine trace. Fail-closed for non-loopback targets
   without a frozen verdict pre-registration.
2. **Post-campaign registration** (after the report): calls
   `verdict_bridge.register_campaign_findings(result)`, records the
   summary in the trace, and attaches it to the result under
   `result["verdict_bridge"]`. Per-finding failures become typed
   blockers in the result; they never raise into a completed campaign.

No other core file changed. No code inside `verdict/`, `emulator/` or
`rehearsal/` changed — the bridge couples through the verdict tool's
CLI subprocess, so the Round-3 package checksums still hold.

## Checksums

| File | Round-3 seal | Round-4 seal |
|---|---|---|
| `src/webpent/production/modern_spine.py` | `ff43e90971bf8807219e153c3e7db0a6d9b9ab3aec6176589dac54cabe1dbd35` | `ef551212eb2a3583f6d7af14b46f58c32afe9b4c67c5da6e08d4f7aece9ade31` |
| `src/webpent/live_hunter/profile.py` | `30fd86c61156e7a5883205b9ce4b2f6c3f856f78e1561676345ad988d9c5b663` | unchanged (`30fd86c6…`) |

The diff-equivalent for the new seal is exactly: the two touch-point
blocks above plus a docstring note in the dispatch method, and three
line-wrap cosmetic fixes inside one pre-existing trace call the second
touch point abuts. Everything else in the file is byte-identical.

## New core-side files (no existing file touched)

- `src/webpent/production/verdict_bridge.py` (new, the Accountability
  Spine).
- `tests/test_verdict_bridge.py` (new, 13 red-first tests, all green).
- `scripts/check_orchestrator_construction_authority.py`: one reviewed
  TEST_ALLOWLIST entry for the new test file, per that gate's own
  documented extension procedure.
- `verify_all.py`: five stale audit checks updated to test the current,
  improved behavior (see docs/verification_round4.md).

## Guardrails preserved

- Construction authority: `ModernOrchestrator` is still factory-only;
  the gate test passes with the new reviewed allowlist entry.
- Package isolation: zero imports of the verdict/emulator/rehearsal
  packages from the core; coupling is subprocess-only.
- Fail-closed: the gate blocks real targets by default; the only
  escape (`WEBPENT_REQUIRE_VERDICT_PREREG=0`) is recorded in the trace
  whenever used.
- The operator still owns classification, day-14 selection and the
  day-46 verdict — the bridge registers evidence, never judgments.

## Round 4.1 — mini war games against the bridge itself

_Post-"متابعة" continuation: the bridge is new core-adjacent surface, so
it got its own red-team pass before closeout. Two confirmed findings,
both fixed red-first in `verdict_bridge.py` only (the core's two touch
points did not move — `modern_spine.py` still hashes to
`ef551212…`)._

**WG-R4.1 — traversal-shaped finding_id (confirmed, fixed).** A
promoted finding carrying `finding_id = "../escaped_evil"` was
registered into the ledger and its evidence written under the workspace
root. PoC: feed a crafted campaign result through
`register_campaign_findings`; the id passes into both the CLI argv and
the evidence path. Fix: `_validate_finding_id()` — conservative
allowlist `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` with explicit `..`
rejection — runs before the id touches the filesystem or the CLI;
violations land in `blocked` with a typed reason. Red test:
`test_finding_id_path_traversal_is_blocked`.

**WG-R4.2 — orphaned evidence on refusal (confirmed, fixed).** When the
verdict CLI refused a registration, the evidence JSON had already been
written, leaving `evidence/<id>.json` with no ledger entry — exactly
the orphan artifact that could mislead the day-14 re-test. PoC:
monkeypatch the CLI call to raise; evidence file existed. Fix: loop
reordered to register FIRST and write evidence only after the ledger
accepted the finding. Red test: `test_no_orphan_evidence_on_refusal`.

Bridge suite after fixes: 15/15 green (13 original + 2 red-first).
Hostname-parser differentials (octal/decimal/hex/trailing-dot loopback
forms) all fail-closed as real targets — no finding. Package suites
re-checked after the fix: verdict 60, emulator 17+16 skips, rehearsal
10 — unchanged.

## Round 5 pointer

Round 5 (Re-test Dispatch Engine, docs/verification_round5.md) grew
`verdict_bridge.py` only — both seals above are UNMOVED by Round 5, and
no new touch points were added. The bridge's transport surface is
unchanged (caller-injected re-test executor); the direct-I/O artifact
was regenerated once more for line shifts only.
