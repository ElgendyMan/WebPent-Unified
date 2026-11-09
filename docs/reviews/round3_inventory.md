# Round-3 Inventory and Gate — The 3 New Packages

_Date: 2026-10-18. Reviewer: red team (Round 3). Scope: `verdict/`,
`emulator/`, `rehearsal/` — the packages the Verdict Protocol depends on._

The premise of this round: **the Verdict depends on these tools. If they
lie, the Verdict lies.** Day 1 inventories what exists, what claims to be
true, and whether anything here touches the webpent core.

## 1. Inventory

| Package | Unit | Modules | Tests (count) | Live/Docker-skipped |
|---|---|---|---|---|
| verdict/ | U-VERDICT-1..8 | tracking, targets, classifier, submission, metrics, pre_registration, protocol, cli | 52 → 60 after Round-3 fixes | none (pure Python) |
| emulator/ | U-EMU-1..5 | docker-compose (6 services), ModSecurity config, rate limiter, fail2ban, monitoring dashboard | 9 static + 8 live (skip without Docker) → 17 after fixes | 16 skip without Docker |
| rehearsal/ | U-DRYRUN-1..2 | rehearsal.py, playbook.py, run_dry_run.py, run_real_pilot.py | 10 | none (pure Python) |

Total before this round: 52 + 9 + 10 = 71 collected tests (16 skipped
without Docker). After Round-3 fixes: 60 + 17 + 10 = 87 collected, all
green in-sandbox. Suite count went UP (8 new regression tests), never down.

## 2. Isolation gate (zero-touch on webpent core)

- `git diff` on tracked core files: not a git repo in the review
  workspace, so isolation was verified by checksum against the shipped
  ZIP (`webpent_v89_prism_fixed.zip`):
  - `src/webpent/production/modern_spine.py` → `ff43e9…` **identical**
  - `src/webpent/live_hunter/profile.py` → `30fd86…` **identical**
- Cross-import grep: `from webpent`, `import webpent`, `modern_spine`,
  `live_hunter` across all 3 packages → **0 hits**.
- The 3 packages import only stdlib, yaml, click and each other (verdict
  imports nothing from emulator/rehearsal; rehearsal imports nothing from
  verdict).

**Gate result: PASS.** The packages are isolated; nothing in this round
needs to touch `modern_spine.py` or `profile.py`, so the zero-touch
escalation rule was never triggered.

## 3. Claims found in the packages, to be attacked in Days 2-4

- verdict: "no network, no shell: a structured notebook, not an agent";
  "classifications are immutable"; "the verdict is a function of the
  data, not of hope"; pre-registration "written on day 0, checked on day
  46".
- emulator: vulnerable-by-design services; WAF blocks at paranoia 2;
  monitoring reads shared logs.
- rehearsal: playbook generated from real lessons; dry-run/pilot reports
  are explicitly labeled NOT capability proofs.

## 4. What Day 1 found on paper (checked for real on Days 2-3)

- `Workspace.save`/`load` wrote and parsed `state.json` with no integrity
  check at all → candidate CRITICAL (became F-1).
- `pre_registration.predict` had no freeze check → candidate HIGH (F-2).
- `pre_registration.md` was never hashed → candidate HIGH (F-3).
- `classify()` accepted any non-empty evidence string → candidate
  MEDIUM-HIGH (F-4).
- `select` could be re-run after the day-14 freeze → candidate MEDIUM
  (F-5).
- All 6 emulator services published ports on 0.0.0.0 → candidate MEDIUM
  (F-6).
- `test_waf.py::test_paranoia_level_2` checked a string, not a value →
  candidate LOW (F-7).

Every candidate was then verified with a real PoC in
`round3_poc/` (see verdict_wargames.md and emulator_rehearsal_wargames.md).
