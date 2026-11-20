# Fix-Sprint Evidence Report — 2026-10-05 (v5, real-browser POC smoke)

**Sprint:** REAL-BROWSER SMOKE SPRINT — close the last untested layer before
the first live campaign ("a real smoke test with an actual Playwright browser,
data: URL — the only remaining gap not covered by tests"), plus full
remediation of everything the smoke surfaced.

**Constraint compliance:** trust chain untouched (695/695 byte-identical,
697/697 gate tests), zero frozen-file edits, all fixes in non-frozen files,
every claim below re-verified from artifacts in this package.

---

## V5 CONTEXT — what this sprint closed

The v4 evidence report listed three honest limitations. This sprint closes
the first and most consequential one:

| v4 limitation | v5 disposition |
|---|---|
| **no real-browser smoke in CI** (every POC test used a fake browser factory) | **CLOSED:** `scripts/poc_smoke_real_browser.py` + `tests/test_poc_real_browser_smoke.py` — 4 phases against REAL headless chromium 143, strictly local (data: URL + loopback HTTP, zero external network); wired as a hard pre-flight gate in `scripts/run_campaign.sh` |
| frozen ledger without WAL | unchanged (documented design; upgrade is a separate sprint) |
| 2 pinned unapproved transport identities | unchanged (open security-engineering work item, g02-pinned fail-closed) |

## V5 WHAT THE SMOKE PROVES (4 phases, all local)

* **A — data: URL machinery.** The PRODUCTION factory (`playwright_factory`)
  launches real headless chromium, renders an inline `data:text/html` page
  (HTML + executed JS), and finalizes a real .webm within the 5 MiB cap. The
  webm is kept as operator-visible evidence in `hunt_artifacts/poc_smoke/`.
* **B — full owner-vs-foreign replay.** The production entry
  (`maybe_record_poc`) drives a real browser against a loopback ACL server:
  the server itself asserts the FIRST navigation carried the OWNER token, the
  SECOND the FOREIGN token (same-origin injection works over a real browser —
  previously only ever tested with fake routes). A cross-origin decoy server
  (different port) proves the v4 R-05 fix end-to-end: an `<img>` probe arrives
  with NO Authorization header, and a keepalive `fetch` carrying a
  pre-existing `Authorization: Attacker-Preexisting` passes through UNTOUCHED
  (the v3 code would have overwritten it with the phase token). Metadata:
  digests differ, caps honored, steps b–e present, raw tokens absent from the
  JSON on disk, `poc.recorded` audit event emitted.
* **C — BOLA signature.** Same real pipeline against a token-blind server →
  `identical_body_detected: true` with matching digests.
* **D — fail-soft with a real browser failure.** An unreachable target
  degrades to `{"status": "failed"}` via `maybe_record_poc` — never raises;
  `poc.failed` audit event emitted.

Measured on this machine: all 4 phases in ~3.1 s total; no external network.

## V5 DEFECTS THE SMOKE SURFACED — and their disposition

| id | severity | defect (empirically demonstrated) | disposition |
|---|---|---|---|
| S-01 | P2 | **`record_poc` leaked its `_poc_tmp_<stem>` scratch dir on every mid-recording failure.** The v4 R-16 comment claimed the dir is removed "whether the recording succeeded or failed", but the cleanup `finally` lived in the SECOND try block — a factory failure or a `goto` failure never reached it. Proven by the smoke: after phase D (real browser failure) the dir `_poc_tmp_smoke-d-unreachable` remained on disk with playwright scratch files inside. Every failed recording in a live campaign would have leaked one. | **FIXED (v5):** `record_poc` restructured with an OUTER `try/finally` that removes `record_dir` on EVERY exit path (factory failure, mid-recording failure, cap refusal, success) plus the INNER `try/finally` for browser close. Semantics otherwise unchanged. Regression tests: `test_record_poc_cleans_scratch_dir_on_factory_failure`, `test_record_poc_cleans_scratch_dir_on_mid_recording_failure`, `test_record_poc_browser_errors_propagate_raw`. Smoke re-run: **zero `_poc_tmp_*` leftovers.** |
| S-02 | P3 | **`record_poc` docstring overclaimed the error contract** ("Raises POCError on failure") while browser/navigation errors propagate with their original type. | **FIXED (v5):** docstring states the honest contract (POCError for validation/cap/artifact problems; browser errors propagate raw — `maybe_record_poc` absorbs every class). Behavior deliberately UNCHANGED: wrapping would require either a new `except Exception` site (violates the registered broad-exception gate) or a new playwright import (violates the g02 identity-preservation gate). A pin test (`test_record_poc_browser_errors_propagate_raw`) now locks the honest behavior. |
| S-03 | P3 | Smoke script's own first draft moved the phase-A video AFTER deleting its containing scratch dir (`FileNotFoundError`). | **FIXED:** move happens after `context.close()` (finalization) and before `rmtree`; `--out` resolved to absolute paths. (Recorded for honesty: the smoke found bugs in the recorder AND in itself on first run.) |

## V5 GATE WIRING

`scripts/run_campaign.sh` pre-flight now runs the smoke as a HARD gate when
`WEBPENT_POC_ENABLED=1` (operator wants POC evidence → a broken browser stack
aborts the start instead of silently recording nothing) or on demand via
`WEBPENT_POC_SMOKE=1`. Without either flag the gate is skipped with an
explicit message. Contract tests (3 new, 19 total in
`tests/test_campaign_pack_contract.py`) pin the wiring: smoke script called,
failure reaches `fail`, phases present, script compiles, and —
enforced structurally — the smoke script contains NO unregistered
`except Exception` site (scripts/ is inside the register gate's scope).

In browserless CI the pytest wrappers skip LOUDLY with the reason
(`_chromium_available()` probe); with chromium installed they run for real.

## V5 VERIFICATION BLOCK (all re-run after the S-01 fix)

| gate | result |
|---|---|
| full hermetic suite (`pytest tests/`) | **3098/3098 PASS** (3:01) = 3089 v4 baseline + 9 new (3 real-browser smoke + 3 leak regressions + 3 wiring contracts) |
| real-browser smoke (standalone script) | **4/4 phases PASS**, zero scratch-dir leftovers |
| real-browser smoke (pytest) | 3/3 PASS |
| campaign pre-flight end-to-end | smoke executes inside `run_campaign.sh` and reports PASS before campaign start (verified live) |
| integration battery (`run_integration_battery.sh`) | 153/153 PASS, genuine exit code 0 |
| frozen trust chain | 695/695 byte-identical (pytest gate 697/697) + authority manifest OK (13 files) |
| g02 direct-IO inventory | 4/4 — regenerated by `scripts/regen_direct_io_inventory_v4_linedrift.py` with identity-sequence preservation (653 records; the single `getattr` site in `poc_recorder.py` moved line 265→277, identity unchanged) |
| broad-exception register gate | 3/3 (no new `except Exception` sites anywhere) |
| bandit src/ | 0 HIGH / 17 MEDIUM / 122 LOW — unchanged from v4 |
| literal `pip check` | exit 0 |
| dependency closure audit | CLEAN — 0 open findings, 1 accepted residual (chromadb 1.5.9, 4 advisories, 2.x upgrade = separate sprint) |
| ZIP hygiene gate | PASS (see build block) |

## V5 BUILD BLOCK

* purge of runtime artifacts before packaging (hunt_artifacts, __pycache__,
  .pytest_cache, *.egg-info, runtime DBs, smoke scratch)
* all package mtimes normalized to 2026-10-05 14:00 UTC before archiving
* archive: `WebPent_FINAL_v5_20261005.zip`; hygiene gate PASS
* fresh-extract verification: tree identical to source, frozen gate green
  from the extract, real-browser smoke 4/4 FROM THE EXTRACT

## V5 NON-FINDINGS (attacks that failed — recorded for completeness)

* Chromium Local Network Access (LNA) restrictions do NOT apply to the smoke's
  cross-origin probes: both origins are loopback on the same host (different
  ports only), so no local-network permission gate can mask the leak probes.
* The `keepalive` fetch probe survives page navigation, making the R-05
  cross-origin assertion deterministic rather than racy.
* `build_poc_plan` deliberately REJECTS `data:` finding URLs (http/https only)
  — a data: URL page cannot issue same-origin requests, so a "POC" recorded
  against one would falsely flag the BOLA signature. The smoke therefore uses
  the data: URL at the browser-machinery layer (phase A) and loopback HTTP for
  the full replay (phase B) — the contract stays intact and the gap is closed.
