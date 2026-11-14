# Round-5 Central Proposal — The Re-test Dispatch Engine

_Date: 2026-10-19._

## The gap (verified against the code, not assumed)

The Accountability Spine (Round 4) closes the FIRST half of the verdict
protocol's life with a campaign: pre-flight gate in, promoted findings
registered out, evidence written. What it does not close is the protocol's
decisive moment: the re-test. Today:

1. The registered evidence (evidence/<id>.json) records THAT a finding was
   promoted (bundle id, seal digest, promotion decision) but not HOW to
   re-execute it. Fourteen days later the operator must reconstruct the
   baseline/candidate/negative-control triple by hand from the report.
2. The re-test itself is fully manual: nothing in the project can re-run
   the triple against the target with fresh state and leave the evidence
   files the verdict CLI's `findings classify` requires.
3. The gap is real in the data: AVI's promoted findings DO carry
   `request_sequence` (role, method, url per request — the recipe exists at
   promotion time) and the bridge drops it on the floor.

The 47-day protocol's unknowns 1, 2, 3 and 6 all resolve through re-tests.
A hunter that cannot re-test its own findings is a one-shot scanner.

## The proposal

Complete the spine's second half, inside `verdict_bridge.py` only — zero
touch on the webpent core (no new touch points in `modern_spine.py` or
`profile.py`), zero touch on the three isolated packages:

- **P1 — Recipe capture.** The evidence payload gains `replay_recipe`:
  the role/method/url triple extracted from the promoted finding's
  `request_sequence`, plus experiment id and vulnerability class. A
  finding without a usable sequence gets `replay_recipe: null` — never a
  fabricated one.
- **P2 — `dispatch_retest`.** A bridge function that reads registered
  evidence files from the workspace, re-executes each recipe's triple
  through an EXECUTOR SUPPLIED BY THE CALLER (the operator's authorized
  transport; the bridge itself performs no network I/O of its own — its
  direct-I/O surface does not grow), writes `evidence/<id>.retest.json`
  with per-role observations (status code + SHA-256 response digest), and
  returns a summary.
- **P3 — Fail-closed and honest.** A non-loopback re-test target requires
  the same frozen pre-registration the campaign gate requires (reuse of
  `verdict_preflight`); the escape stays never-silent. A missing recipe,
  an executor failure, an unreadable evidence file — each is a typed
  blocker; nothing raises into a partially dispatched batch.
- **P4 — The machine never classifies.** The retest evidence records
  OBSERVATIONS and one coarse, clearly-labeled signal
  (`candidate_differs_from_baseline`). The word `classification` never
  appears in what the bridge writes, and the bridge never invokes
  `findings classify`. Instead the summary hands the operator a
  ready-to-run classify command per finding with the classification,
  severity and impact left as the operator's fills-in — that separation
  is the protocol's anti-self-confirmation seal and it does not move.
- **P5 — Verification.** Red-first tests (~12), full suite, verify_all,
  package suites, inventory drift check (expected: no drift — no new I/O
  sites), fresh-extraction ZIP.

## Why this is the central one

Round 4 made the campaign feed the scorekeeper. This makes the scorekeeper
judgable: registration → recipe → re-execution → evidence → operator
classification becomes one unbroken, tamper-evident chain. It is also the
last coupling the three-package architecture needs: verdict (scorekeeper),
emulator (range), rehearsal (training) all now connect to the loop through
the same bridge without a single import between packages.

## Honest limits

The reproduce signal is a transport-level observation, not a causal
verdict; the validator's semantics are not re-run by the bridge. The
executor is as trustworthy as the caller's client. Day-14 timing and the
select/submit/verdict commands remain operator moves by design.
