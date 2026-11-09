# The Accountability Spine — central proposal for the ultimate autonomous bug hunter

_Date: 2026-10-18. Written after the Part-1 verification pass (see
docs/verification_round4.md). This is the single central enhancement
requested: one coupling that changes what the system IS, not ten small
improvements._

## The gap the verification pass exposed

Everything in the project works, and almost nothing holds the hunter
accountable to its own scorekeeper. The picture after Part 1:

- The production spine runs the full AVI lifecycle and ends every
  campaign at a `SecurityReport` — a self-assessment written by the same
  system that did the hunting.
- The Verdict Protocol (47-day honest adjudication: day-0 predictions,
  day-14 selection, day-46 GO/NO-GO) is the project's own answer to
  "how do we know the numbers are real" — but it is a hand-fed island.
  Nothing wires campaign results into a verdict workspace. grep across
  `src/webpent/` finds zero references to the verdict package.
- The emulator is a training range that nothing is required to pass
  before a capability is turned loose on a real target.
- The Known Unknowns Register says it directly: unknowns 1-3 and 7
  (real capability, FP rate, acceptance rate, the pilot) are retired
  only by the 47-day protocol — which cannot run if nobody feeds it.

The hunter today can run forever without ever being scored. That is the
one structural gap between what exists now and an ultimate autonomous
bug hunter: not more scanners, not more hypotheses — accountability
that closes the loop.

## The proposal: make the verdict workspace the campaign's accountability layer

Four couplings, one new bridge module, fail-closed by default:

1. **Pre-flight gate.** An authorized-active AVI campaign against a
   non-loopback (real) target refuses to start unless a verdict
   workspace exists at the configured path AND its pre-registration is
   frozen (day-0 predictions recorded and hash-sealed). The hunter must
   state its predictions before it hunts — the core discipline of the
   protocol, now enforced by the dispatch path itself. Loopback targets
   (the emulator, localhost test stacks) are exempt: training does not
   need a scorekeeper, real engagements do. A test-only environment
   escape exists (`WEBPENT_REQUIRE_VERDICT_PREREG=0`) and is recorded
   in the trace whenever used.

2. **Auto-registration bridge.** At campaign end, every PROMOTED
   finding is registered into the verdict workspace through the verdict
   tool's CLI, invoked as a subprocess with the repo's `verdict/`
   directory on PYTHONPATH. Zero imports of the verdict package: the
   Round-3 isolation guarantee survives by construction, and the
   package checksums do not move. Each finding's evidence (promotion
   decision, bundle id, seal digest, proof trace, security-report
   extract) is written as a JSON evidence file inside the workspace, so
   the F-4 evidence-existence check is satisfied with real artifacts
   and the day-14 re-test has something to verify.

3. **Classification stays human.** The bridge registers and attaches
   evidence; it never classifies. Classification, day-14 selection and
   the day-46 verdict remain the operator's moves — the protocol's
   immutability guarantees are exactly what makes automated registration
   safe to add.

4. **Run record + trace.** The campaign result records what the bridge
   did (registered ids, evidence paths, workspace path, gate decisions)
   in the runtime trace, and the bridge refuses silently-zero
   registration: a campaign against a gated target that promoted
   findings but registered none is recorded as a typed blocker in the
   trace, not a clean pass.

## Why this is the central one

It converts the project's strongest unused asset (an adversarially
hardened, tamper-evident adjudication protocol) from a document into
the hunting loop's conscience. After this coupling: every real-target
campaign has frozen predictions, every promoted finding lands in an
immutable ledger with real evidence, and the numbers the Known
Unknowns Register needs (FP rate, capability, acceptance) start
accumulating as a side effect of hunting instead of a manual ritual.
Everything else on the roadmap (better recall, more families, smarter
selection) makes the hunter find more; only this makes the hunter's
claims trustworthy at scale.

## Implementation plan (executed in the same session — see Part 4 log)

- **P1 (red):** `tests/test_verdict_bridge.py` — failing tests for the
  gate (no workspace / unfrozen prereg / loopback exempt / env escape
  traced) and the bridge (register via subprocess, evidence files
  written, no-import isolation, duplicate-id safety, blocked-run
  trace).
- **P2 (green):** `src/webpent/production/verdict_bridge.py` — new
  module: `verdict_preflight()`, `register_campaign_findings()`,
  severity/score mapping, evidence packaging.
- **P3 (wiring):** two marked touch points in
  `modern_spine.py::run_autonomous_validation_campaign` — pre-flight
  gate before the loop, registration after the report. Fail-closed,
  escape recorded in trace.
- **P4 (seal update):** new SHA-256 for `modern_spine.py` recorded in
  the isolation register with an explicit note that the Round-3
  zero-touch rule was superseded by this directive for these two
  marked touch points only.
- **P5 (verify):** full suite green, verify_all.py 145/145, three
  package suites green, docs updated, fresh ZIP.

## Honest limits, stated up front

- The gate reads the verdict workspace's `state.json` and its recorded
  SHA-256 directly (no import). It detects the same tampering the
  tool's own loader detects — accidental edits and naive rewrites —
  and inherits the same documented limit: a determined local attacker
  with filesystem control defeats an unkeyed hash; the operator's VCS
  remains the second seal.
- Registration requires the verdict tool's CLI to be runnable in this
  environment (it is: `python -m verdict_tool.cli`, 60 tests green).
  If the subprocess fails, the bridge records a blocker and the
  campaign result carries it; it does not fabricate a registration.
- This coupling does not retire any Known Unknown by itself. It builds
  the pipe that lets the 47-day protocol retire them.
