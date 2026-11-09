# Known Unknowns — updated after Round 3

_Status after the Red Team Round-3 review of the 3 new packages,
2026-10-18. Supersedes the Pre-Verdict Sprint register of the same date;
the verdict packages themselves were the unreviewed layer until now._

## What Round 3 newly verified (with evidence)

- Verdict tool integrity: the state file now carries a recorded SHA-256
  and refuses tampered or forged files (was the CRITICAL hole: a forged
  state.json issued GO).
- Pre-registration is real: predictions and the pre-registration file are
  frozen and hash-verified; verdict issuance refuses a tampered file.
- Evidence integrity: classifications require re-test evidence that
  actually exists in the workspace.
- Selection immutability: the day-14 selection cannot be re-frozen.
- Emulator containment: all services and dashboards bind loopback only;
  no privileged mode, no docker.sock, no host mounts.
- WAF test sensitivity: paranoia/engine values are parsed, so behavioral
  config mutations fail the suite without Docker.
- Submission pipeline: still no auto-submit, no network code (re-verified
  under a full socket blockade).
- Determinism: same state → same metrics hash, 3×.

## The original 7 unknowns — what Round 3 changed

1. **Finding capability on real programs** — UNCHANGED. Round 3 verified
   the tooling that will judge this, not the capability itself. Only the
   pilot can retire it.
2. **FP rate on real targets** — UNCHANGED. (Integrity of the FP-rate
   *computation* is now protected from tampering, but the number itself
   still needs real targets.)
3. **Acceptance rate** — UNCHANGED. Submission recording is now
   tamper-evident, which makes the future number trustworthy.
4. **Emulator parity with the compose stack** — PARTIALLY advanced. The
   value-blind WAF test (a hidden dependency of this unknown) is fixed;
   the two Docker-only tests still need one Docker run on a real machine.
5. **Juice Shop through the WAF** — UNCHANGED (needs the Docker run).
6. **Long-run stability** — UNCHANGED (the 47-day protocol's job).
7. **The real pilot on a real target** — UNCHANGED, but its scorekeeper
   is now trustworthy: the verdict a forged file used to be able to issue
   (WG5.4) can no longer be forged.

## Net effect

Round 3 did not retire any of the 7 unknowns by itself; what it did is
make the instruments honest. Before this round, a tampered workspace
could have made unknowns 2, 3 and 7 report a GO that nobody could
distinguish from a real one. Now the tools that will answer the unknowns
can detect their own tampering — the unknowns themselves are retired
exactly where the original register said: one Docker run (4, 5), the
pilot kit (7), and the 47-day protocol (1, 2, 3, 6).
