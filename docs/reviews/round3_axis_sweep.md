# Round-3 Nine-Axis Sweep — the 3 new packages

_Date: 2026-10-18. Axes in the order the plan named them; the authority
axis is first among equals and got the deepest pass._

## Axis 3 — Authority escalation (the most important axis)

Question: can any of the 3 packages act on its own authority — network,
shell, or escalation past the operator?

- verdict: grep for `requests|urlopen|socket|subprocess|Popen` across
  `verdict_tool/` → only `targets.py::_http_head` (one HEAD to the
  program URL, operator-invoked, isolated and patched in tests). The
  submission pipeline has none. No `os.system`, no shell.
- emulator: network-capable **by design** (it simulates targets) but
  after F-6's fix, loopback-only; no docker.sock, no privileged mode.
- rehearsal: dry-run/pilot are explicit scaffold scripts that require an
  existing registered target and print NOT-a-capability-proof banners.
- **Escalation-past-the-operator**: no path found. The forged-GO attack
  (WG5.4) was the closest thing to authority escalation — the tool
  declaring the operator's job done on forged data — and it is now
  blocked by F-1's integrity check.

## Axis 1 — Claims vs reality

Every load-bearing claim was tested: immutability of classifications
(holds), no-network pipeline (holds), determinism of metrics (holds,
3× identical hashes), pre-registration checked on day 46 (was false —
rewriting was possible, F-2/F-3), emulator containment (was false,
F-6), WAF paranoia 2 (true in config, untestable by the old suite,
F-7).

## Axis 2 — Security vulnerabilities

The 7 findings F-1..F-7 (see the war-game documents). Post-fix residual
risk is stated in round3_verdict.md, including the honest limit that the
integrity hash is unkeyed and does not stop a determined local attacker
with filesystem control — the second seal is the operator's own VCS.

## Axis 4 — Determinism

Same state → same metrics report hash three consecutive runs
(`534935b16b506e31…` each time). Playbook regeneration is deterministic
from its lessons state. The only nondeterminism left is timestamps, which
are recorded, not computed into outcomes.

## Axis 5 — Evidence fragility

F-4 was exactly this axis: evidence as unverified free text. Fixed: paths
must resolve to files inside the workspace. Remaining fragility (a real
screenshot of the wrong thing) is inherently a human-review problem and
is documented, not solvable in code.

## Axis 6 — Real-target exploitability

The packages do not and cannot run exploits; the rehearsal pilot runs
against a target already validated by targets.py (legal review, safe
harbor, https-only, rate ceiling ≤ 50 rps). No uplift to attacking a
real target exists in these packages.

## Axis 7 — Trust-spine violations

No core imports, no core edits (checksum-verified), no new features
beyond the fixes themselves, suite count raised not lowered, all
generated reports keep the NOT-a-capability-proof labeling.

## Axis 8 — Missing tests

Before this round: nothing tested tampering, freezing, evidence
existence, selection immutability, or WAF values. Added:
`tests/test_round3_fixes.py` (verdict, 8 tests) and
`tests/test_round3_fixes.py` (emulator, 5 tests incl. the mutation
sensitivity trio), plus the value-aware rewrite of
`test_waf.py::test_paranoia_level_2`.

## Axis 9 — Doc vs code

`verdict/docs/verdict_protocol.md` claimed classifications immutable
(true) and pre-registration on day 0 checked day 46 (true only after the
fix). Docs updated where the fix changed behavior: freeze semantics,
integrity record, loopback-only binding. The doc-vs-code drift found was
fixed in code and reflected in docs; no claim in the docs is now
unverified.

## Mutation testing (evidence the new tests bite)

- `metrics.py` decision table mutated `accepted >= 3 → >= 4` → 2 tests
  failed. Table restored.
- `configs/modsecurity.conf` mutated paranoia 2 → 1 → old suite stayed
  green (that WAS finding F-7); new value-aware tests fail on the same
  mutation. Config restored.
- `SecRuleEngine On → DetectionOnly` → new tests fail. Restored.
