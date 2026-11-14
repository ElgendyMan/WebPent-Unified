# Round-3 War Games — emulator (WG4) and rehearsal (WG6)

_Date: 2026-10-18. Executed with real PoCs against the running configs
and source trees; the host ModSecurity mutation tests ran against the
local stack and were restored afterwards (verified: 403 on SQLi, 5/5 WAF
tests passing)._

## WG4 — Emulator escape

Could the training range leak out of the machine it runs on?

- **Compose audit (structural)**: 6 services; **all 6 published ports
  bound 0.0.0.0** (e.g. `ports: ["3000:3000"]`). On a connected laptop,
  the DVWA/juice-shop/WAF/monitoring services are reachable from the LAN.
  → **F-6 CONFIRMED (MEDIUM).**
- **Monitoring dashboard and custom API**: both hardcode
  `HTTPServer(("0.0.0.0", port))` — same exposure, and the dashboard
  serves probe IPs and payloads from shared logs, so the leak includes
  attacker-observable state.
- **Privilege audit**: no `privileged: true`, no `docker.sock` mounts, no
  host path mounts anywhere in the compose file. The only capabilities
  are `NET_ADMIN`/`NET_RAW` on fail2ban, which are functionally required
  for its firewall rules and are documented as such.
- **Behavioral (host stack)**: mutating `/etc/modsecurity/modsecurity.conf`
  paranoia 2 → 1 while the 5-test WAF suite stayed green — the suite could
  not see a behavioral change. → **F-7 CONFIRMED (LOW).** Then mutating
  `SecRuleEngine On → DetectionOnly`: behavior changes (attacks pass),
  suite still green. Restored from backup and re-verified after the test.

## WG6 — Playbook poisoning

Could a poisoned playbook or report corrupt a future campaign?

- **Attack**: seeded hostile entries into the lessons store (an
  out-of-scope target, an FP recorded as confirmed, an instruction-like
  string) and regenerated the playbook; ran dry-run and pilot report
  generation over the poisoned state.
- **Result — BLOCKED at three levels**:
  1. `run_real_pilot.py` refuses to run without a verified, registered
     target with legal review and safe harbor; the poisoned
     out-of-scope entry cannot pass target validation (forbidden keys and
     https-only checks also hold).
  2. Dry-run/pilot outputs are labeled **NOT a capability proof** at the
     top of every report, so a poisoned run cannot be presented as a real
     result.
  3. Report scan of playbook/dry-run/pilot outputs: **no PII, no emails,
     no real exploit code** in any generated report.
- The lessons store itself is additive and versioned; regeneration is
  deterministic from state, so deleting the poisoned seed removes it from
  the next build (no hidden persistence).

## What this document hands to the fix phase

| ID | Severity | One line |
|---|---|---|
| F-6 | MEDIUM | all 6 emulator services and both Python dashboards bind 0.0.0.0 |
| F-7 | LOW | WAF tests check strings, not values; behavioral mutations pass the suite |

Both fixed in Round 3: loopback-only binding and the value-aware
`waf_config.waf_problems()` checker (see round3_verdict.md).
