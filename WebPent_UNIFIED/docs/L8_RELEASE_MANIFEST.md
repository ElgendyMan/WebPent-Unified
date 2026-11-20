# L8 Release Manifest

Release: **webpent-l8-independent-application-discovery** (2026-10-26)
ZIP: `webpent_l8.zip`, cut with `git archive` from the deliverables
commit (committed content only; the never-committed
`download/econ/portfolio_transitions.jsonl` is structurally excluded
because it is not in the repository). The archive cannot contain its
own digest; the SHA-256 of the final zip is published alongside the
release.

## Commit inventory (L8, oldest first; L7 release HEAD was 73b8484)

```
ebdeb92 docs: L8 §1 reproduction — complete gate log and manifest digest corrections
f30100b egaie: L8 §1 — L7 reproduction: gates, 144-run matrix re-verified;
        trace instrumentation fixed with red-first test; metric units documented
e0788fb appsuite: L8 §2 — generation-2 independently implemented applications
e9cf069 egaie+appsuite: L8 §2 — engine-wire integration fixes
782b3fc egaie: L8 §5 — probe each family across distinct resources (capped)
5b85ee9 egaie: L8 §4/§5 — discovery-v2: declare the checkout defect per resource
a106f31 egaie: L8 §3 — discovery-efficiency matrix runner + post-fix DEV block
df4de06 egaie: L8 §3 — HELD-OUT block measured once, after DEV analysis frozen
b3813cf docs: L8 §5 failure analysis — scoped-defect miss, fix, v2 correction,
        held-out gaps
2263f69 egaie: L8 §4 + §2 — labsuite scorer dedups per defect; appsuite
        isolation tests pinned as tests
9486f30 docs: L8 deliverables — §6 document with budget-matched tables,
        metric units, independence evidence, evidence statement
+ deliverables commit (docs: L8 release manifest and final gate log)
```

## Key file digests (SHA-256)

| file | sha256 |
|---|---|
| `src/webpent/egaie/differential.py` | `aa79fe929e9d47681eb61f6f633acbf1f7043e81fc57bce070eddeaddaf0053a` |
| `src/webpent/egaie/discovery_ground_truth.py` | `7c079920e96b8c07e9809608b04876fe806670f04bf58c7419aecb242eebc73f` |
| `src/webpent/labsuite/evaluator.py` | `a18294d64794734fb0b968b0b9fb19489e06464bc9f5ba199af49f77a5622029` |
| `src/webpent/appsuite/docvault.py` | `e74555925f900c928be48029615dd00418549d6048d014f1a28bac7d875e370c` |
| `src/webpent/appsuite/market.py` | `100af3eeae765e3983340171fba95f3d64f33123d9eb428b3967da64103db265` |
| `src/webpent/appsuite/ticketflow.py` | `1f174d18230961c90e17f3ff8da890bb7d31a3c9d416f0d50399822a0a7a98b2` |
| `src/webpent/appsuite/slots.py` | `59f1eb5e9c169b503663223b6e5a1412b0e84f9b2619a47a1bf1c2fbbe8d60cd` |
| `src/webpent/appsuite/groundtruth.py` | `28670c79e5cb9f5bd5da222dba0d458f3989d5a65ef482c8bce69b808411cc5c` |
| `src/webpent/appsuite/corpus.py` | `70c59e714d684fc9fb564cf3f555aa687ecb360a97030a8e9b27061d27ae60ff` |
| `scripts/l8_discovery_matrix.py` | `c110b66af85e693ac7daa0cae8fcb872b1be38d461973b28a89bba52b2a30a26` |
| `docs/l8_discovery_dev.json` | `7a4e29f3f240dbe8d17720ff25a2e21a39785972cceb98da1808b670bfea6675` |
| `docs/l8_discovery_heldout.json` | `ad3e074f73f720e6d4dd207502a417f912354593321dfe408af8b12fcceb489c` |
| `docs/L8_FAILURE_ANALYSIS.md` | `2dddbe50ebea79be77d9ca043f209874ea932789fb0af2b9898249c3b98d38be` |
| `docs/L8_REPRODUCTION.md` | `18fd4fca5762d28f8a0a171832e32401837f793af8d65efc827ab70436db68e3` |
| `docs/l8_gate_logs/gate_run_20261026T163316Z.log` | `6be314c54d968fc4e9a34bb82b4a0493fe72e5450fb618525a80bafe70164cf2` |

## Final gate (at this deliverables commit)

`docs/l8_gate_logs/gate_run_20261026T163316Z.log`: full `make ci` at
commit 9486f30 — 4491 passed, coverage 62.01% (floor 35%), lint all
checks passed, bandit high-severity clean, both authority gates OK
(GATE_OK). The earlier run `gate_run_20261025T214601Z.log` recorded
the one failure (labsuite price tp==3) that forced the §4 scoring
dedup now in place; the corrected suite passes in the final log.

## Changed-file inventory (L8 vs L7 release HEAD 73b8484)

Added: `src/webpent/appsuite/{corpus,groundtruth,docvault,market,
ticketflow,slots}.py`, `tests/appsuite/test_discovery.py`,
`tests/appsuite/test_isolation.py`, `scripts/l8_discovery_matrix.py`,
`docs/l8_discovery_dev.json`, `docs/l8_discovery_heldout.json`,
`docs/L8_REPRODUCTION.md`, `docs/L8_FAILURE_ANALYSIS.md`,
`docs/L8_DELIVERABLES.md`, `docs/L8_RELEASE_MANIFEST.md`,
`docs/l8_gate_logs/*`, `webpent_l8.zip.sha256` (published alongside
the release).

Modified: `src/webpent/egaie/differential.py` (stall fix; §5
multi-resource probing; constants), `src/webpent/egaie/
discovery_ground_truth.py` (discovery-v1 → v2), `src/webpent/
labsuite/evaluator.py` (§4 per-defect dedup),
`tests/egaie/test_differential_discovery.py` (v2 counts).

## Sequencing attestation

DEV block was measured before any held-out run; the held-out block
was measured once, after the DEV analysis and the §5 fix were
committed (`df4de06`), and no engine change has followed it.
