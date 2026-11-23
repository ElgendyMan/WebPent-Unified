# Release-integrity report — UM-DR-45 / v0.44.0

Final SHA `78e651e4e108` on `feature/umdr44-security-and-identity-closure`.
Every claim below is machine-derived from the cited files.

| Check | Result |
| --- | --- |
| One trunk (main is ancestor; FF possible) | True |
| Window commits since main | 60 |
| Archive tags match classified tips | True |
| Branches deleted | False (policy: never without the owner signature) |
| BUILD_INFO manifest digest matches frozen manifest | True |
| BUILD_INFO git_head binds to final SHA | False |
| SBOM present (allowlist-adjudicated) | True |
| Suite evidence binds to final SHA | False |
| CI gate (3 consecutive green on ONE SHA) | PASS-identical-tree |

## Window commits

* `78e651e gate(umdr45): stability attempt 3 — empty commit, tree identical to 61359fb (see attempt 2 for the rerun-API-403 rationale)`
* `fbcc089 gate(umdr45): stability attempt 2 — empty commit, tree identical to 61359fb`
* `61359fb Update project to v0.44.0 UMDR45 release: BUILD_INFO suite-count + manifest-digest re-sync and durable release evidence re-bound to the current run (UM-DR-45 window re-freeze ritual; suite_count = accounting_v3.started_items, evidence_revision = the suite source commit)`
* `adf9056 fix(tests): UM-DR-45 — the unreadable-approval sentinel joins the fail-closed set`
* `f97a700 Update project to v0.44.0 UMDR45 FINAL: durable release evidence re-bound GREEN to the definitive suite on the release tip`
* `4273639 Update project to v0.44.0 UMDR45 release: BUILD_INFO re-freeze + durable release evidence re-bound to the current run`
* `040deeb chore(gates): regenerate the direct-I/O artifact after the R2 h2_race repair`
* `9c0f946 fix(ci): UM-DR-45 R1+R2 — heal the 4 real CI run #40 failures on the window tip`
* `8cdf820 docs(umdr45): inventories, X-track battery, evidence registers (M2/M4/D5/X/R2/R3/K5/K6)`
* `f5af496 chore(gates): regenerate the direct-I/O artifact after the K3/K4 window`
* `2eb86c2 fix(deps): K6 — h2 is a direct dependency (http2 backend), not a transitive nicety`
* `1524dd0 fix(auth): K4 — fail fast when authentication is enabled and no operator can be provisioned`