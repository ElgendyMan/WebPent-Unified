# Multi-Target Scoring Readiness Matrix v1

## Decision scope

This pack is a bounded local readiness assessment for OWASP Juice Shop, OWASP WebGoat, and crAPI. It does not open Official P10, contact an external target, use credentials, submit mutations, or make a qualification claim. Route reachability, HTTP status, lesson completion, and health responses are observations only and are never vulnerability verdicts.

| Target | Source revision | Runtime scope | Independent ground truth | Approved causal cases | Approved classes | Quality metrics | Readiness decision |
|---|---|---|---|---:|---:|---|---|
| OWASP Juice Shop | `1618a611b173b4bf114028e6e02549950606e29d` | `http://127.0.0.1:3000`, GET-only/allowlisted workflow | Available and frozen; oracle review accepts a partial subset | 3 | 3 | Baseline evidence exists for all 3; official metrics withheld | Partial scoring-ready; not P10-ready |
| OWASP WebGoat | `7517acca95d9851da706452454c223dd13545ef4` | `http://127.0.0.1:8080`, GET-only loopback scope | Not admitted in this cycle | 0 | 0 | Withheld; no valid GT/oracle contract | Blocked pending target-local package and safe causal contracts |
| crAPI | `73d309cc8f28bbdeed31dbb35f05dba8354de3c9` | `http://127.0.0.1:8888`, GET-only loopback scope | Not admitted in this cycle | 0 | 0 | Withheld; no valid GT/oracle contract; compose uses mutable `latest` | Blocked pending immutable runtime provenance and target-local package |

## Required evidence matrix

| Requirement | Juice Shop | WebGoat | crAPI |
|---|---|---|---|
| TargetSpec and authorization boundary | Present in adapter/manifest and local manifest | Present for lifecycle-only validation; no scoring adapter | Present for lifecycle-only validation; no scoring adapter |
| Version/source manifest | Present; source revision fixed; package `20.2.0` recorded | Source revision fixed; project version `2026.2-SNAPSHOT` | Source revision fixed; image digest not admitted; compose references `latest` |
| Independent ground truth | Present; frozen mapping plus source snapshot | Missing/not admitted | Missing/not admitted |
| Approved case IDs | `juice.error_handling.v1`, `juice.exposed_metrics.v1`, `juice.local_xss.v1` | None | None |
| Causal oracle contract | Present for the three cases only | None admitted | None admitted |
| Safe precondition | Proven for the three bounded workflows | Not established for any scoring case | Not established for any scoring case |
| Independent negative control | Present for the three cases | Not run for scoring; no admitted case | Not run for scoring; no admitted case |
| Central verifier mapping | Present through target adapter and semantic profiles | No scoring mapping | No scoring mapping |
| Sealed/replayable ProofBundle | Present for the three baseline cases; seal and replay passed | None | None |
| Regression suite | Existing generic and Juice Shop tests pass | Generic tests only; target package absent | Generic tests only; target package absent |
| Baseline → diagnosis → proposal → implementation → retest | Completed historically for the current three-case adapter state; no new generic change required | Not applicable because zero cases are admitted | Not applicable because zero cases are admitted |
| Before/after comparison | Existing lifecycle classification improvement only; no new causal case was promoted | No scoring comparison | No scoring comparison |

## Interpretation

The only current target with any scoring-ready evidence is the three-case Juice Shop subset. Its baseline is **not** an official P10 run: the evaluator correctly withholds precision, recall, case coverage, and class coverage until the complete approved set and required isolated runs exist. WebGoat and crAPI remain readiness blockers, not clean targets and not failures of the generic orchestrator.

The current formal P10 gap remains **7 additional approved cases and 3 additional classes** beyond the current Juice Shop 3/3 subset, plus three valid isolated official runs and final independent review. No observation-only, inconclusive, blocked, or out-of-scope row may close that gap.

## Safe next gates

A WebGoat or crAPI case may move into scoring readiness only after a target-local adapter/profile supplies a source-backed semantic predicate, independent ground-truth admission, safe precondition, independent negative control, central verifier mapping, and sealed/replayable proof procedure. For crAPI, the runtime image must also be pinned by an immutable digest before any reproducibility claim. Any request for credentials, mutation, external callbacks, frozen-ground-truth modification, policy/threshold change, or Official P10 authorization requires a separate Owner Decision Packet and remains blocked.
