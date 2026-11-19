# WebPent v60 — Smart Autonomous Bug Hunter Phase 6

**Date:** 2026-08-18  
**Target:** `http://127.0.0.1:8000` (local WAPTLab runtime)  
**Profile:** `safe-smart`  
**Qualification output:** `docs/live_waptlab_output_smart_release7/`

## Release gates

The final regression suite completed successfully with **661 passed tests** and no test failures. This remains above the required baseline of 656 passed tests and 537 test functions. Ruff also completed successfully on all modified files.

The only emitted messages were dependency/security warnings already present in the project environment, including development-mode secret warnings, LangGraph/LangChain deprecation warnings, and optional tool availability warnings. They did not fail the release gate.

## Conservative implementation changes

The Smart Hunter now preserves the existing legacy path while enabling bounded safe-smart behavior. `SCAN_PROFILE=safe-smart` is supported as an additive compatibility alias for the scan-mode setting, while the default remains `legacy`.

The graph includes a GET-only Smart Campaign execution path. It is limited to three concrete tasks per execution round, requires same-origin targets, uses the central Action Authority and Campaign Executor, passes the configured User-Agent and session cookies, and records only redacted response metadata. It never sends POST requests, never performs destructive actions, never uses cross-origin targets, and never promotes a hypothesis to a confirmed finding.

The state schema now formally persists `scan_mode`, `smart_governance`, `capability_manifest`, and `action_budget`. This prevents LangGraph transitions from dropping the policy inputs required by the execution authority. Passive crawler endpoint strings are converted into bounded surface records, and the campaign plan is refreshed deterministically when the initial plan has no observed references. Coverage projection and reporter export retain the final campaign execution metadata.

No source file in WAPTLab was modified. Runtime-only container configuration was used to make the local benchmark available, and the WebPent scan remained scoped to the authorized local target.

## Live WAPTLab result

The final live run completed successfully and generated HTML/JSON reports. The result was:

| Metric | Result |
|---|---:|
| Candidate findings | 2 |
| Tool-confirmed findings | 0 |
| High-severity candidates | 1 |
| Medium-severity candidates | 1 |
| Smart campaign count | 20 |
| Smart task outcomes | 42 |
| Redacted HTTP observations | 3 |
| Coverage projection attempts | 42 |
| Blocked by precondition | 17 |
| Inconclusive campaigns | 3 |
| Not observed in campaign ledger | 13 |
| Missing validator campaigns | 7 |

The two candidate rows were:

| Candidate | Classification | Evidence status |
|---|---|---|
| `Potential RCE at /csv/upload` | High, tentative | **Not confirmed**; OOB validation, reproduction, CVSS, and business impact are missing |
| `Potential IDOR at /user_profile/1` | Medium, tentative/clean lifecycle | **Not confirmed**; owner-vs-foreign authenticated proof was not attempted |

The report explicitly states `confirmed_count: 0`. Therefore, the live result must be reported as **2 candidates and 0 confirmed vulnerabilities**, not as two proven vulnerabilities.

## Remaining blockers

The live run still cannot reach the full WAPTLab matrix because browser automation is unavailable, `katana` and `nuclei` are not installed, no OOB callback channel is configured, safe-smart intentionally does not perform POST/active actions, and seven campaign entries have no compatible validator. These are recorded as coverage/precondition limitations rather than hidden or falsely promoted findings.

## Artifacts

The machine-readable live report is available at `docs/live_waptlab_output_smart_release7/report.json`, and the rendered report is at `docs/live_waptlab_output_smart_release7/report.html`. The full release archive is accompanied by a SHA-256 checksum.
