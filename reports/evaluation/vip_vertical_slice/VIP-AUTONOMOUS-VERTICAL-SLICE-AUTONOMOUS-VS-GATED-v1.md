# VIP Autonomous Vertical Slice v1 — Autonomous vs Gated Work

## Autonomous and reversible within the current policy

| Work item | Current disposition | Evidence path |
|---|---|---|
| Safe local code changes | Allowed when bounded, reviewed, and reversible | Vertical slice commit and regression suite |
| Offline contracts and tests | Allowed | `tests/test_vip_vertical_slice.py` |
| Loopback GET-only observation | Allowed | Local runner Juice Shop campaign |
| Mock/local fixture improvement | Allowed when target-local and explicitly injected | Fixture campaign before/after |
| Redaction and neutrality checks | Allowed | Allowlisted observations and safety invariants |
| ProofBundle build/seal/verify/replay | Allowed | Common `ProofBundle` path |
| Failure diagnosis and improvement proposal | Allowed | Orchestrator lifecycle and case report |
| Hash/provenance/report regeneration | Allowed | Release workflow |
| Rollback and local retest | Allowed | Improvement record and test evidence |

## Gated work requiring explicit Owner Approval

| Work item | Current status | Why it remains gated |
|---|---|---|
| Opening Official P10 run gate | Not executed | Official isolated run authorization is false |
| Changing P10/VIP thresholds | Not executed | Thresholds are policy-controlled |
| Editing frozen Ground Truth | Not executed | Frozen evidence must not be changed to fit implementation |
| Credentials, login, OTP/MFA/CAPTCHA | Not executed | Outside the current no-credential local contract |
| State-changing or destructive action | Not executed | Current method policy is read-only |
| Expanded authorization or scope | Not executed | Current origin is loopback-only |
| External targets or Bug Bounty | Blocked | No external authorization is present |
| P10/P9/VIP qualification declaration | Not executed | Required cases, classes, isolated runs, and final review are incomplete |

## Decision Packet contract

When a gated path is encountered, the orchestrator records a pending packet containing `decision_requested`, `why_needed`, `evidence`, `options`, `risk`, `affected_files_or_commits`, `rollback`, and `recommendation`. The packet is an evidence request, not approval. `human_independent_signoff_obtained` remains false, silence is not approval, and the runner does not continue through the gated branch.

## Current decision

No Owner Approval is requested for the local vertical slice delivered in this cycle. The fixture improvement is target-local, bounded, reversible, and non-scoring. The non-local improvement regression demonstrates the blocked path and produces `pending_owner_approval` without invoking a change handler. Any future request to promote cases, alter policy, or open official execution must produce a separate owner decision packet and wait for explicit approval.

_End of governance boundary record._
