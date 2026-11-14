# AI Independent Technical Review + Owner Approval Policy v1

## Purpose

This policy defines the project operating model for safe autonomous engineering work and explicitly separates non-human technical review from owner-controlled gated actions. It applies to WebPent repository changes, the authorized local Juice Shop loopback lab, target-local adapters and profiles, evidence generation, regression testing, proof sealing/replay, provenance checks, and qualification gates.

## Review authority

The AI agent may perform an **AI Independent Technical Review** of implementation and evidence. This review is attributable to the AI system only and is not a human signature, human identity, legal attestation, or independent human governance signoff. The AI review must state its scope, evidence, commit, hashes, limitations, and unresolved blockers.

The project owner retains approval authority for gated actions. Owner approval must be explicit and recorded; silence, prior permission for routine work, or a technical PASS must not be interpreted as approval for a gated action.

## Work allowed without additional owner approval

The agent may independently perform safe, local, bounded, and reversible work inside the sandbox and authorized loopback lab. This includes diagnosis, Improvement Proposals, target-local implementation, regression tests, local baseline/candidate execution, independent negative controls, central verification, redacted ProofBundle creation, sealing, `verify_seal()`, replay, before/after comparison, hash checks, neutrality checks, safety checks, normal commits, and normal pushes after all applicable gates pass.

The agent must keep all target-specific details in the target adapter/profile. Generic Core changes are allowed only when a cross-target need is demonstrated and the change is covered by generic regression tests. The agent must not weaken a validator, alter a frozen artifact to fit results, or convert an observation into a causal finding.

## Owner-approval gates

The agent must stop only the affected path and prepare a decision packet when an action would do any of the following:

| Gated action | Owner approval required |
|---|---|
| Modify project policy or this governance model | Yes |
| Modify frozen Ground Truth or frozen P10 artifacts | Yes |
| Set `official_isolated_p10_runs_authorized=true` | Yes |
| Start Official P10 Runs | Yes, after all formal prerequisites pass |
| Contact an external target, Bug Bounty, OAST/SSRF endpoint, or public service | Yes |
| Use credentials, sessions, OTP/MFA, CAPTCHA bypass, or personal data | Yes and separately authorized scope |
| Perform destructive or state-changing target actions | Yes and separately authorized scope |
| Declare P10, P9, VIP, or any qualification | Yes, after objective requirements and final review pass |

A decision packet for a blocked gated action must contain the issue, evidence, affected files and commits, available options, risks, rollback plan, and recommendation. The packet must not imply that approval was granted.

## Current project state

The current AI technical review of the Juice Shop packet is complete as a **non-human attributable technical review**. It must not be written into the Governance Packet as a human countersign. The official governance and qualification state remains:

```text
human_independent_signoff_obtained = false
official_isolated_p10_runs_authorized = false
P10 = NOT_QUALIFIED
P9 = NOT_QUALIFIED
VIP = NOT_QUALIFIED
Bug Bounty = BLOCKED
```

The current approved scoring set remains limited to the cases and classes recorded by the authoritative Governance Packet. Blocked, observation-only, and out-of-scope cases must not be counted as TP, FP, or FN and must not be used to inflate coverage.

## Qualification prerequisites

P10 may be considered only after all of the following are objectively evidenced and recorded:

1. At least 10 approved cases.
2. At least 6 approved vulnerability classes.
3. A causal oracle for every approved case.
4. A safe, reproducible precondition for every approved case.
5. An independent negative control for every applicable case.
6. A sealed and replayable ProofBundle for every confirmation.
7. Three valid isolated Official P10 Runs, each with independent run identifiers, workspaces, namespaces, and evidence.
8. Metrics recomputation from retained redacted evidence, including TP, FP, FN, precision, recall, and class coverage.
9. A final qualification decision that is independently traceable to the approved artifacts and run outputs.
10. Explicit owner approval before opening the Official P10 Run Gate or announcing qualification.

Until then, the agent must continue safe coverage analysis and implementation where contracts are genuinely provable, while leaving the run gate closed.

## Change control and rollback

Every implementation change must be made in the correct target-local or generic location, covered by regression tests, recorded in an independent commit, and pushed normally only after the relevant gates pass. Any generated manifest or provenance artifact must be regenerated through its supported generator and must not create a self-hash cycle. If a verification step fails, the failing path is blocked, the cause is documented, and the change is reverted or corrected through a new normal commit; history rewriting, force-push, and silent artifact replacement are prohibited.

## AI review statement

Any review generated under this policy must use wording equivalent to:

> AI Independent Technical Review completed within the stated scope. This is a non-human attributable technical review and is not a human signature, human countersign, or independent human governance approval.
