# Owner Decision Packet — Controlled Authorized Causal Lab v1

**Packet ID:** `LOCAL-CAUSAL-LAB-OWNER-DECISION-v1`
**Status:** `PENDING_OWNER_APPROVAL`
**Author:** **Manus AI — non-human attributable technical review**
**Date:** 2026-08-27

## Executive decision request

This packet requests an explicit owner decision on whether to open a **narrow, disposable, loopback-only causal lab** for selected WebGoat and crAPI cases. It is a request for authorization of a bounded local experiment only. It is **not** authorization for Official P10, Bug Bounty activity, external targets, qualification, policy changes, frozen Ground Truth changes, threshold changes, or Generic Core relaxation.

The project goal remains **VIP Autonomous Bug Hunter**. P10 is treated as one evidence gate on that path, not as an independent end goal. No credentials, login, state mutation, payload execution, or live causal test has been performed under this packet. Silence is not approval; execution must not begin until the owner records a decision with exact Targets, case IDs, methods, and expiry.

## Current governance state

| Control | Current state |
|---|---|
| `official_isolated_p10_runs_authorized` | `false` |
| Human independent signoff | `false` |
| P10 | `NOT_QUALIFIED` |
| P9 | `NOT_QUALIFIED` |
| VIP | `NOT_QUALIFIED` |
| Bug Bounty | `BLOCKED` |
| Current Juice Shop set | 3 cases / 3 classes |
| P10 minimum | 10 cases / 6 classes |

The current state is unchanged by this packet. No blocked, observation-only, or out-of-scope candidate is counted as TP, FP, FN, clean, or confirmed.

## Immutable provenance

The source-backed inventory is the authority for the candidate list, source revisions, and source-evidence hashes [1]. Its SHA-256 is `88849d5a4df55e473ed4a230218db330127e7cad15b92caf6dd6898d56874aac`. The machine-readable packet is [2], with SHA-256 `8ddeabaebe0696feb77c7de0fe553e18436eee24205a7e2bb4031ab51037963a`.

| Target | Source revision | Runtime/version constraint | Ground Truth state | Decision implication |
|---|---|---|---|---|
| OWASP WebGoat | `7517acca95d9851da706452454c223dd13545ef4` | Source build requiring Java 25 | Not admitted for scoring | A separate lab GT must be created and approved; it must not modify the frozen or scoring GT. |
| crAPI | `73d309cc8f28bbdeed31dbb35f05dba8354de3c9` | Compose currently uses `VERSION=latest`; immutable image digest is not admitted | Not admitted for scoring | Pin every image by digest or immutable build digest before reproducibility admission. |

The source revisions identify the checked-out source only. They do not by themselves establish a vulnerability, causal oracle, or reproducible runtime.

## Proposed authorization boundary

| Boundary | Proposed rule |
|---|---|
| Network | Bind and connect only to `127.0.0.1`; no public IP, DNS, external callback, OAST, redirect following, or internet service. |
| Runtime | Use pinned source and runtime/image digests; stop on any digest drift. |
| Data | Disposable database/fixture snapshot with synthetic canaries only. No real accounts, emails, passwords, tokens, OTP, MFA, or user data. |
| Evidence | Store typed metadata, hashes, verifier decisions, and redacted proof references only. Never persist raw bodies, cookies, authorization headers, tokens, passwords, or raw canary contents. |
| Methods | Only the exact method list approved per case. A method not listed in the owner decision is prohibited. |
| Reset | Restore a disposable snapshot between candidate/control pairs and between runs. A reset endpoint is not a permitted shortcut. |
| Promotion | No lab result promotes scoring until every GT/oracle/precondition/control/verifier/proof gate passes. Lab approval does not open Official P10. |

## Target and case scope

The following cases are **proposals**, not approvals. The `lab disposition` column describes what may be considered for owner authorization; it does not authorize execution.

### WebGoat

| Case ID | Class | Current inventory decision | Proposed methods | Proposed lab disposition | Main causal requirement |
|---|---|---:|---|---|---|
| `webgoat.idor.view_other_profile.v1` | Broken Access Control | blocked | GET | Candidate for narrow approval | Cross-user owner-specific canary disclosed to requester B, while B-own and nonexistent-object controls do not disclose it. |
| `webgoat.path_traversal.v1` | Path Traversal | blocked | GET | Candidate for narrow approval | Only an approved synthetic canary file is resolved under the vulnerable condition; authorized/sibling/invalid controls remain inaccessible. |
| `webgoat.stored_xss.comments.v1` | XSS | blocked | POST + GET | Candidate only with explicit mutation approval | Stored marker reaches an approved local DOM sink/execution observation while benign encoded control remains inert. |
| `webgoat.sql_injection.advanced.v1` | Injection | blocked | PUT | Candidate only with explicit mutation/payload approval | Differential unauthorized row selection using a narrowly allowlisted non-destructive query; parameterized control remains safe. |
| `webgoat.ssrf.task1.v1` | SSRF | out_of_scope | GET | Deferred out of scope | Would require external/OAST/callback evidence under the current boundary. |
| `webgoat.csrf.get_flag.v1` | CSRF | out_of_scope | POST | Deferred out of scope | Cross-site state-changing behavior is outside the currently proposed boundary. |

### crAPI

| Case ID | Class | Current inventory decision | Proposed methods | Proposed lab disposition | Main causal requirement |
|---|---|---:|---|---|---|
| `crapi.profile_video_object_access.v1` | Broken Access Control | blocked | GET | Candidate for narrow approval | Synthetic user B receives A-owned canary object metadata while own/nonexistent controls do not. |
| `crapi.vehicle_location_bola.v1` | Broken Access Control | blocked | GET | Candidate for narrow approval | B receives A-owned synthetic location canary while own/nonexistent controls do not. |
| `crapi.community_post_object_access.v1` | Broken Access Control | blocked | GET | Candidate for narrow approval | B receives A-owned private canary field while own/nonexistent controls do not. |
| `crapi.mechanic_report_object_access.v1` | Broken Access Control | blocked | GET | Candidate for narrow approval | B receives A-owned report canary while own/nonexistent controls do not. |
| `crapi.coupon_validation.v1` | Business Logic | blocked | POST | Deferred pending separate mutation decision | Requires a reviewed stateful business invariant and mutation-safe reset. |
| `crapi.login_with_token.v1` | Authentication | out_of_scope | POST | Deferred credentials boundary | Requires explicit local authentication/token protocol and a dedicated oracle. |
| `crapi.reset_test_users.v1` | State Management | out_of_scope | POST | Rejected for this lab | Explicit state-changing/destructive reset; snapshot restore is required instead. |

## Synthetic identity and state/reset model

If the owner approves a case requiring authentication, the lab will create only opaque synthetic identities such as `test_subject_a` and `test_subject_b` inside a disposable local database or fixture. These identities must not map to real people, real email addresses, or existing accounts. Cross-user cases require a precise ownership relation: subject A owns the canary object and subject B is the requester.

The lab will start from an immutable source/runtime snapshot and a disposable data snapshot. Each candidate/control pair will record a pre-run state hash, restore the snapshot, execute the bounded pair, and record a post-run state hash. A mismatch, failed restore, unexpected data disclosure, or unapproved side effect is an immediate stop condition. Application reset endpoints are not allowed as a replacement for snapshot restoration.

## Safe workflow after explicit approval

The approved case must pass the following sequence without skipping a gate:

1. Pin and verify source, runtime, and image hashes.
2. Create synthetic identities and non-sensitive canary records only inside the disposable lab.
3. Establish a baseline and independent negative control under the same state.
4. Measure quality only if the owner-approved lab Ground Truth and complete oracle are admitted.
5. Diagnose any failure or weak confirmation.
6. Write an Improvement Proposal and classify it as generic or target-local.
7. Implement only a bounded target-local adapter/profile change, unless the same deficiency is independently demonstrated on more than one Target.
8. Run regression tests, then rerun under the same conditions.
9. Compare before/after results.
10. Produce a redacted ProofBundle, seal it, run `verify_seal()`, and replay it independently.
11. Recompute discovery quality, confirmation quality, FP/FN, proof completeness, and cross-target portability only when all admission gates pass.

The workflow cannot promote a result merely because a route returns HTTP 200, a lesson completes, a source file exists, or a canary route is reachable.

## Causal oracle and negative-control requirements

Each approved case must have a target-local semantic oracle that distinguishes the intended causal predicate from ordinary reachability. The oracle must compare candidate and independent controls using typed canaries, ownership or authorization relationships, and state hashes. A status code, route existence, lesson completion, or generic response length is never sufficient.

The independent negative control must be meaningfully different from the candidate and must be run under the same source/runtime/data snapshot. Examples include the requester accessing its own object, a nonexistent opaque object, an authorized file, a parameterized benign query, or a benign encoded marker. If the control produces the same purported causal signal, the case remains blocked.

The central verifier mapping must route the target-local semantic decision through the existing central verifier and preserve ActionAuthority, CampaignExecutor, redaction, ProofBundle sealing, verification, and replay. No new bypass or direct scoring path is permitted.

## ProofBundle, sealing, and replay procedure

A valid bundle must contain only redacted typed metadata: packet ID, Target ID, source/runtime/image hashes, case ID, precondition result, candidate/control decision, pre/post state hashes, verifier mapping, and evidence hashes. It must not contain raw HTTP bodies, cookies, authorization headers, tokens, passwords, raw database rows, raw comments, raw file contents, or real personal data.

The procedure is: create the redacted bundle; seal it with the canonical model; verify the seal; replay the verifier from the sealed metadata in an isolated workspace; compare replay output with the original decision; and reject promotion on any mismatch. No bundle is a scoring ProofBundle until the independent negative control and replay both pass.

## Stop conditions

Execution stops immediately if any connection leaves `127.0.0.1`, any external callback or OAST behavior appears, a redirect is followed, a public DNS/IP is resolved, an unapproved method/route/payload/identity is attempted, a raw secret or body is about to be persisted, state restoration fails, a digest changes, a negative control is missing or non-independent, or sealing/verification/replay fails.

The lab also stops if the oracle cannot distinguish the candidate from its control, if the result relies only on HTTP status or reachability, if an unexpected sensitive field appears, or if the target requires a credential, destructive action, or external dependency not explicitly approved in the decision.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Synthetic authentication state leaks into evidence | Opaque identities, disposable store, redaction, no raw tokens/cookies, and destroy after run. |
| Mutation affects later cases | Snapshot restore before every pair and post-run state-hash check. |
| A payload causes destructive behavior | Strict per-case allowlist, no multi-statement/destructive payloads, immediate stop on side effects. |
| crAPI runtime is not reproducible | Pin all image digests before admission; `VERSION=latest` is a blocker. |
| False confirmation from route/HTTP behavior | Semantic canary oracle plus independent negative control; status-only evidence rejected. |
| Generic change weakens boundaries | Keep logic in adapters/profiles; generic change requires multi-Target demonstration and regression. |
| Lab approval is mistaken for qualification | Keep Official P10 gate closed and qualification state unchanged. |

## Cleanup and rollback

After each approved test cycle, stop local services and fixtures, destroy disposable containers/databases, delete synthetic identities and canary records, and retain only redacted metadata, hashes, decisions, and audit artifacts. On failure, restore the disposable snapshot or recreate the lab from pinned artifacts.

Any later code change must be target-local unless the same deficiency is demonstrated on more than one Target. Rollback means reverting only the target-local adapter/profile commit and restoring the disposable runtime/data snapshot. No force-push, history rewrite, Generic Core change, frozen Ground Truth change, threshold change, or qualification-state change is permitted.

## Decision options

| Option | Scope | Risk | Recommendation |
|---|---|---|---|
| A — Keep closed | Continue source analysis only; no local credentials or mutation. | No new causal quality evidence; P10/VIP gap remains. | Valid conservative option. |
| B — Staged read-only causal lab | Approve only WebGoat IDOR/path traversal and crAPI object-access cases listed as candidates, using synthetic identities, disposable fixtures, GET-only methods, and no external callbacks. | Requires synthetic authentication and ownership canaries. | **Recommended first gate.** |
| C — Full listed local lab | Also approve WebGoat stored XSS/advanced SQLi and separately approved crAPI mutation/auth cases under exact per-case controls. | Higher mutation, credential, and payload risk. | Requires separate per-case approval; not recommended as one blanket approval. |

### Requested owner decision record

The owner must fill all fields explicitly. An empty or partial record is not approval.

| Field | Owner response |
|---|---|
| Decision (`approve`, `reject`, or `changes_requested`) |  |
| Approved Target IDs |  |
| Approved case IDs |  |
| Approved methods per case |  |
| Credentials/login authorized? |  |
| State mutation authorized? |  |
| Expiry timestamp |  |
| Owner notes and constraints |  |
| Owner identity/signature |  |

**Recommendation:** choose **Option B** as a staged first gate. Do not approve mutation, authentication/token, destructive reset, SSRF, or external/callback cases in this decision. After Option B produces complete causal evidence, issue a separate packet for any additional cases.

## References

[1]: ../source_inventory/SOURCE-BACKED-CANDIDATE-INVENTORY-v1.json "Source-Backed Candidate Inventory v1"
[2]: LOCAL-CAUSAL-LAB-OWNER-DECISION-PACKET-v1.json "Machine-readable Owner Decision Packet v1"
[3]: ../scoring_readiness/MULTI-TARGET-GROUND-TRUTH-MATRIX-v1.json "Multi-Target Ground Truth Matrix v1"
[4]: ../scoring_readiness/MULTI-TARGET-ORACLE-CONTRACT-REGISTER-v1.json "Multi-Target Oracle Contract Register v1"
[5]: ../scoring_readiness/MULTI-TARGET-QUALITY-BASELINES-v1.json "Multi-Target Quality Baselines v1"
