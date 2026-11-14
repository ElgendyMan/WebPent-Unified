# Option B — Local Causal Lab v1 Readiness Report

**Author:** Manus AI — non-human attributable technical review

**Campaign:** `option-b-local-causal-lab-v1-20260827`

**Determination:** `LAB_NOT_READY / PRECONDITION_BLOCKED`. This phase closes the safety and fail-closed readiness checks, but it does not establish causal detection quality.

## Executive determination

The Option B readiness work was completed only within the approved local boundary. Immutable source revisions and source-file hashes were revalidated. A WebGoat build/runtime digest and Java toolchain digest were pinned, and crAPI service image RepoDigests were pinned as a composite runtime manifest. However, the running WebGoat service could not be attested as aligned with the pinned build artifact, so WebGoat runtime readiness remains blocked. crAPI runtime provenance is attested, but its selected object-access cases still require authenticated ownership/session state that cannot be created under the current GET-only/no-credentials approval.

Offline synthetic identities, ownership labels, disposable canary metadata, and in-memory snapshot/restore were implemented and verified. These fixtures never entered either target runtime and therefore are regression evidence only, not target evidence. The runner added a preflight decision that must pass before any socket operation. The subsequent one-off rerun produced six `LAB_NOT_READY / PRECONDITION_BLOCKED` records, with `network_allowed=false` and `network_attempted=false` for every case.

> **No target-backed baseline, candidate, or independent-control observation was collected. Therefore no causal oracle was evaluated and no ProofBundle was created, sealed, verified, or replayed.**

## Scope and authorization boundary

| Control | Applied value | Result |
|---|---|---|
| Targets | WebGoat IDOR/path traversal and crAPI object-access only | Approved tracks only |
| Network | Loopback and declared local origin only | Preflight-enforced; no case socket operation occurred |
| Methods | `GET` only | Non-GET rejected by contract and regression tests |
| Redirects and external callbacks | Forbidden | Rejected and not attempted |
| Credentials, login, sessions, cookies, and tokens | Forbidden | Auth-dependent cases blocked |
| Application mutation and reset endpoints | Forbidden | Not invoked |
| Raw response bodies/headers and personal data | Not retained | Redacted model and tests enforced this |
| Official P10 and Bug Bounty | Closed | Unchanged |

The controlling authorization is the imported owner directive at [`LOCAL-CAUSAL-LAB-OPTION-B-OWNER-APPROVAL-IMPORT-v1.json`](../owner_decision/LOCAL-CAUSAL-LAB-OPTION-B-OWNER-APPROVAL-IMPORT-v1.json). Its source-text SHA-256 is `2784b4746e96419a3dadea2e765d58a9dbc719b283bb683b38bbe95c5850230b`. The original decision packet remains `PENDING_OWNER_APPROVAL` and was not modified. The import record is not human independent signoff and does not authorize qualification or Official P10 execution.

## Provenance and readiness

| Target | Source revision | Source verification | Runtime provenance | Readiness consequence |
|---|---|---|---|---|
| OWASP WebGoat | `7517acca95d9851da706452454c223dd13545ef4` | Declared source files matched expected hashes | Build/toolchain digests pinned; service alignment is `not_attested` | WebGoat cases remain blocked before network |
| crAPI | `73d309cc8f28bbdeed31dbb35f05dba8354de3c9` | Controller and route files matched expected hashes | Composite runtime digest and individual image RepoDigests pinned; alignment `attested` | Auth/ownership fixture restriction still blocks all selected cases |

The machine-readable artifact contains typed provenance and status fields only. It does not persist environment variables, process arguments, credentials, tokens, cookies, response bodies, or raw headers. Mutable image tags are retained only as image names paired with the pinned RepoDigest; the digest, not the tag, is the reproducibility reference.

## Offline identity and fixture readiness

The fixture implementation under `src/webpent/adapters/local_causal_lab/fixtures.py` models opaque synthetic identities and ownership/canary labels in memory. It supports typed snapshot/restore and state-hash verification. The fixture layer rejects credential/session material, raw canary persistence, application mutation, and application reset endpoints. The runner recorded `offline_snapshot_restore_verified` and stable state hashes for every case.

This result means the offline fixture model is ready for regression testing. It does **not** mean that an equivalent identity, ownership relation, session, or canary exists inside WebGoat or crAPI. Target fixture injection remains unattested and is intentionally treated as a blocker.

## Precondition gate

The target-local preflight gate runs before any network client is allowed to operate. It checks the declared case status, source/runtime readiness, offline snapshot/restore status, loopback origin, exact route and query allowlist, `GET` method, redirect prohibition, auth/session restrictions, target-fixture attestation, and independent-control declaration. If any check fails, the decision contains `network_allowed=false` and the runner stops.

The latest rerun produced the following aggregate result:

| Result | Count |
|---|---:|
| Approved-track cases evaluated | 6 |
| `LAB_NOT_READY / PRECONDITION_BLOCKED` | 6 |
| Target-backed baseline observations | 0 |
| Target-backed candidate observations | 0 |
| Independent-control observations | 0 |
| Causal confirmations | 0 |
| ProofBundles created/sealed | 0 |
| Network case requests | 0 |

## Case decisions

| Case ID | Readiness/precondition result | Final classification |
|---|---|---|
| `webgoat.idor.view_other_profile.v1` | Blocked because GET-only approval cannot create the required `LessonSession`; POST login and built-in lesson credentials are not approved. WebGoat service alignment is also not attested. | **LAB_NOT_READY / PRECONDITION_BLOCKED** |
| `webgoat.path_traversal.v1` | GET route exists, but the safe target-local disposable canary injection route is not established. Raw traversal markers remain forbidden, and WebGoat service alignment is not attested. | **LAB_NOT_READY / PRECONDITION_BLOCKED** |
| `crapi.profile_video_object_access.v1` | Runtime provenance is ready, but authenticated ownership/session state is unavailable. Source review also indicates owner-scoped behavior, so no BOLA confirmation is inferred. | **LAB_NOT_READY / PRECONDITION_BLOCKED** |
| `crapi.vehicle_location_bola.v1` | Runtime provenance is ready, but the required authenticated synthetic owner/requester pair and target fixture injection are unavailable under the approval. The source-level UUID lookup remains only a candidate indication. | **LAB_NOT_READY / PRECONDITION_BLOCKED** |
| `crapi.community_post_object_access.v1` | Authentication middleware and stateful post-fixture creation are outside the approved boundary. | **LAB_NOT_READY / PRECONDITION_BLOCKED** |
| `crapi.mechanic_report_object_access.v1` | Authentication and pre-existing report creation/retrieval state are unavailable; creation is stateful and not approved. | **LAB_NOT_READY / PRECONDITION_BLOCKED** |

Each case record includes a Failure Record, RCA, target-local classification, safety determination, improvement proposal, regression status, before/after comparison, preflight errors, cleanup status, and explicit absence of target observations.

## Candidate/control, oracle, and proof status

The causal cycle was not entered for any case because no case satisfied the precondition gate. This is neither a detection success nor a detection failure. It is an auditable lab-readiness blocker.

| Evidence component | Result |
|---|---|
| Baseline GET | Not run |
| Candidate GET | Not run |
| Independent negative control | Not run |
| Causal oracle | Not evaluated |
| Central verification | Not run |
| ProofBundle | Not created |
| `verify_seal()` | Not run |
| Isolated replay | Not run |
| Cleanup | Offline snapshot/restore verified; no target mutation, reset endpoint, or network case request |

No metrics, TP/FP/FN labels, clean labels, confirmation labels, or scoring promotion were produced. `LAB_NOT_READY / PRECONDITION_BLOCKED` is not converted into a detection-quality result.

## Improvement cycle and remaining gaps

The implemented improvements are target-local readiness infrastructure: immutable provenance validation, offline fixture snapshot/restore, and a preflight gate that stops before the network. No generic core, frozen ground truth, threshold, policy, or authorization gate was changed. The same-condition comparison remains unchanged: all six cases are blocked before and after because target fixture/session prerequisites are still unavailable.

The next executable step requires a separately authorized, source-backed, disposable target fixture/session mechanism that does not use real credentials, login, token generation, mutation, or an auth bypass. For WebGoat path traversal, a safe canary route or fixture injection mechanism must also be demonstrated without raw traversal markers or broad filesystem access. WebGoat runtime service-to-artifact alignment must be attested. If any of these conditions cannot be established safely, the affected case must remain blocked.

## Validation and invariant state

The focused readiness suite passed **30 tests** after the preflight, provenance, fixture, and runner changes. Ruff passed on all affected files. The live runner rerun was independently checked for six blocked cases, zero network attempts, zero target observations, and zero ProofBundles.

The project invariants remain:

| State | Value |
|---|---|
| `human_independent_signoff_obtained` | `false` |
| `official_isolated_p10_runs_authorized` | `false` |
| P10 | `NOT_QUALIFIED` |
| P9 | `NOT_QUALIFIED` |
| VIP | `NOT_QUALIFIED` |
| Bug Bounty | `BLOCKED` |
| Scoring promotion | `false` |

## References

[1]: file:///tmp/webgoat-source/src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOtherProfile.java "WebGoat IDOR profile source"

[2]: file:///tmp/webgoat-source/src/main/java/org/owasp/webgoat/lessons/idor/IDORLogin.java "WebGoat IDOR login source"

[3]: file:///tmp/webgoat-source/src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java "WebGoat path traversal retrieval source"

[4]: file:///tmp/webgoat-source/src/main/java/org/owasp/webgoat/lessons/pathtraversal/PathTraversal.java "WebGoat path traversal source"

[5]: file:///tmp/crapi-source/services/identity/src/main/java/com/crapi/controller/VehicleController.java "crAPI vehicle controller source"

[6]: file:///tmp/crapi-source/services/identity/src/main/java/com/crapi/controller/ProfileController.java "crAPI profile controller source"

[7]: file:///tmp/crapi-source/services/community/api/router/routes.go "crAPI community routes source"

[8]: file:///tmp/crapi-source/services/workshop/crapi/mechanic/urls.py "crAPI mechanic routes source"
