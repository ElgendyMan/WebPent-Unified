# WebGoat Causal Redesign and Blocker Report v1

**Author:** Manus AI

**Scope:** Local bounded WebGoat IDOR causal experiment redesign only. The historical B2/B2.1 request flow was not re-run.

## Decision

> **Result: BLOCKED — no target-backed causal confirmation and no scoring ProofBundle.**

The redesigned experiment is implemented as a target-local, non-executing design in `src/webpent/adapters/webgoat/causal_experiment.py`. It requires two independently controllable synthetic identity states, one owner-owned disposable resource, a candidate observation under a distinct requester identity, an independently denied or nonexistent negative control, and a bounded semantic distinction that is stronger than status code, redirect, route, or source presence.

The current WebGoat source and existing adapter do not provide that capability within the approved GET-only, loopback-only, no-new-credentials, no-login, no-mutation scope. Therefore the correct result is a formal blocker rather than a fabricated confirmation.

## Source-backed diagnosis

The pinned local WebGoat source revision used by the existing target-local runner is `7517acca95d9851da706452454c223dd13545ef4`. The relevant source files were inspected passively and were not invoked through the application.

| Source | Observed behavior | SHA-256 |
|---|---|---|
| `/tmp/webgoat-source/src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOwnProfile.java` | `GET /IDOR/own` and `GET /IDOR/profile` read `LessonSession` values `idor-authenticated-as` and `idor-authenticated-user-id`, then construct the session-bound `UserProfile`. | `e6d82fadc90c6bc3485f988fb17d8e346bb39e997238ed096d2c471d5fd8267f` |
| `/tmp/webgoat-source/src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOwnProfileAltUrl.java` | The alternate assignment is a `POST`, checks the same session-bound user ID, and validates the supplied path against that same ID. It is not an independent GET-only owner/requester object-access fixture. | `7fc58039979105602d881c9d245b1c6ea44d732928b22598cc5c3ca4eb009009` |
| `src/webpent/adapters/webgoat/causal_experiment.py` | Design-only experiment contract and fail-closed blocker. | `2a90cf0a5548ad20585822858849d9239418bafbbdd5c4e74201b28d5aa14c56` |

The source-backed gap is precise: the available GET endpoint is session-bound and does not expose a separately addressable owner resource that can be requested under a different LessonSession. The alternate route uses POST and validates the authenticated session user ID; using it would not satisfy the redesigned GET-only causal contract. The existing WebGoat adapter is metadata-only and does not inject or reset application `LessonSession` state.

## Redesigned experiment contract

| Element | Required condition |
|---|---|
| Owner baseline | Synthetic owner identity successfully reads a disposable owner-owned resource and exposes a bounded semantic resource identity. |
| Candidate | A distinct synthetic requester identity requests the same owner resource. The result must be semantically observable and differ from the owner baseline in the required access predicate. |
| Independent negative control | A distinct denied or nonexistent resource/request is used, with an independent request digest and a denial/nonexistence semantic result. |
| Expected invariant | A requester session cannot read the owner-owned profile/object. |
| Violated invariant | The requester session receives the owner-owned profile/object semantic identity. |
| Reset | Snapshot restore must return the same fixture state hash before and after the experiment. |
| Proof gate | Typed oracle decision must be `CONFIRMED`; `CLEAN`, `INCONCLUSIVE`, and `BLOCKED` must withhold scoring bundles. |

HTTP status, redirect behavior, route presence, lesson completion, and source presence are explicitly insufficient signals. No such signal was promoted in this phase.

## Exact blocker and required capability

The blocker code is `WEBGOAT_LESSON_SESSION_OWNER_FIXTURE_UNAVAILABLE`.

To remove it, an owner-approved target-local fixture mechanism must expose, without real credentials or external callbacks, two independently controllable `LessonSession` identity states and a disposable owner/resource mapping. It must support snapshot, restore, and state-hash verification, and it must permit a GET-only observation whose bounded semantic content distinguishes owner access, requester access, and the independent negative control. If implementing this capability requires login, credentials, token generation, application state mutation, or a new permission, it must be raised as a separate Owner Decision Packet; this milestone does not expand scope automatically.

## Safety and governance outcome

No WebGoat network request was made by the redesigned experiment module or its tests. The historical runner was not re-run. No credential, cookie, token, response body, or external target was used. No scoring ProofBundle was created for WebGoat. `official_isolated_p10_runs_authorized` remains `false`; P10, P9, and VIP remain `NOT_QUALIFIED`; Bug Bounty remains `BLOCKED`; scoring promotion remains `false`.

The crAPI fixture work in this milestone is offline-only and is not target-backed evidence. It must not be combined with this WebGoat blocker to claim a live WebGoat confirmation.

## Validation

The design and regression tests passed together with the causal oracle, ProofBundle vNext, and crAPI offline fixture tests. The test command and result were:

```text
PYTHONPATH=src:integrations/bbscout/src pytest -q \
  tests/test_webgoat_causal_experiment.py \
  tests/test_crapi_offline_fixture.py \
  tests/test_causal_foundation.py
12 passed
```

## References

[1] [WebPent WebGoat causal experiment design](../../src/webpent/adapters/webgoat/causal_experiment.py)

[2] [WebGoat IDOR GET source](file:///tmp/webgoat-source/src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOwnProfile.java)

[3] [WebGoat IDOR alternate-path source](file:///tmp/webgoat-source/src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOwnProfileAltUrl.java)

[4] [Historical target-local runner, not re-run](../../scripts/run_b2_target_live.py)
