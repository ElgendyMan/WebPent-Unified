# RTA v1 — Realistic Target Assessment Report

## Scope and safety

RTA v1 replaces the previous in-process DCVU observations with three disposable local applications exposed through real loopback HTTP. Each application uses a real FastAPI request path and a real SQLite read model. Identities, sessions, roles, tenant records, and object relationships are synthetic and deterministic. All campaign requests are `GET` only; no real credentials, login flow, state mutation, external callback, or external target is used.

The RTA harness is an assessment fixture, not a production deployment and not a bug-bounty target. Its results are **HTTP-backed fixture evidence** and do not constitute field detection quality or official P10/VIP qualification.

## Implemented path

The campaign now follows:

`HTTP discovery → API mapping → synthetic authenticated context → permission graph → baseline/candidate/control requests → semantic redaction → causal inference → redacted proof seal/replay → verdict`

Discovery reads a target-provided `openapi-lite` document and HTML links over loopback HTTP. It records route templates, path parameters, authentication hints, and redacted response digests. It does not store raw response bodies or issue state-changing requests.

The local harness includes IDOR/BOLA, BFLA, privilege escalation, tenant isolation, workflow authorization, business-logic discount abuse, partial-access behavior, and misleading same-status responses. The same status code is intentionally returned for full and limited billing access; the semantic access-level facts distinguish them.

## Results

| Target | Version | Discovered surfaces | Parameters | Cases | TP | FP | FN | TN | Precision | Recall | F1 | Positive proof completeness |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| rta-http-a | 1.0.0 | 8 | 6 | 7 | 7 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 |
| rta-http-b | 1.1.0 | 8 | 6 | 7 | 5 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 | 1.00 |
| rta-http-c | 2.0.0 | 8 | 6 | 7 | 4 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 | 1.00 |
| **Aggregate** | — | **24** | **18** | **21** | **16** | **0** | **0** | **5** | **1.00** | **1.00** | **1.00** | **1.00** |

The aggregate contains **16 positive and 5 clean cases**. Clean cases are counted as TN, not FN. Every predicted-positive case has candidate, baseline, and independent-control observations plus replayable redacted proof. No blocked or observation-only case is promoted into the scored set.

## Stress coverage

The benchmark includes different truth distributions across three target profiles, same-status full versus limited billing responses, hidden role boundaries, cross-tenant object requests, owner/requester differentials, privilege-preview behavior, workflow role checks, and business-rule discount semantics. Target-specific route semantics remain in the RTA harness/profile; the DCVU Generic Core is not modified to encode these routes.

## Legacy blockers

The existing seven full-suite failures remain classified as legacy blockers and were not hidden or converted into passing evidence:

1. Four failures are caused by the frozen Option B approval source-hash mismatch.
2. Two failures concern WebGoat service/build alignment and crAPI runtime/source attestation.
3. One failure depends on the absent local Juice Shop fixture at `/tmp/juice-shop-source/data/static/challenges.yml`.

These require frozen-evidence repair, approved runtime/source inputs, or fixture availability. RTA v1 does not alter policy, ground truth, thresholds, or historical evidence to remove them.

## Governance status

```text
official_isolated_p10_runs_authorized = false
P10 = NOT_QUALIFIED
P9 = NOT_QUALIFIED
VIP = NOT_QUALIFIED
Bug Bounty = BLOCKED
qualification_effect = false
```

## Interpretation and remaining gaps

RTA v1 demonstrates that the research and confirmation path can operate over real local HTTP traffic with synthetic authenticated contexts and a database-backed read model. It is a substantial upgrade over in-process fixtures. It still does not prove detection quality on independently deployed real applications, production-grade authentication protocols, resettable mutable workflows, or externally reviewed ground truth. The next safe upgrade is to add more independent local target implementations and controlled resettable business workflows; any login, mutation, new privilege, or external scope remains subject to a separate owner decision packet.
