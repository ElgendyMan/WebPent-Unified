# Juice Shop P10 Coverage Expansion — Candidate Review Index

## Purpose

This directory contains the diagnosis and oracle-contract proposal for every candidate track currently considered for Juice Shop P10 coverage expansion. These documents are engineering proposals and safety decisions; they are not human governance signoff, not scoring approval, and not Official P10 authorization.

## Current decision matrix

| Candidate | Potential class | Diagnosis result | Contract status | Counts now |
|---|---|---|---|---:|
| Vulnerable Components / static dependency surface | Vulnerable Components | Exact served asset and semantic causal predicate are not proven | Blocked pending profile/source proof | No |
| SQL injection read-only probe | Injection | Causal query influence requires crafted input outside the current no-payload contract | Blocked; no safe contract | No |
| Broken access control state boundary | Broken Access Control | Controlled identity/ownership boundary and safe reset are absent | Blocked; precondition or mutation required | No |
| Sensitive document static resource | Sensitive Data Exposure | Exact runtime mapping and sensitivity predicate are not proven; reachability is insufficient | Blocked pending mapping/oracle review | No |
| Permissive CORS and limited security middleware | Security Misconfiguration | Source configuration does not prove an unauthorized sensitive cross-origin read or browser security impact | Blocked pending causal predicate and authorized control | No |
| Redirect allowlist boundary | Unvalidated Redirects | Source route semantics are visible, but causal proof needs a controlled destination outside the current local-only boundary | Blocked pending safe destination oracle | No |

## Required gates for any future promotion

A candidate may be promoted only after an independent mapping and oracle decision, a safe precondition, baseline/candidate/independent negative control, a semantic causal predicate, central verification, a redacted sealed ProofBundle, successful `verify_seal()`, replay, target-local adapter/profile placement, regression tests, and a before/after comparison.

## Current scope decision

No candidate in this directory is promoted. No candidate changes the approved set, the case count, the class count, the scoring denominator, or the Official P10 run gate. The current approved set remains 3 cases / 3 classes and the theoretical gap remains 7 cases / 3 classes.

The SQL injection and broken-access-control tracks are not executed because doing so would require payloads, credentials, cross-user identity, bypass, or mutation outside the authorized local read-only scope. The static-resource tracks are not executed because source presence or route reachability alone cannot satisfy a semantic vulnerability oracle. The additional CORS/header and redirect surfaces were analyzed from source metadata only and remain blocked because no approved causal predicate and safe control exist within the current scope.

## Evidence handling

Only redacted metadata-level evidence is allowed for the current phase. Do not add cookies, credentials, tokens, raw response bodies, or external callback data. Local activity must remain loopback-only and read-only.

## Independent review

Each document contains a reviewer decision field. It must be completed by a real independent human reviewer. Internal engineering review or assistant-generated text does not satisfy `human_independent_signoff_obtained`.

## Files

- `CANDIDATE-01-vulnerable-components-diagnosis-and-oracle-proposal-v1.md`
- `CANDIDATE-02-sql-injection-diagnosis-and-oracle-proposal-v1.md`
- `CANDIDATE-03-broken-access-control-diagnosis-and-oracle-proposal-v1.md`
- `CANDIDATE-04-sensitive-document-diagnosis-and-oracle-proposal-v1.md`
- `JUICE-SHOP-ADDITIONAL-CANDIDATES-ANALYSIS-v1.md`
