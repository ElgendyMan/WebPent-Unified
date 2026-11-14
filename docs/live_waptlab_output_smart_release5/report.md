# WebPent Engagement Report

**Target:** http://127.0.0.1:8000
**Total findings:** 2
**Generated:** 2026-08-18T17:40:34.778161+00:00

## Executive Summary

Automated penetration testing of http://127.0.0.1:8000 identified 2 candidate finding(s). None have been tool-confirmed — the overall risk posture is UNCONFIRMED and requires verification before drawing exploit-risk conclusions. The candidate findings should be triaged manually to determine which warrant deeper validation.

Remediation should not be prioritised on unconfirmed rows alone. A follow-up engagement with the target's authentication context (or with OOB callback enabled) is recommended to convert candidates into confirmed findings and establish a verified risk baseline.

## Findings

| # | Title | Severity | CVSS | Confidence | Business Impact | Reasoning | URL |
|---|-------|----------|------|------------|-----------------|-----------|-----|
| 1 | Potential RCE at http://127.0.0.1:8000/csv/upload | high | — | Needs Human Review | — | OOB validation is unavailable because the operator has not enabled a callback channel. No automated confirmation is claimed; human review is required. | http://127.0.0.1:8000/csv/upload |
| 2 | Potential IDOR at http://127.0.0.1:8000/user_profile/1 | medium | — | Clean | — | IDOR check: no unauthenticated successful object response was observed; authenticated owner-vs-foreign proof was not attempted. | http://127.0.0.1:8000/user_profile/1 |

## Decision Log

Every promotion, abandonment, scope check, and risk-gate decision the framework made during this engagement, in chronological order. `Rule Fired` is the deterministic rule that triggered the decision (never LLM free text).

| # | Timestamp (UTC) | Type | Rule Fired | Outcome | Branch ID |
|---|-----------------|------|------------|---------|-----------|
| 1 | `—` | `hypothesis_promoted` | deterministic_match=True (path-classified, validator-available) — promotion threshold bypassed; score=0.2875 (informational, not gating) | promoted to finding c2c37095-d5fc-46d7-b7a5-4891c4ab05b0 | `—` |
| 2 | `—` | `hypothesis_promoted` | deterministic_match=True (path-classified, validator-available) — promotion threshold bypassed; score=0.2250 (informational, not gating) | promoted to finding d48a4cf0-27af-491b-a430-d0029d8d084d | `—` |
