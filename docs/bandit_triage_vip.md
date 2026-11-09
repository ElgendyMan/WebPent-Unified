# Bandit VIP Triage

## Scope

This triage records the exact Bandit 1.9.4 output from the local VIP verification run on `src/`. No target, WAPTLab, AutoPentestX executable, browser, or external network was used.

## Snapshot

| Severity | Count | Disposition |
|---|---:|---|
| High | 0 | No high-severity result observed. |
| Medium | 4 | Two low-confidence false positives and two intentional preflight policy literals; none is an unreviewed exploit path. |
| Low | 63 | Retained for ongoing triage; not silently suppressed. |

## Medium findings

| Location | Rule | Assessment | Disposition |
|---|---|---|---|
| `src/webpent/agents/payload_generator/agent.py:500` | B608 | The flagged string is a prompt/reference-data assembly operation, not SQL construction. The inserted payload reference is explicitly treated as untrusted reference data and is not executed. | False positive, low confidence; retain as audit-visible. |
| `src/webpent/memory/db.py:902` | B608 | The query uses generated `?` placeholders and binds `clean_ids` through the SQLite parameter API. The interpolated text is only the placeholder count, not user data. | Safe parameterized pattern; retain as audit-visible. |
| `src/webpent/shared/preflight.py:330` | B104 | The literal `0.0.0.0` is intentionally recognized as a public bind address so preflight can reject insecure unauthenticated configuration. It does not bind a socket. | Intentional security-policy detection; retain as audit-visible. |
| `src/webpent/shared/preflight.py:339` | B104 | Same preflight guard, raising a fail-closed error when an unauthenticated public bind is requested. | Intentional security-policy detection; retain as audit-visible. |

## Release interpretation

There are **zero High** Bandit findings. The four Medium findings are reviewed above and are not silently ignored. The release remains blocked from the final VIP label for the plan's independent reasons: no target benchmark in this loop, no three-run 15/20 proof, no precision/reproducibility measurements, and no Docker/browser/tool runtime qualification. This document does not convert Bandit output into a claim that the project is vulnerability-free.
