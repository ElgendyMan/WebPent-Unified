# Unified Plan Phase 0 — Intake and Evidence Boundary

## Scope

This intake covers the current Git worktree at `/tmp/webpent_v60_smart_implementation`. The ZIP named `webpent_ux_final.zip` was not present in `/home/ubuntu/upload` at intake time, so no claim is made that a ZIP archive was independently audited in this phase. The current source tree is treated as the authoritative working copy for implementation.

## Current source manifest

| Item | Observed value |
|---|---|
| Git branch | `master` |
| Git HEAD at intake | `28194f66da866237512eb8eac4702bc4958c5fd3` |
| Remote | `https://github.com/ElgendyMan/webpent-v61.git` |
| Tracked files | 476 |
| Tracked Python files | 331 |
| Worktree changes at intake | `README.md` modified |
| Potential local runtime artifacts | `webpent.db`, `memory/global/chroma_db/chroma.sqlite3` |
| `.env` / private key files found | none in the reported scan |

## Existing operational boundary

The repository already contains explicit scope-enforcement, hardened HTTP client helpers, an ActionExecutor/CampaignExecutor, ProofBundle models, research contracts, and local WAPTLab static/mock validation documentation. Existing documentation correctly states that the Docker-based WAPTLab runtime was blocked by the sandbox kernel's missing iptables raw table and that mock results are not live WAPTLab confirmation.

## Confirmed P0 candidate

Static inspection found an unconditional precondition bypass in:

`src/webpent/agents/smart_campaigns/agent.py:727`

```python
outcomes.append(executor.execute(task, handler, preconditions_met=True))
```

This is inconsistent with the executor contract, which supports fail-closed blocking through `preconditions_met=False` and `resolve_preconditions()`. It is a confirmed code defect candidate and is the first P0 remediation target.

## Direct-I/O boundary observation

The source contains several calls to the centralized `make_safe_httpx_client`, which is positive evidence that many HTTP paths use SSRF and engagement-scope guards. However, the presence of a safe client alone does not prove that every action is mediated by the central executor. The smart campaign path contains direct network execution inside its handler, while the executor authorizes the task before invoking the handler. This boundary must be reviewed and tested rather than assumed safe.

## Evidence classification

No live WAPTLab qualification is claimed from this intake. No new vulnerability finding is confirmed from route names, RAG hits, LLM output, static signatures, or mock behavior alone. Any later confirmed finding must include causal positive evidence, a negative control, deterministic validation, scope/identity context, replay metadata, and a sealed ProofBundle.

## Next action

Proceed with baseline tests and focused P0 tests before modifying the smart campaign execution path. Preserve WAPTLab and Juice Shop repositories unchanged.
