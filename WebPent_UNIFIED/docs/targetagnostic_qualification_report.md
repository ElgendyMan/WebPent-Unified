# WebPent v72 Target-Agnostic Qualification Report

## Executive disposition

This delivery is **not VIP-qualified** and does not claim any new Tool-Confirmed vulnerability. The local contract and quality gates pass, but live target qualification remains blocked or inconclusive because the authorized local labs did not complete a reproducible run with registered runtime adapters, resettable evidence, and sealed replayable ProofBundles.

The evidence policy remains fail-closed:

> A finding may be called confirmed only when a causal signal, a neutral negative control, and a valid sealed/replayable ProofBundle are all present. Tool output, reflection, heuristics, HTTP errors, timeout, or a candidate record alone are insufficient.

## Changes implemented in this loop

The live Juice Shop attempt exposed a target-agnostic boundary defect: reconnaissance retained structured endpoint records, while the hypothesis analyzer passed those mappings as if they were URL strings. This produced invalid pseudo-URLs such as Python dictionary representations and caused downstream promotion validation errors.

The fix is additive and fail-closed. The hypothesis analyzer now accepts URL strings and structured `url`, `target_url`, or `href` fields, deduplicates canonical strings, rejects non-HTTP(S), credentials-bearing, fragment-bearing, malformed, and oversized values, and logs skipped records as coverage gaps. A regression test covers valid structured records, duplicate suppression, malformed input, credentials, and fragments.

The release manifest builder was also corrected to exclude SQLite sidecars (`.db-shm`, `.db-wal`, and `.db-journal`) from release inventory. A regression test prevents runtime database sidecars from entering release artifacts.

## Quality evidence

| Gate | Result | Evidence |
|---|---:|---|
| Focused endpoint/promotion tests | PASS | 50 passed |
| Full pytest after source fix | PASS | 1340 passed, 290 warnings |
| Ruff | PASS | `ruff check src/ tests/` |
| Compileall | PASS | `python -m compileall -q src` |
| G-02 runtime | PASS | `external_target_contacted=false`, `primary_records=63` |
| G-02 precommit/direct-I/O | PASS | no reported errors |
| Diff whitespace | PASS | `git diff --check` |
| Internal quality-gate test-count | PASS | Current `run_vip_quality_gate.py` enforces minimum 818; AST count is 1286 |
| pip-audit | PASS (current rerun) | `pip-audit --strict` and CycloneDX SBOM completed from current HEAD; artifacts regenerated at 2026-08-22T11:29:58Z |
| Bandit | PASS (high-severity gate) | Current Bandit `-lll` gate exited 0; raw JSON artifact regenerated and retained |
| Docker full stack | BLOCKED | kernel bridge/iptables raw-table restriction and prior disk/cache constraints; host API/worker checks are not equivalent to full stack qualification |

## Live qualification attempts

### Juice Shop

The first attempt exposed the endpoint-record defect before it could produce valid promotion evidence. After the fix, two independent clean attempts (`phase9-juice-r2` and `phase9-juice-r2b`) used new target workspaces and engagement IDs with LLM enabled and `DISABLE_RAG=true`. RAG-degraded operation is explicitly not RAG qualification.

Both attempts timed out at the bounded runner level. During the runs the existing `juice-shop` container exited cleanly with Docker state `exit=0` and `OOMKilled=false`, after which the application returned `ERR_CONNECTION_REFUSED`. No final report with a valid sealed ProofBundle was produced. Nuclei also ended with `exit=-15`; this is a runtime interruption, not a clean result or confirmation.

The container was restarted from the existing local image and returned an HTML homepage before the second clean attempt. The repeated graceful container exit is an operational blocker that needs controlled lab supervision or a resettable container configuration; it is not evidence of a WebPent finding.

### WAPTLab

The authorized local WAPTLab container was running on localhost:8000, but unauthenticated probes returned 403 for `/` and `/health`. No valid test-account credential fixture was available in the qualification workspace. A single bounded attempt used a new workspace and engagement with no credentials and timed out while RAG was disabled. No report or ProofBundle was produced. The historical WAPTLab baseline already records live qualification as blocked by the sandbox Docker/kernel constraint; synthetic/mock artifacts are not live evidence.

## G0–G10 status

| Gate | Status | Honest basis |
|---|---|---|
| G0 | PASS locally / live blocked | baseline and safety checks pass; live qualification is not complete |
| G1 | PASS | target workspace and engagement isolation contracts pass |
| G2 | PASS | scope compiler, ActionAuthority, ActionExecutor, and direct-I/O gates pass locally |
| G3 | PASS locally | target-understanding and coverage-gap contracts pass; target-backed coverage unqualified |
| G4 | PARTIAL | browser/identity contracts pass; Gmail/OTP and live mailbox E2E are not qualified |
| G5 | PASS locally / live blocked | differential validators and negative-control contracts pass; no live causal evidence |
| G6 | PASS locally / promotion fail-closed | ProofBundle contracts reject missing/invalid evidence; no live sealed bundle was produced |
| G7 | PARTIAL/BLOCKED | unit recovery/isolation contracts pass; full Docker/distributed runtime is blocked |
| G8 | BLOCKED/REVIEW | core gates pass; inherited pip-audit, Bandit, test-count, and release/security classifications remain |
| G9 | BLOCKED | three independent resettable target-backed runs with qualified adapters and LLM/RAG evidence were not completed |
| G10 | NOT QUALIFIED | release can be packaged, but VIP acceptance criteria are not met |

## Remaining blockers and next actions

The next qualification cycle must first provide a stable, resettable local lab runtime and a legitimate registered adapter path with G-02 metadata. It must then run three independent clean engagements per target, preserving workspace isolation and collecting causal signal, neutral negative control, and sealed/replayable ProofBundle hashes. Any missing validator, adapter, target identity, reset, or proof must remain `Needs Human Review`, `Not Scanned`, `Blocked`, or `Inconclusive` rather than being promoted.

The current quality gate rerun passed compileall, Ruff, pytest, G-02, Bandit, pip-audit/SBOM, secret scan, and manifest generation; its overall result remains false only because live WAPTLab and distributed/Docker qualification are explicit blockers. The strict AST preservation check (`--minimum 1300`) independently reports 1286 and remains a review blocker; the internal quality gate uses 818. Neither threshold may be changed or padded arbitrarily.

## Safety and artifact hygiene

No WAPTLab source was modified. No Gmail password, OAuth secret, MFA bypass, CAPTCHA bypass, raw session credential, cookie, `.env`, workspace database, checkpoint, RAG cache, or live qualification log belongs in the release ZIP. The live evidence described above remains outside the repository and is not used as a confirmation artifact.
