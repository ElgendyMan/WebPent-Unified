# CLI Decision Matrix — scan vs hunt vs agent-hunt (P2-306)

**Date:** 2026-11-01 · **Closes:** Phase-1 §6 (three parallel hunting entry
points with different semantics; divergence closed with a decision record,
NOT a code merge — `webpent/cli/commands.py` is byte-frozen).

## The three entry points

| | `scan` | `hunt` | `agent-hunt` |
|---|---|---|---|
| **Status** | **LEGACY** — do not start new engagements with it | **LEGACY** — superseded for governed runs | **GOVERNED DEFAULT** for new engagements |
| **Execution model** | URL-scoped legacy loop; per-URL agent execution outside the modern governed spine | Orchestrated campaign over the graph; broader than `scan` but without the bounded-loop governance | Governed bounded loop: hard `--scope`, cost caps, HITL gates, rate-governed transport |
| **Scope authority** | CLI flag only, no hard envelope | Campaign config | Hard `--scope` enforcement (ScopeLaw + target-workspace isolation) |
| **Cost control** | none built in | partial | explicit cost caps (budget governor) |
| **Audit chain** | partial | partial | full EngagementAuditChain (hash-chained, fail-closed) |
| **Modern-spine authority** | legacy-compatibility path (ADVISORY recon) | mixed | modern spine is the authoritative knowledge producer |

## Decision rule for operators

1. **New engagements → `agent-hunt`.** It is the only entry point that
   composes hard scope, cost caps, and the governed audit chain by default.
2. `hunt` may be used for ad-hoc exploratory campaigns where its weaker
   guarantees are understood and accepted.
3. `scan` remains for backward compatibility with existing tooling/scripts;
   treat its output as advisory-only (it cannot produce governed findings).

## Why documentation instead of a code merge

`commands.py` is sealed: byte-identical under the frozen gate
(`tests/test_frozen_module_gate.py` / `frozen_modules.sha256`), and the M2A
conditional-thaw grants covered exit-code honesty ONLY. Merging the three
surfaces would also change operator-facing contracts (`CAMPAIGN_GUIDE.md`,
team1 acceptance evidence) in the same commit — a governance change, not a
refactor.

## What a future unfreeze-and-merge requires

1. An authorized re-freeze window per `DRIFT_REGISTER.md` (precedent:
   TC-4 in-place refreeze; M2 dossiers per WP).
2. A documented CLI contract migration: deprecation notice → alias period →
   removal, with `test_frozen_module_gate.py` manifest update in the same
   window (re-pin after the documented change; scope 719 unchanged unless
   files are added).
3. Re-run of the full suite + team1 acceptance under the merged surface, plus
   a new evidence file (no hand-edited numbers).
4. Update this matrix's Status column and `docs/CAMPAIGN_GUIDE.md` in the
   same commit.
