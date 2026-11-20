# M4_PHASE_REPORT.md — M4 (White-Box / SAST & Hybrid Analysis)

**Phase:** M4 of the CANONICAL_PHASE_REGISTRY (Part 4 §6 — P1, OPTIONAL).
**Date of decision:** 2026-11-06 (UTC).
**Decision:** **NOT EXECUTED — the optionality gate is not met.** This is the
registry's own gating criterion, not a deferral by convenience.

---

## 1. The gate

Part 4 §6 and the registry both define M4 as optional with TWO explicit
preconditions:

1. *"optional, authorized source intake"* — any repository analysis
   requires the operator to supply authorized source code. No such
   intake exists in any engagement surface today: the CLI/API accept
   targets (URLs), scope files, authorization manifests, target
   packages, identity profiles and JS bundles fetched from the LIVE
   target — never a source repository.
2. *"gated by demonstrated need"* — M4 builds a provider interface
   (Joern et al.), unified Candidate results and static↔dynamic
   correlation. The need is demonstrated when discovery quality on the
   BLACK-BOX path (M3 + M6 evidence quality) is measurably blocked by
   the absence of source-level truth. The M3 closure state is the
   opposite: the black-box engine's recall/precision baseline was just
   wired to its measurement harness (UM-DR-17 §2.7) and the Charter
   §4.1 gate exists precisely so that any LLM/structural producer —
   including a future SAST-fed one — must MEASURE before it earns
   budget.

## 2. What exists vs what M4 would build

- **No SAST capability exists** (verified: no `sast` package, no
  source-intake channel in `PentestState`, no provider interface). M4
  is a full greenfield.
- The frozen JS AST reverser (UM-DR-17 ف3.2) is the closest existing
  static-analysis surface — it analyzes LIVE-FETCHED bundles under the
  target's own scope policy, which is black-box reconnaissance, not
  authorized source intake. It is NOT a partial M4 and must not be
  counted as one.

## 3. Conditions that would open M4 (recorded for the owning operator)

1. An operator supplies an authorized source repository for an
   engagement (a new intake surface with its own authorization gate —
   M2's manifest vocabulary would extend to it), AND
2. M11's benchmark shows a discovery-quality gap that source-level
   truth would close (the demonstrated need), AND
3. The 0.34.x roadmap prioritizes it above M5–M12 residuals.

Until all three hold, M4 stays closed. Nothing in M5–M12 depends on
M4 (the registry lists no dependents; M5 depends on M3+M2 only).

— End of M4_PHASE_REPORT.md —
