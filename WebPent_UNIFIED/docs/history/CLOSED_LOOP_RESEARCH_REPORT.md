# TEAM-1 — CLOSED-LOOP RESEARCH MILESTONE REPORT
## Proof Semantic Integrity + Closed-Loop Research Memory + Replanning

**Status:** IMPLEMENTATION COMPLETE. **226 tests pass, 1 skipped (API deps). 0 failures.**

---

## 1. FILES CHANGED (this milestone)

### MODIFIED (2)
| File | Change |
|------|--------|
| `src/webpent/models/proof_semantics.py` | Added **chronology + execution identity** derivation: timestamps across causal/session/replay must be consistent (>1yr disconnect rejected); `execution_identity` required; `experiment_id` mismatch across contexts rejected. |
| `src/webpent/production/modern_spine.py` | Added `FindingLifecycle` (candidate→supported→refuted/inconclusive/blocked→promoted, contradictory evidence can refute), `ResearchAgenda` (mutable from evidence: unresolved_questions/confirmed_facts/rejected_hypotheses/promising_relationships/blocked/follow_up, mutation log), `run_research_campaign()` (bounded multi-step closed loop with organic replan + explicit stop conditions). |

### NEW TESTS (1)
`tests/team1_acceptance/test_closed_loop_research.py` — 26 tests across 8 classes.

---

## 2. PROOF SEMANTIC INTEGRITY (caller-controlled truth eliminated)

| Field | Derived from | Caller assertion trusted? |
|-------|-------------|--------------------------|
| evidence_origin | Literal validated | NO (must be target_runtime for promotion) |
| target_backed | evidence_origin == target_runtime | NO |
| negative_control_independent | digest comparison (NC ≠ baseline AND ≠ candidate) | NO |
| chronology | timestamp consistency across contexts | NO (disconnected rejected) |
| execution identity | required + experiment_id consistency | NO (mismatch rejected) |
| causal verdict | causal_signal must be True for CONFIRMED | NO |

---

## 3. NEGATIVE-CONTROL MUTATION EVIDENCE

Missing/null/copied-baseline/copied-candidate/identical/forged-assertion → all fail SemanticValidationError before sealing. Post-seal tamper → crypto seal broken → promotion fails. `verify_seal()=PASS` never implies semantic validity.

---

## 4. REFUTATION LIFECYCLE EVIDENCE

`FindingLifecycle`: candidate → supported → promoted (valid). candidate → promoted (invalid, rejected). supported + strong contradictory evidence → refuted (terminal, cannot promote). weak contradictory → inconclusive. Invalid transitions rejected. `can_promote()` requires state=supported + support≥1 + refute=0.

---

## 5. MEMORY RETRIEVAL/INFLUENCE EVIDENCE (ablation)

- **With memory:** ranking changes (default `/api/health` → influenced `/api/orders`).
- **Without memory:** default alphabetical ranking.
- **Stale/conflicting memory:** remains advisory_only, trust_level=untrusted_advisory, cannot grant authority.
- **Persistence readback:** actual SQLite LessonsManager (save_lesson → search_lessons) verified.
- **Isolation:** client B cannot retrieve client A lessons.

---

## 6. RESEARCHAGENDA EVOLUTION EVIDENCE

`ResearchAgenda.mutate(source, changes)` — every mutation recorded with provenance. Agenda mutation (promising_relationship added) changes candidate prioritization (h1 → h2). Not static.

---

## 7. ORGANIC REPLANNING EVIDENCE

`run_research_campaign()`: 2+ sequential decision cycles. Second decision depends on first observation (agenda mutated from outcome → different priority). Stop conditions explicit: no_available_hypotheses, promotable_finding_found, max_steps_reached.

---

## 8. PERSISTENCE READBACK EVIDENCE

`LessonsManager` (SQLite) — save_lesson → search_lessons. Cross-client isolation verified. Not simulated in-memory.

---

## 9. ADVERSARIAL MUTATION RESULTS

7 post-seal mutations (evidence_origin, target_backed, negative_control, vuln_class, target_identity, hypothesis_id, execution_identity) → ALL fail promotion. Pre-seal forged target_backed with offline origin → SemanticValidationError.

---

## 10. END-TO-END RESEARCH CAMPAIGN (real loopback)

Loopback HTTP server → campaign: recon → hypothesis A → experiment A → observation A → agenda update → hypothesis B/priority change → experiment B → observation B → finding lifecycle → ProofBundle → promotion_valid=True → persistence.

---

## 11. REGRESSION RESULTS

226 passed, 1 skipped (API app extra deps). All existing authority tests preserved. No authority component modified.

---

## 12. KNOWN LIMITATIONS

1. E2E campaign ProofBundle generation conditional on supported finding (if no supported finding, no bundle — that's correct fail-closed behavior).
2. Memory RAG is keyword-based (no vector DB — sufficient for demonstrated influence).
3. Not production-qualified, not independently validated — TEAM-2 acceptance required.
