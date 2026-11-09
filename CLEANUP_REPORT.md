# REPOSITORY CLEANUP REPORT

**Classification: A — CLEAN** (materially consolidated, no unsafe deletion ambiguity)

---

## BEFORE/AFTER COUNTS
| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Root directory files | 74 | 45 | **-29** |
| Root .md files | 16 | 2 (README, SECURITY) | **-14** |
| Generated artifacts (txt/json/zip/sha) | 16 | 0 | **-16** |
| Tests passing | 251 | 251 | **0 new failures** |

---

## FILES DELETED (16 generated artifacts — reproducible, not source)
| File | Reason |
|------|--------|
| audit-key-sections.txt | GENERATED audit output |
| BASELINE.sha256.txt, POST.sha256.txt, combined_plan_baseline.sha256, webpent_archive_baseline.sha256 | GENERATED hash snapshots |
| baseline-symbols.txt, code-symbols.txt | GENERATED symbol dumps |
| baseline-vip-audit.txt | GENERATED audit |
| CHANGED_FILES.txt, GOVERNANCE.txt | TEMPORARY notes |
| combined_plan_traceability_matrix.json, doctor-offline.json, REGRESSION.json | GENERATED JSON artifacts |
| requirements-audit-v63.txt (330KB) | GENERATED audit |
| WebPent-GOED-v1.8.3-RealLLM-CausalBridge.zip (978KB) | GENERATED zip (reproducible) |
| WebPent_v60_Audit_Report_extracted.txt (55KB) | GENERATED extracted audit |
| source_runtime_callgraph.md | GENERATED callgraph (also exists in artifacts/) |

## FILES MOVED (13 milestone reports → docs/history/)
CLOSED_LOOP_RESEARCH_REPORT.md, DURABLE_RESEARCH_STATE_REPORT.md, HALF1_IMPLEMENTATION_REPORT.md, HALF2_IMPLEMENTATION_REPORT.md, HALF2_PRODUCTION_DATAFLOW_REPORT.md, HMAC_PROOF_AUTHORITY_REPORT.md, PHASE0_BASELINE.md, PRODUCTION_RUNTIME_CLOSURE_REPORT.md, PROJECT_BASELINE_AR.md, RAG_KNOWLEDGE_PACK_NOTES.md, RUNTIME_INTEGRATION_IMPLEMENTATION_REPORT.md, TEAM1_IMPLEMENTATION_REPORT.md, TEAM2_HOSTILE_FIXES_REPORT.md

Reason: HISTORICAL — preserved for maintenance/debugging value, but consolidated out of root.

## FILES CREATED (1 canonical)
- **SECURITY.md** — ONE canonical security/governance document (consolidates 11 security invariants: ScopeLaw, ToolBoundary, CausalGuard, ProofBundle HMAC, semantic proof integrity, PromotionFirewall, replay binding, modern/legacy authority, schema trust boundary, advisory memory, fail-closed).

## FILES RETAINED AS CANONICAL
- **README.md** — project overview, quick start
- **docs/architecture_simple.md** — canonical architecture (already exists, referenced by README)
- **docs/architecture_detailed.md** — detailed architecture (already exists)
- All source/test/config files — UNTOUCHED

## .GITIGNORE CHANGES
Added patterns for: *.sha256, *_baseline.txt, *_symbols.txt, *_audit.txt, requirements-audit-*.txt, combined_plan_*.json, doctor-offline.json, REGRESSION.json, CHANGED_FILES.txt, GOVERNANCE.txt, *.zip (except docs/), *.tmp, *.bak.

## ZERO FUNCTIONAL DRIFT VERIFICATION
- `import webpent` → OK
- 251 tests pass, 1 skipped (API deps), 0 failures
- No source/test files modified or deleted
- Security invariants unchanged

## REMAINING DEBT (intentionally preserved)
- docs/ (228 files), audit/ (58 files), artifacts/ (3 files) — NOT cleaned; may contain historical value, require deeper analysis. Classification: B-level debt for future cleanup cycles.
- Legacy source clusters — NOT touched; require behavioral equivalence proof before consolidation.
