# UM-DR-38.1 — Security Gate Report (Phase 3)

Generated: 2026-11-17T04:58:58.439577+00:00 — from EXECUTION evidence, not from report text.

## Ruff ratchet

The UM-DR-38 published matrix carried `ruff-ratchet exit_code=1` with status PASS. The remediation this time: every finding attributable to the corrective work was FIXED at the root (including one real F821 that would have crashed the campaigns and the deliverables-era findings never re-baselined), and the final `check_ruff_ratchet.py --json` reports `pass=true, total=allowed` — recorded with its real exit code in UMDR38_GATE_RESULTS.json.

## Dependency security — verified from the raw scan

* Raw pip-audit JSON preserved: `deliverables/umdr38/raw/pip_audit_umdr38_1.json` (15794 bytes).
* soupsieve installed: [('4.1.1', [])] — ZERO open advisories; the UM-DR-38-era claim (four 2026 CVEs on 2.9.2, closed by the 4.1.1 bump) is consistent with the recorded advisory IDs (CVE-2026-126190..193, fixes 2.10/3.0.2/4.0.0).
* Remaining vulnerable packages (the audited waiver list): [('chromadb', '1.5.9', ['PYSEC-2026-311', 'PYSEC-2026-311', 'PYSEC-2026-3814', 'PYSEC-2026-3815', 'PYSEC-2026-3813'])] — chromadb's PYSEC entries carry NO upstream fix (optional RAG vector store, disabled in the production composition: DISABLE_RAG=true); each waiver is documented in scripts/quality/cve_allowlist.json.
* `uv lock --check`: PASS; `check_deps_gate.py`: PASS (real exit codes in UMDR38_GATE_RESULTS.json).
