# GOED v1.5 — Phase 2: Discovery Boundary Audit
**Date:** 2026-09-03T06:35:25.769696+00:00

## Objective
Re-audit all discovery dependencies and separate:
GENERIC / TARGET-INDEPENDENT HEURISTIC / TARGET-SPECIFIC / BENCHMARK LEAKAGE RISK

## Pattern Scan Results

| Pattern | Count | Risk Assessment |
|---------|-------|-----------------|
| Hardcoded case IDs | 0 | NONE |
| Hardcoded target names | 0 | NONE |
| Hardcoded tenant-a/b | 0 | NONE |
| Hardcoded u001-u999 IDs | 0 | NONE |
| Benchmark imports | 0 | NONE |
| 'ground truth' text refs | 3 | Documentation/isolation only |
| Qualification refs | 0 | NONE |
| Expected vulnerability labels | 0 | NONE |

## Classification

### A. GENERIC
- Standard web entry points: /, /api, /health, /openapi.json, /docs, /robots.txt
- HTTP status code semantics (200/401/403/404)
- Authorization header patterns (X-Actor, X-Authorization-Outcome, etc.)
- OpenAPI spec structure detection
- HTML href/src/action link extraction
- JSON path-like string extraction

### B. TARGET-INDEPENDENT HEURISTIC
- Security-relevant path term detection (admin, auth, user, profile, billing, tenant, internal, private, audit, reset, secret, config, role, permission, access, message)
- Path pattern entity inference (/api/{entity}/...)
- Response semantic digest comparison
- Actor context response differential analysis

### C. TARGET-SPECIFIC
- None found in generative runtime logic

### D. BENCHMARK LEAKAGE RISK (contained, not entering runtime)
- KnowledgeIsolationBoundary.BENCHMARK_LEAKAGE_PATTERNS — these are DETECTION targets, not used as knowledge
- Documentation strings mentioning 'ground-truth labels' in negative context (what NOT to receive)
- Coverage accounting documentation mentioning 'ground-truth case' in evaluation context

## Key Finding

The `ground_truth` text references exist ONLY in:
1. **KnowledgeIsolationBoundary.BENCHMARK_LEAKAGE_PATTERNS** — the list of patterns the isolation layer actively BLOCKS.
2. **Documentation strings** describing what the engine must NOT receive.

These are NOT used as discovery knowledge. They are part of the ISOLATION DEFENSE.

## Automated Isolation Tests

Created: `tests/goed_v1_5/test_isolation_boundary.py`
- Verifies no benchmark modules imported into GOED runtime
- Verifies no target-specific IDs in discovery logic
- Verifies leakage detection works correctly

## Conclusion

✅ **Discovery boundary VERIFIED.** No benchmark knowledge enters the generative runtime.
All target-specific knowledge is contained in benchmark definitions and evaluators,
not in the discovery engine itself.
