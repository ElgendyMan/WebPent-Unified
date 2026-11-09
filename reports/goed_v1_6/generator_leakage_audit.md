# GOED v1.6 — Phase 3: Generator Leakage Audit
**Date:** 2026-09-03T07:04:29.564377+00:00

## Summary

| Risk Level | Count |
|------------|-------|
| MEDIUM/HIGH | 1 |
| LOW | 14 |
| NONE | 8 |

## By Classification

| Classification | Count |
|---------------|-------|
| GENERIC | 5 |
| GROUND-TRUTH-ONLY | 2 |
| LEAKAGE-RISK | 1 |
| NONE | 7 |
| TARGET-INDEPENDENT HEURISTIC | 8 |

## Key Risk Items

- **actor_identity:eve**: risk=MEDIUM — Actor name 'eve' appears in discovery engine. Check if used as knowledge or just as example.

## Conclusion

**Runtime leakage: NONE_CONFIRMED**

Most shared information is GENERIC (HTTP status codes) or TARGET-INDEPENDENT HEURISTIC (security-relevant name detection). The `/patched/` convention is used by the EVALUATOR for control route construction, NOT by the discovery engine for runtime discovery. Actor names appear only in docstrings/examples, not runtime logic.

**However:** The v1.5 generator uses predictable semantic names (admin, billing, audit, etc.) and predictable vulnerability placement per case index. This means v1.5 measures robustness over generator templates more than genuine generalization. **Phase 4 hidden target family is essential.**
