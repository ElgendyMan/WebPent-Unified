# P1 Exception Cleanup Report

The audit counted AST handlers whose type was the bare name `Exception` in the nine unique files named by the sprint's top-ten list (the list names `validators.py` twice for two logical areas).

| Audited file | Before | After | Result |
|---|---:|---:|---|
| `src/webpent/production/autonomous_validation_v1.py` | 12 | 0 | Replaced with explicit expected tuples and fail-closed stage handling. |
| `src/webpent/production/validators.py` | 0 | 0 | No bare handler present. |
| `src/webpent/shared/http.py` | 9 | 0 | Replaced with typed URL, transport, browser, and runtime failures. |
| `src/webpent/production/modern_spine.py` | 6 | 0 | Replaced with typed boundary and transport failures. |
| `src/webpent/production/context_authority.py` | 1 | 0 | Replaced with expected filesystem/runtime failures. |
| `src/webpent/shared/fixture_registry.py` | 0 | 0 | No bare handler present. |
| `src/webpent/shared/untrusted_content.py` | 1 | 0 | Narrowed parser/runtime fallback. |
| `src/webpent/graph/builder.py` | 17 | 0 | Replaced with explicit best-effort and construction failures. |
| `src/webpent/agents/validator/agent.py` | 33 | 0 | Replaced with explicit persistence, HTTP, tool, and validator failure tuples. |

## Policy

- The frozen trust boundary was not weakened.
- `src/webpent/llm_researcher/tool_boundary.py` remains byte-identical to the frozen baseline and is covered by the exception-hygiene regression.
- Best-effort paths log and continue; authority, promotion, and transport failures remain fail-closed.
- No `except Exception: pass` remains in the audited set.

## Verification

`tests/test_p1_exception_hygiene.py` passed as part of the full suite. The five security gates and authoritative frozen-manifest verifier also passed with exit code `0`.
