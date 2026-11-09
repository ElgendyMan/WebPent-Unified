# v97 Phase 1 Evidence — skill selector

**Timestamp:** 2026-08-23 UTC

## Decision

Implemented **option (a)** from v97: `get_skill_reference()` now resolves `reference_source: payload_corpus` through the local `knowledge_retrieval.retrieve_knowledge_context()` path with `doc_types=("payload",)`, bounded `per_type_k=2`, and `max_chars=2000`. It does not add live network I/O. The caller in `payload_generator` continues to place the result inside the existing untrusted-data wrapper before any LLM advisory call. Corpus content remains reference data and is never target evidence.

## Regression evidence

The new test is `tests/test_skill_selector.py::test_payload_generation_skill_returns_local_payload_reference`.

Before the fix:

```text
Command: PYTHONPATH=src:/tmp/webpent-release-run/bbscout/src .venv/bin/pytest -q tests/test_skill_selector.py
Result: exit 1; 1 failed
Failure: get_skill_reference(...) returned '' for a payload_generation/xss skill.
Raw stdout: skill_selector.before.stdout.txt
```

After the fix:

```text
Command: PYTHONPATH=src:/tmp/webpent-release-run/bbscout/src .venv/bin/pytest -q tests/test_skill_selector.py
Result: exit 0; 1 passed
Raw stdout: skill_selector.after.stdout.txt
Raw stderr: skill_selector.after.stderr.txt
```

## Required quality gates after the fix

| Gate | Command | Result |
|---|---|---|
| Ruff | `.venv/bin/ruff check src` | PASS, exit 0 |
| Vulture | `vulture src --min-confidence 80` | PASS, exit 0 |
| Bandit | `.venv/bin/bandit -r src -x tests` | BLOCKED, exit 1: 77 pre-existing low/medium findings, 0 high |
| Full tests | `PYTHONPATH=src:/tmp/webpent-release-run/bbscout/src .venv/bin/pytest -q` | PASS, exit 0 |
| Compile | `.venv/bin/python -m compileall src` | PASS, exit 0 |

The Bandit result is retained as a blocker rather than hidden. The existing release policy uses the high-severity gate (`-lll`), which remains green; the v97 instruction requested the broader command, whose baseline findings have not been suppressed or falsely declared resolved.

## Reproducibility

All raw outputs are stored under this directory. The complete Bandit text and JSON reports are preserved as `bandit.stdout.txt` and `bandit.json`. No credentials, cookies, raw HTTP bodies, or target evidence are included.
