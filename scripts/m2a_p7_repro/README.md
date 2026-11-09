# WP-J P7 Reproduction Harness (Dispatch #009-A)

Replays the lab P7 command shape locally — zero external-target
interaction; the target is a synthetic local HTTP server and the LLM is a
local OpenAI-compatible stand-in registered through the normal LOCAL
provider settings.

## Components

- `target_server.py` — synthetic in-scope target on `127.0.0.1:8977`
  (static pages + JSON endpoints; deliberately unexploitable).
- `fake_llm_server.py` — deterministic OpenAI-compatible chat endpoint on
  `127.0.0.1:11434/v1` (stand-in for the lab's configured LLM).
- `scope.yaml` — program-scope file for the target (real
  `webpent.scope.parser` grammar).
- `run_p7_repro.sh` — orchestration: starts both servers, runs
  `webpent.cli hunt --target http://127.0.0.1:8977 --scope scope.yaml …`,
  captures the exit code and the `production_trace` block from
  `campaign_summary.json`, and tears the servers down.

## Reproduced result (2026-10-06)

- EXIT_CODE=0
- `production_trace.complete = False`
- 8 of 12 required stages missing (see D-J §2)
- zero exceptions raised on the path

Evidence logs: `deliverables/m2a_evidence/p7/`.
Root-cause analysis: `deliverables/DJ_P7_ROOT_CAUSE_20261006.md`.
