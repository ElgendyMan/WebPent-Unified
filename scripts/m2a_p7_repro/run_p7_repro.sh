#!/usr/bin/env bash
# WP-J reproduction (Dispatch #009-A): replay the lab P7 command shape locally.
#   webpent hunt --target <local> --scope <file>  ->  observed: EXIT 0 + production_trace.complete=false
# Captures exit code, stdout/stderr, and campaign_summary.json trace fields.
set -u
ROOT=/home/z/my-project/work/m2impl/p7
VENV=/home/z/.venv/bin
TREE=/home/z/my-project/work/m2impl/v7x
LOG="$ROOT/logs"

cd "$ROOT"
export PYTHONPATH="$TREE/src"
export LOCAL_LLM_ENABLED=true
export LOCAL_LLM_API_KEY=repro-not-a-real-key
export LOCAL_LLM_URL=http://127.0.0.1:11434/v1
export LOCAL_LLM_MODEL=repro-fake

echo "== targets ==" | tee "$LOG/p7_repro.log"
"$VENV/python" target_server.py > "$LOG/target_server.log" 2>&1 &
TARGET_PID=$!
"$VENV/python" fake_llm_server.py > "$LOG/fake_llm.log" 2>&1 &
LLM_PID=$!
sleep 1.5
curl -s -o /dev/null -w "target_http=%{http_code}\n" http://127.0.0.1:8977/ | tee -a "$LOG/p7_repro.log"
curl -s -o /dev/null -w "llm_http=%{http_code}\n" http://127.0.0.1:11434/v1/models | tee -a "$LOG/p7_repro.log"

echo "== CLI hunt (lab P7 command shape) ==" | tee -a "$LOG/p7_repro.log"
set +e
"$VENV/python" -m webpent.cli hunt \
  --target http://127.0.0.1:8977 \
  --scope "$ROOT/scope.yaml" \
  --engagement-id p7repro-01 \
  --artifact-root "$ROOT/artifacts/p7repro-01" \
  --time-budget 180 --request-budget 60 --llm-budget 1.0 \
  --max-hypotheses 6 --max-decisions 6 --max-llm-calls 6 --max-cost-usd 0.10 \
  > "$LOG/p7_hunt_stdout.log" 2> "$LOG/p7_hunt_stderr.log"
EXIT_CODE=$?
set -e
echo "EXIT_CODE=$EXIT_CODE" | tee -a "$LOG/p7_repro.log"

echo "== trace fields from campaign_summary.json ==" | tee -a "$LOG/p7_repro.log"
"$VENV/python" - "$ROOT/artifacts/p7repro-01/campaign_summary.json" <<'PY' 2>&1 | tee -a "$LOG/p7_repro.log"
import json, sys
try:
    summary = json.loads(open(sys.argv[1]).read())
except Exception as exc:
    print(f"campaign_summary.json unreadable: {exc}")
    raise SystemExit(0)
trace = summary.get("production_trace") or {}
print("production_trace.complete =", trace.get("complete"))
print("missing_required_stages  =", trace.get("missing_required_stages"))
print("stages_seen              =", trace.get("stages_seen"))
print("candidates_generated     =", summary.get("candidates_generated"))
print("candidates_executable    =", summary.get("candidates_executable"))
print("confirmed_findings       =", summary.get("confirmed_findings"))
print("agent_graph_events       =", summary.get("agent_graph_events"))
print("program_scope.enabled    =", (summary.get("program_scope") or {}).get("enabled"))
print("program_scope.halted     =", (summary.get("program_scope") or {}).get("halted"))
PY

echo "== stderr tail ==" | tee -a "$LOG/p7_repro.log"
tail -5 "$LOG/p7_hunt_stderr.log" | tee -a "$LOG/p7_repro.log"

kill $TARGET_PID $LLM_PID 2>/dev/null
wait $TARGET_PID $LLM_PID 2>/dev/null
echo "== done ==" | tee -a "$LOG/p7_repro.log"
