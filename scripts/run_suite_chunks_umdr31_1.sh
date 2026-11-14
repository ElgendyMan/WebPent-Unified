#!/usr/bin/env bash
# UM-DR-31.1: chunked full-suite runner — one invocation runs a slice of
# chunks so a tool call stays under the timeout. State: /tmp/u311_suite/
# Usage: run_suite_chunks_umdr31_1.sh <first_chunk> <last_chunk> <total_chunks>
set -u
cd /home/z/my-project/webpent/WebPent_UNIFIED
PY=/home/z/.venv/bin/python3
STATE=/tmp/u311_suite
mkdir -p "$STATE"
FIRST=$1; LAST=$2; TOTAL=${3:-13}
CHUNK=55
if [ ! -s "$STATE/files.txt" ]; then
  mapfile -t FILES < <($PY -m pytest --collect-only -q tests/ -p no:cacheprovider 2>/dev/null | sed 's#::.*##' | rg '^tests/.*\.py$' | sort -u)
  printf '%s\n' "${FILES[@]}" > "$STATE/files.txt"
  echo "collected ${#FILES[@]} test files" > "$STATE/progress.log"
fi
mapfile -t FILES < "$STATE/files.txt"
N=${#FILES[@]}
for ((c=FIRST; c<=LAST; c++)); do
  start=$(( (c-1)*CHUNK ))
  end=$(( start+CHUNK ))
  [ $start -ge $N ] && break
  CHUNK_FILES=("${FILES[@]:start:CHUNK}")
  LOG="$STATE/chunk_${c}.log"
  if timeout 560 "$PY" -m pytest "${CHUNK_FILES[@]}" --tb=line -q --no-header -p no:cacheprovider >"$LOG" 2>&1; then
    echo "chunk $c/$TOTAL [OK]: $(tail -1 "$LOG")" | tee -a "$STATE/progress.log"
  else
    echo "chunk $c/$TOTAL [FAIL]: $(tail -1 "$LOG")" | tee -a "$STATE/progress.log"
  fi
done
