#!/usr/bin/env bash
# UM-DR-26: chunked full-suite runner (the sandbox OOM-kills one giant pytest).
# Splits tests/ into ~60-file chunks, runs each, appends the tail summary.
set -u
cd /home/z/my-project/webpent/WebPent_UNIFIED
PY=/home/z/.venv/bin/python3
LOG=/tmp/suite_chunks.log
: > "$LOG"
mapfile -t FILES < <($PY -m pytest --collect-only -q tests/ -p no:cacheprovider 2>/dev/null | rg '\.py$' | sed 's#::.*##' | sort -u)
TOTAL=${#FILES[@]}
echo "collected $TOTAL test files" | tee -a "$LOG"
CHUNK=55
FAILED_CHUNKS=()
for ((i=0; i<TOTAL; i+=CHUNK)); do
  CHUNK_FILES=("${FILES[@]:i:CHUNK}")
  CHUNK_ID=$(( i / CHUNK + 1 ))
  CHUNK_LOG=/tmp/chunk_${CHUNK_ID}.log
  if timeout 900 "$PY" -m pytest "${CHUNK_FILES[@]}" --tb=line -q --no-header -p no:cacheprovider >"$CHUNK_LOG" 2>&1; then
    STATUS=OK
  else
    STATUS=FAIL
    FAILED_CHUNKS+=("$CHUNK_ID")
  fi
  TAIL_LINE=$(tail -1 "$CHUNK_LOG")
  echo "chunk $CHUNK_ID [$STATUS]: $TAIL_LINE" | tee -a "$LOG"
done
echo "=== FAILED CHUNKS: ${FAILED_CHUNKS[*]:-none} ===" | tee -a "$LOG"
