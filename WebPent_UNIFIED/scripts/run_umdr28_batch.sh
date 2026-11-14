#!/usr/bin/env bash
# Resumable chunk runner: runs chunks START..END from /tmp/umdr28_test_files.txt
set -u
cd /home/z/my-project/webpent/WebPent_UNIFIED
PY=/home/z/.venv/bin/python3
LOG=/tmp/suite_chunks_umdr28.log
touch "$LOG"
mapfile -t FILES < /tmp/umdr28_test_files.txt
TOTAL=${#FILES[@]}
CHUNK=55
START=${1:-1}
END=${2:-999}
for ((i=(START-1)*CHUNK; i<TOTAL; i+=CHUNK)); do
  CHUNK_ID=$(( i / CHUNK + 1 ))
  if (( CHUNK_ID < START )); then continue; fi
  if (( CHUNK_ID > END )); then break; fi
  CHUNK_FILES=("${FILES[@]:i:CHUNK}")
  CHUNK_LOG=/tmp/umdr28_chunk_${CHUNK_ID}.log
  if timeout 560 "$PY" -m pytest "${CHUNK_FILES[@]}" --tb=line -q --no-header -p no:cacheprovider >"$CHUNK_LOG" 2>&1; then
    STATUS=OK
  else
    STATUS=FAIL
  fi
  echo "chunk $CHUNK_ID [$STATUS]: $(tail -1 "$CHUNK_LOG")" >> "$LOG"
done
echo "batch done (chunks $START..$END)" >> "$LOG"
