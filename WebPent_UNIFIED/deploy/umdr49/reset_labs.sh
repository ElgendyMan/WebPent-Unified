#!/usr/bin/env bash
# UM-DR-49 P0.2 — deterministic reset before EVERY campaign (law 6).
# docker path (owner env):      ./deploy/umdr49/reset_labs.sh --docker
# native path (49 sandbox):     ./deploy/umdr49/reset_labs.sh --native
set -euo pipefail
MODE="${1:---native}"
if [[ "$MODE" == "--docker" ]]; then
  docker compose -f deploy/umdr49/docker-compose.yml down -v
  docker compose -f deploy/umdr49/docker-compose.yml up -d --wait
  echo "labs reset (docker): juiceshop:3000 webgoat:8080/8888 dvwa:80"
else
  # native: kill + fresh state dirs + relaunch (fresh containers are the
  # docker path's determinism; natively we drop the state dirs the apps
  # persist to and restart the processes)
  pkill -f "juice-shop" 2>/dev/null || true
  pkill -f "webgoat.jar" 2>/dev/null || true
  sleep 1
  rm -rf /home/z/my-project/labs/juice-shop/data_njsscan /home/z/my-project/labs/juice-shop/logs
  mkdir -p /home/z/my-project/labs/state && rm -rf /home/z/my-project/labs/state/*
  cd /home/z/my-project/labs/juice-shop && (nohup npm start > /home/z/my-project/worklogs/juiceshop_run.log 2>&1 &)
  cd /home/z/my-project/labs && (nohup java -jar webgoat.jar --server.port=8080 --webwolf.port=8888 --spring.jpa.hibernate.ddl-auto=create-drop > /home/z/my-project/worklogs/webgoat_run.log 2>&1 &)
  sleep 20
  echo "labs reset (native): juiceshop:3000 webgoat:8080/8888 dvwa:UNAVAILABLE(env gap)"
fi
