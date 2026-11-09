#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose down -v
: > monitoring/nginx-logs/access.log
: > monitoring/nginx-logs/error.log
rm -f monitoring/nginx-logs/modsec_audit.log monitoring/nginx-logs/fail2ban.log
mkdir -p monitoring/nginx-logs
touch monitoring/nginx-logs/access.log monitoring/nginx-logs/error.log
docker compose up -d --build
echo "OK Emulator reset and running"
