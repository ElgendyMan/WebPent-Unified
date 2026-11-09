#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p monitoring/nginx-logs
touch monitoring/nginx-logs/access.log monitoring/nginx-logs/error.log
docker compose up -d --build
echo "OK Emulator running"
echo "  Juice Shop:   http://localhost:3000"
echo "  DVWA:         http://localhost:8080 (admin/password)"
echo "  Custom API:   http://localhost:9000"
echo "  WAF (Juice):  http://localhost:80"
echo "  Rate-limited: http://localhost:8000"
echo "  Monitoring:   http://localhost:9090"
echo ""
echo "WARNING: all traffic is logged. Local training only."
