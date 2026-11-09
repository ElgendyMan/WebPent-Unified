#!/usr/bin/env bash
# WebPent GOED v1.8 Release Candidate — Startup Script
# Usage: ./start_webpent.sh [--port PORT] [--config CONFIG]

set -euo pipefail

PORT="${PORT:-8765}"
CONFIG="${CONFIG:-release/config_schema.json}"
WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"

cd "$WORKDIR"
export PYTHONPATH="$WORKDIR/src"

echo "=== WebPent GOED v1.8 Release Candidate ==="
echo "Workdir: $WORKDIR"
echo "Python: $(python3.12 --version)"
echo "Port: $PORT"
echo "Config: $CONFIG"

echo ""
echo "Running health check..."
python3.12 release/health_check.py --config "$CONFIG"

echo ""
echo "Starting WebPent API on port $PORT..."
echo "Note: API server module is part of the optional layer."
echo "For benchmark execution, use: python3.12 release/benchmark_runner.py"
echo ""
echo "Governance: vip_qualified=false, P10=CLOSED, P9=CLOSED"
echo "Scope: local_synthetic_authorized_targets_only"
