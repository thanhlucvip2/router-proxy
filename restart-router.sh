#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p state

./stop-router.sh || true
sleep 1

nohup ./run-router.sh > state/router_manager.restart.log 2>&1 &
echo "Router manager restarting in background. Log: state/router_manager.restart.log"
