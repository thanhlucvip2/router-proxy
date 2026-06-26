#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
exec python3 router_manager.py \
  --wan enp8s0 \
  --lan enp3s0f0,enp3s0f1 \
  --stop

