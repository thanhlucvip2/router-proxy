#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
exec python3 router_manager.py \
  --wan enp3s0f1 \
  --lan enp3s0f0,enp8s0 \
  --stop
