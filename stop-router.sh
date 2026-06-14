#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
exec python3 router_manager.py \
  --wan enp7s0 \
  --lan enp10s0 \
  --stop


