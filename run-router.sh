#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
exec python3 router_manager.py \
  --wan enp7s0 \
  --lan enp10s0 \
  --lan-cidr 10.42.0.1/24 \
  --host 0.0.0.0 \
  --port 8080 \
  --admin-user admin \
  --replace \
  --apply
