#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
if [ ! -d node_modules ]; then
  npm install
fi
npm run build >/dev/null
exec node dist/main.js \
  --wan enp3s0f1 \
  --lan enp3s0f0,enp8s0 \
  --lan-cidr 10.42.0.1/21 \
  --host 0.0.0.0 \
  --port 4500 \
  --admin-user admin \
  --replace \
  --apply
