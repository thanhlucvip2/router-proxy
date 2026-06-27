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
  --stop
