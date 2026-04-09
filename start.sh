#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export CODEX_PROXY_CONFIG="${CODEX_PROXY_CONFIG:-$SCRIPT_DIR/config/proxy.config.json}"

# Stop an existing mitmdump for this addon before starting a new one.
pkill -f "mitmdump.*$SCRIPT_DIR/addon.py" 2>/dev/null || true

HOST=$(python3 -c "import json,sys; c=json.load(open(sys.argv[1])); print(c.get('host','127.0.0.1'))" "$CODEX_PROXY_CONFIG")
PORT=$(python3 -c "import json,sys; c=json.load(open(sys.argv[1])); print(c.get('port',8787))" "$CODEX_PROXY_CONFIG")

exec mitmdump \
  --mode regular \
  --listen-host "$HOST" \
  --listen-port "$PORT" \
  --set connection_strategy=lazy \
  -s "$SCRIPT_DIR/addon.py"
