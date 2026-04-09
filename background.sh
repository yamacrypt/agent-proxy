#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
nohup bash "$SCRIPT_DIR/start.sh" > "$SCRIPT_DIR/app.log" 2>&1 & echo $!
