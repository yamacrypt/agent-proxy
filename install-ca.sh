#!/bin/bash
set -euo pipefail

SOURCE_CERT="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"
TARGET_CERT="/usr/local/share/ca-certificates/mitmproxy.crt"

if [[ ! -f "$SOURCE_CERT" ]]; then
  cat <<EOF
mitmproxy CA certificate was not found at:
  $SOURCE_CERT

Run mitmproxy or mitmdump once first so the CA is generated, then rerun this script.
EOF
  exit 1
fi

sudo cp "$SOURCE_CERT" "$TARGET_CERT"
sudo update-ca-certificates

cat <<EOF
Installed mitmproxy CA into the system trust store:
  $TARGET_CERT

This is a one-time setup for this machine unless ~/.mitmproxy is recreated.
EOF
