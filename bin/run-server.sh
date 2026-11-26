#!/bin/sh
# Service entry (launchd/systemd): run desktop-bridge from its install directory so .env is picked up.
cd "$(dirname "$0")/.." || exit 1
NODE="${MB_NODE_BIN:-$(command -v node)}"
exec "$NODE" dist/server.js
