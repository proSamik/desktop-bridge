#!/bin/sh
# Service entry for a token-run (remote-managed) Cloudflare Tunnel.
# The token comes from the secret store (Keychain on macOS, secrets/ elsewhere) and is passed via env, not argv.
cd "$(dirname "$0")/.." || exit 1
TUNNEL_TOKEN="$(node dist/admin/ctl.js tunnel-token 2>/dev/null)"
if [ -z "$TUNNEL_TOKEN" ]; then echo "secret tunnel-token missing (npm run -s ctl -- secret-set tunnel-token)" >&2; sleep 30; exit 1; fi
export TUNNEL_TOKEN
exec "${CLOUDFLARED_BIN:-$(command -v cloudflared)}" tunnel --no-autoupdate run
