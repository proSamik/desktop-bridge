#!/bin/sh
# Install desktop-bridge as launchd agents (start at login, restart on crash).
#   deploy/macos/install.sh                      # server only
#   deploy/macos/install.sh --tunnel             # + Cloudflare Tunnel (secret tunnel-token)
#   deploy/macos/install.sh --forward NAME SSH_HOST LOCAL_PORT [REMOTE_PORT]
#                                                # panel machine: SSH forward to a remote's admin API
# MB_LABEL (default com.desktop-bridge) prefixes the launchd labels.
set -e
DIR="$(cd "$(dirname "$0")/../.." && pwd)"
LABEL="${MB_LABEL:-com.desktop-bridge}"
AG="$HOME/Library/LaunchAgents"; U="gui/$(id -u)"
NODE_DIR="$(dirname "$(command -v node)")"
mkdir -p "$AG" "$DIR/data/logs"

plist() { # label, log name, program args...
  l="$1"; log="$2"; shift 2
  args=""; for a in "$@"; do args="$args<string>$a</string>"; done
  cat > "$AG/$l.plist" <<P
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$l</string>
  <key>ProgramArguments</key><array>$args</array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>$DIR/data/logs/$log.log</string>
  <key>StandardErrorPath</key><string>$DIR/data/logs/$log.log</string>
  <key>EnvironmentVariables</key><dict><key>HOME</key><string>$HOME</string><key>PATH</key><string>$NODE_DIR:$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
</dict></plist>
P
  plutil -lint "$AG/$l.plist" >/dev/null
  launchctl bootout "$U/$l" 2>/dev/null || true
  launchctl bootstrap "$U" "$AG/$l.plist"
  echo "loaded $l"
}

case "$1" in
  --forward)
    [ $# -ge 4 ] || { echo "usage: $0 --forward NAME SSH_HOST LOCAL_PORT [REMOTE_PORT]"; exit 1; }
    plist "$LABEL.forward-$2" "forward-$2" /usr/bin/ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -L "127.0.0.1:$4:127.0.0.1:${5:-8788}" "$3"
    echo "Add $2=http://127.0.0.1:$4 to MB_REMOTES in .env, then: desktop-bridge restart" ;;
  *)
    plist "$LABEL.server" server "$DIR/bin/run-server.sh"
    [ "$1" = "--tunnel" ] && plist "$LABEL.tunnel" tunnel "$DIR/bin/run-tunnel.sh"
    mkdir -p "$HOME/.local/bin" && ln -sf "$DIR/bin/desktop-bridge" "$HOME/.local/bin/desktop-bridge"
    echo "CLI: desktop-bridge open|status|restart|logs" ;;
esac
