#!/bin/sh
# Install desktop-bridge as a systemd *user* service (starts at boot with linger, restarts on crash).
#   deploy/linux/install.sh                          # server
#   deploy/linux/install.sh --tunnel                 # + token-run Cloudflare Tunnel as a user service
#   deploy/linux/install.sh --forward NAME SSH_HOST LOCAL_PORT [REMOTE_PORT]   # panel machine only
set -e
DIR="$(cd "$(dirname "$0")/../.." && pwd)"
UD="$HOME/.config/systemd/user"; mkdir -p "$UD"
NODE="$(command -v node)"

unit() { # name, description, ExecStart
  cat > "$UD/$1.service" <<U
[Unit]
Description=$2
After=network-online.target

[Service]
WorkingDirectory=$DIR
Environment=PATH=$(dirname "$NODE"):$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=$3
Restart=always
RestartSec=5
KillMode=process

[Install]
WantedBy=default.target
U
  systemctl --user daemon-reload
  systemctl --user enable --now "$1.service"
  echo "enabled $1.service"
}

case "$1" in
  --forward)
    [ $# -ge 4 ] || { echo "usage: $0 --forward NAME SSH_HOST LOCAL_PORT [REMOTE_PORT]"; exit 1; }
    unit "desktop-bridge-forward-$2" "desktop-bridge SSH forward to $2" \
      "/usr/bin/ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -L 127.0.0.1:$4:127.0.0.1:${5:-8788} $3"
    echo "Add $2=http://127.0.0.1:$4 to MB_REMOTES in .env, then: systemctl --user restart desktop-bridge" ;;
  *)
    unit desktop-bridge "desktop-bridge" "$DIR/bin/run-server.sh"
    [ "$1" = "--tunnel" ] && unit desktop-bridge-tunnel "desktop-bridge Cloudflare Tunnel" "$DIR/bin/run-tunnel.sh"
    if [ "$(loginctl show-user "$USER" -p Linger 2>/dev/null)" != "Linger=yes" ]; then
      echo "NOTE: to keep running while logged out / start at boot, run once:  sudo loginctl enable-linger $USER"
    fi
    mkdir -p "$HOME/.local/bin" && ln -sf "$DIR/bin/desktop-bridge" "$HOME/.local/bin/desktop-bridge" ;;
esac
