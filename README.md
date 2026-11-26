# desktop-bridge

A remote **MCP server** that lets your Claude assistant (claude.ai, Claude Desktop, any MCP client) run
**Claude Code** (`claude -p`) and **Codex** (`codex exec`) headless on your own machines: macOS, Linux or Windows.
Each machine gets its own public URL through a Cloudflare Tunnel. One machine hosts the admin panel for all of them.

```
 Claude (custom connector)                                     your machines
 ─────────────────────────                                     ─────────────
   https://<host-a>/mcp ──► Cloudflare Tunnel ──► 127.0.0.1:8787  machine A  (admin panel :8788, localhost only)
   https://<host-b>/mcp ──► Cloudflare Tunnel ──► 127.0.0.1:8787  machine B  (admin API :8788, localhost only)
                                                                      ▲
                                  SSH forward from A ─────────────────┘  (panel on A manages B)
```

Every machine is independent: own OAuth clients, tokens, database, run queue and tunnel. If the panel machine is
offline, the others keep serving; only approving *new* connections waits for the panel.

---

## Contents
1. [Features](#features)
2. [Roles: profile and admin style](#roles-profile-and-admin-style)
3. [Common install](#common-install)
4. [macOS](#macos)
5. [Linux](#linux)
6. [Windows](#windows)
7. [Making one machine the admin panel](#making-one-machine-the-admin-panel)
8. [Cloudflare Tunnel](#cloudflare-tunnel)
9. [Connect it to Claude](#connect-it-to-claude)
10. [MCP tools](#mcp-tools)
11. [Security model](#security-model)
12. [Configuration reference](#configuration-reference)
13. [Operations](#operations)
14. [Troubleshooting](#troubleshooting)

---

## Features
- **MCP over Streamable HTTP** at `/mcp`, bound to `127.0.0.1` and exposed only through the tunnel.
- **OAuth 2.1**: metadata (RFC 9728 / 8414), Dynamic Client Registration, authorization code + PKCE (S256 only),
  refresh-token rotation with reuse detection, revocation. Opaque tokens stored hashed; access 1 h, refresh 30 days.
- **Owner approval**: new clients start `pending`; only you can approve them (password + TOTP, or from the panel).
- **Async runs** of `claude -p` or `codex exec`, **up to 6 at once** by default (1-10, panel → Settings or
  `MB_MAX_CONCURRENT_RUNS`), extra runs queue with a `queue_position`; two runs never resume the same session at the
  same time. Logs stream to `data/runs/<id>.jsonl`; exit code, duration, cost (Claude), session/thread id are saved;
  cancel kills only that run's process tree.
- **Subagents**: a single `claude -p` run can start parallel subagents (the `Agent` tool, called `Task` in older Claude
  Code). Open machines allow it always; guarded machines allow it when Settings → *Allow subagents* is on (default).
- **Guarded profile** (optional): regex hard-deny list + a tool-less Claude reviewer before every run, strict MCP
  allowlist, appended policy prompt, config tamper detection.
- **Audit log** of every request (time, client, token, IP, CF-Ray, user agent, tool, status, prompt).
- **Origin IP allowlist** on `CF-Connecting-IP`, per-client rate limit, global kill switch, alerts + notifications.

## Roles: profile and admin style
Two independent settings in `.env`:

| Setting | Values | Meaning |
|---|---|---|
| `MB_PROFILE` | `guarded` (default) | Intent review, only MCP servers from `config/allowed-mcp.json`, policy prompt from `config/policy.md`, Claude permission mode from the panel (default `default`), Codex sandbox `workspace-write`. Tools are limited to `Bash Read Write Edit Glob Grep WebFetch`, the allowed MCP servers, and `Agent`/`Task` when subagents are allowed; subagents inherit the same limits. |
| | `open` | No review. Runs use your normal Claude Code / Codex config, Claude `bypassPermissions`, Codex without sandbox. Auth, IP allowlist, rate limit and kill switch still apply. |
| `MB_ADMIN_UI` | `panel` (default) | This machine serves the admin web UI (password + TOTP) and can manage other machines. |
| | `api` | No UI and no login. A key-protected admin API on localhost that a panel machine reaches over an SSH forward. |

Typical setup: your main computer is `guarded` + `panel`; build boxes or VMs are `open` + `api`.

## Common install
Requirements on every machine: **Node 20.6+**, **Claude Code** (`claude`, logged in) and/or **Codex** (`codex`, logged in),
**cloudflared**, and a Cloudflare account with a domain.

```sh
git clone https://github.com/proSamik/desktop-bridge.git && cd desktop-bridge
npm ci && npm run build
cp .env.example .env              # then edit: MB_NODE_NAME, MB_PROFILE, MB_ADMIN_UI, MB_PUBLIC_URL, ...
```

Then follow your platform section, set up the [tunnel](#cloudflare-tunnel), and [connect Claude](#connect-it-to-claude).
On first start a `guarded` machine copies `config/allowed-mcp.example.json` → `config/allowed-mcp.json` and
`config/policy.example.md` → `config/policy.md`. Edit those (or edit them in the panel → Settings, which shows a diff).

**allowed-mcp.json** uses the Claude Code `mcpServers` format. Put secrets in `${VARS}`, never inline:
```json
{
  "mcpServers": {
    "my-http-server": { "type": "http", "url": "http://127.0.0.1:<PORT>/mcp", "headers": { "Authorization": "Bearer ${MY_SERVER_TOKEN}" } },
    "my-stdio-server": { "type": "stdio", "command": "<absolute path to binary>", "args": ["<arg>"] }
  }
}
```
`npm run setup -- mcp-env` asks for each `${VAR}` and stores it as secret `env-<VAR>`; runs receive it as an env var.

## macOS
```sh
# .env:  MB_NODE_NAME=<name>  MB_PROFILE=guarded  MB_ADMIN_UI=panel  MB_PUBLIC_URL=https://<your-host>
npm run setup                          # admin password + TOTP (QR in the terminal) + MCP env secrets
deploy/macos/install.sh --tunnel       # launchd agents: server + tunnel (start at login, restart on crash)
desktop-bridge open                    # admin panel at http://127.0.0.1:8788
```
- Secrets live in the **Keychain** (service `$MB_KEYCHAIN_SERVICE`, default `desktop-bridge`).
- While a run is active the Mac is kept awake with `caffeinate -i -s` (AC power).
- Logs: `data/logs/*.log`. CLI: `desktop-bridge open|status|restart|logs|kill on|off`.
- Optional launcher app: `osacompile -o ~/Applications/"Desktop Bridge.app" -e 'do shell script "$HOME/.local/bin/desktop-bridge open"'`.

## Linux
```sh
# .env:  MB_NODE_NAME=<name>  MB_PROFILE=open|guarded  MB_ADMIN_UI=api|panel  MB_PUBLIC_URL=https://<your-host>
npm run setup                          # api machine: prints its admin API key once (copy it to the panel machine)
deploy/linux/install.sh                # systemd --user service "desktop-bridge"
sudo loginctl enable-linger "$USER"    # once: keep it running without a login session / start at boot
```
- Secrets live in `secrets/<name>` (mode 0600).
- Tunnel: either `deploy/linux/install.sh --tunnel` (token-run user service) or add a rule to an existing
  system `cloudflared` (see [Cloudflare Tunnel → option B](#option-b-add-a-hostname-to-an-existing-tunnel)).
- Headless boxes work: everything is CLI; the consent page opens in *your* browser, not on the server.
- Logs: `journalctl --user -u desktop-bridge -f`. CLI: `desktop-bridge status|restart|logs|kill on|off`.

## Windows
```powershell
# Requirements: Node 20.6+, Claude Code (claude.exe) and/or Codex (npm i -g @openai/codex), cloudflared (winget install Cloudflare.cloudflared)
copy .env.example .env        # MB_NODE_NAME=<name>  MB_PROFILE=...  MB_ADMIN_UI=...  MB_PUBLIC_URL=https://<your-host>
npm ci; npm run build
npm run setup                 # panel: password + TOTP; api: prints the admin API key
powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1     # Scheduled Task at logon, restarts on crash
cloudflared service install <TUNNEL_TOKEN>                               # tunnel as a Windows service (admin shell)
```
- Secrets live in `secrets\<name>`; protect the folder with NTFS permissions (only your user).
- Runs are stopped with `taskkill /T /F` (whole tree). `codex.cmd` is launched through `cmd` because npm shims need it.
- To reach a Windows machine's admin API from a panel machine, enable the built-in **OpenSSH Server** and use the
  SSH forward below, or put both machines on Tailscale and use the Tailscale IP with the same port forward.
- Sleep: set *Power & sleep → Never* while plugged in if the machine must stay reachable.

## Making one machine the admin panel
Pick one machine with `MB_ADMIN_UI=panel` (it can also run jobs itself). Every other machine uses `MB_ADMIN_UI=api`.

1. **On each remote (`api`) machine**: `npm run setup -- api-key` → copy the printed key.
2. **On the panel machine**, store it under the remote's name:
   ```sh
   npm run setup -- remote-key <remote-name>          # paste the key (hidden)
   # or over SSH without showing it: ssh <remote> 'cat <install-dir>/secrets/admin-api-key' | npm run -s ctl -- secret-set remote-key-<remote-name>
   ```
3. **Forward the remote's admin API** to a local port on the panel machine (the API never goes on the internet):
   ```sh
   deploy/macos/install.sh --forward <remote-name> <ssh-host> 18798 8788     # macOS (launchd, auto-reconnect)
   deploy/linux/install.sh --forward <remote-name> <ssh-host> 18798 8788     # Linux (systemd --user)
   # Windows: install.ps1 -Forward -Name <remote-name> -SshHost <ssh-host> -LocalPort 18798 -RemotePort 8788
   ```
   `<ssh-host>` must log in non-interactively (key auth; a `Host` entry in `~/.ssh/config`, which can use
   `cloudflared access ssh` as `ProxyCommand` if SSH itself goes through a tunnel). Use a different local port per remote.
4. **List the remotes** in the panel machine's `.env` and restart:
   ```
   MB_REMOTES=<remote-name>=http://127.0.0.1:18798,<other>=http://127.0.0.1:18799
   ```
The panel header now shows a switch: *this machine* plus one tab per remote. Each tab has the same pages
(Overview, Clients, Tokens, Requests, Runs, Settings). Alerts from remotes appear as local notifications.
On a remote, the OAuth consent page has no password form; it waits until you press **Approve** in the panel.

## Cloudflare Tunnel
Only the **MCP port** (default 8787) is routed. The admin port is never put behind a hostname.
Use one hostname per machine, e.g. `mcp-<machine>.<your-domain>`.

### Option A: new tunnel per machine (remote-managed)
```sh
npx wrangler login                                                   # once; its connectivity scope covers tunnels
node scripts/cloudflare-tunnel.mjs --name <tunnel-name> --hostname <host.your-domain>   # create/reuse tunnel, set ingress, store token
cloudflared tunnel login                                             # once; pick your zone (writes ~/.cloudflared/cert.pem)
cloudflared tunnel route dns <tunnel-id> <host.your-domain>          # proxied CNAME → <tunnel-id>.cfargotunnel.com
```
`npx wrangler tunnel create <name>` also works for the first step (then the script reuses it by name).
The script stores the tunnel token as secret `tunnel-token`; the installers' `--tunnel` option runs
`bin/run-tunnel.sh`, which passes it to `cloudflared` through the environment. On Windows use
`cloudflared service install <token>` instead (get the token with `npm run -s ctl -- tunnel-token`).
With a `CLOUDFLARE_API_TOKEN` that has Zone DNS:Edit you can add `--dns` to create the CNAME directly.

### Option B: add a hostname to an existing tunnel
If the machine already runs `cloudflared` with a local `config.yml`, add a rule **above** the final catch-all and restart:
```yaml
ingress:
  # ...existing rules...
  - hostname: <host.your-domain>
    service: http://localhost:8787
  - service: http_status:404
```
```sh
sudo cloudflared tunnel ingress validate && sudo systemctl restart cloudflared
cloudflared tunnel route dns <existing-tunnel-id> <host.your-domain>
```

### Who can reach it
- The bridge itself enforces an **IP allowlist** on `CF-Connecting-IP` (panel → Settings → IP allowlist).
  Default: Anthropic's outbound ranges `160.79.104.0/21, 153.61.208.0/20`
  ([source](https://platform.claude.com/docs/en/api/ip-addresses)). Add your own IP if your browser must open the
  consent page through the tunnel (it must, during connector setup). Cloudflare overwrites any client-sent
  `CF-Connecting-IP`, so it cannot be spoofed through the tunnel.
- Optional edge rule (blocks before traffic reaches you): `CLOUDFLARE_API_TOKEN=<token with Zone WAF:Edit> node scripts/cloudflare-waf.mjs --hostname <host> --allow "<your-ip>"`.
- Don't open a new hostname before its DNS record exists: resolvers (including 1.1.1.1) cache the miss for up to 30 min.

## Connect it to Claude
1. Claude → Settings → Connectors → **Add custom connector** → `https://<host.your-domain>/mcp`.
2. Claude registers a client (it shows up as **pending** + notification) and opens the consent page in your browser.
3. Approve: password + 6-digit code on the consent page (panel machine), or **Approve** under *Connection requests
   waiting* in the panel (works for every machine). The page continues by itself.
4. Use one connector per machine; each has its own URL, clients and tokens.

## MCP tools
| Tool | Purpose |
|---|---|
| `run_claude({prompt, cwd?, resume_session_id?, model?, max_turns?, engine?})` | Start an async run; `engine` = `claude` (default) or `codex`. Returns `run_id`. |
| `run_codex({prompt, cwd?, resume_session_id?, model?})` | Same as `run_claude` with `engine: "codex"`. |
| `get_run({run_id, tail_events?})` | Status, verdict, exit code, duration, cost, `session_id`, final text, last events; `queue_position` while queued. |
| `list_runs({limit?})`, `cancel_run({run_id})` | Recent runs of this client (with `queue_position` for queued ones); cancel stops only that run. |
| `read_claude_logs({session_id?, project_path?, tail?})` | Claude Code transcripts under `~/.claude/projects`. |
| `read_codex_logs({session_id?, tail?})` | Codex transcripts under `~/.codex/sessions`. |
| `list_allowed_mcp()`, `ping()` | MCP servers runs can use; health check. |

## Security model
- Auth is never relaxed by the review: every `/mcp` call needs a valid bearer token from an **approved** client.
- Admin panel and admin API listen on `127.0.0.1` only, check the `Host` header (DNS-rebinding), refuse requests
  that carry Cloudflare headers, use CSRF tokens + `SameSite=Strict` cookies, and lock out after failed logins.
- Guarded profile: hard-deny regexes (credential/keychain dumps, `~/.ssh`, browser cookies, disabling
  FileVault/firewall/SIP/Gatekeeper, `rm -rf` on `/` or home, editing the bridge, `curl | sh`, MCP config changes,
  account/password changes), then a tool-less `claude -p` reviewer → `allow` / `deny` / `ask` (held for you).
  Runs refuse to start if `allowed-mcp.json` or `policy.md` changed outside the panel. This is a soft layer.
- Open profile: anything the logged-in user can do, the run can do. Use it only on machines where that is acceptable.

## Configuration reference
All variables are optional and documented in [`.env.example`](.env.example). `.env` is read from the install dir at start.
Runtime settings (kill switch, max concurrent runs, allow subagents, rate limit, Claude permission mode, Codex sandbox,
review model, IP allowlist, public URL) live in `data/bridge.db` and are changed in the panel → Settings.
`MB_MAX_CONCURRENT_RUNS` in `.env` overrides the concurrency setting (the panel field is then read-only).

**Secrets** (never in git, never in `.env`): macOS Keychain service `$MB_KEYCHAIN_SERVICE`, or `secrets/<name>` on Linux/Windows.

| Secret | Where | What |
|---|---|---|
| `admin-password-hash`, `totp-secret` | panel machine | Admin login (`npm run setup`) |
| `admin-api-key` | each `api` machine | Key its admin API accepts (`npm run setup -- api-key`) |
| `remote-key-<name>` | panel machine | That remote's `admin-api-key` |
| `env-<VAR>` | guarded machines | Values for `${VAR}` in `allowed-mcp.json` (`npm run setup -- mcp-env`) |
| `tunnel-token` | machines using a token-run tunnel | Written by `scripts/cloudflare-tunnel.mjs` |

## Operations
```sh
desktop-bridge status | restart | logs | kill on|off      # macOS / Linux
npm run ctl -- status|clients|approve <id>|approve-auth <id>|revoke <id>|kill on|off|runs|pin-config
node scripts/e2e-local.mjs [none|run|codex|mcp|parallel|subagents]   # end-to-end test (approves via ctl; "none" skips model runs)
```
Health: `GET /healthz` (alias `/health`): `active_runs`, `max_concurrent_runs`, kill switch (details only on localhost).

**Updating safely.** A restart marks every running job as failed (`bridge restarted`), so restart only when idle:
```sh
curl -s http://127.0.0.1:8787/healthz          # wait until "active_runs":[] (optionally: kill switch on to stop new runs)
git pull && npm ci && npm run build
desktop-bridge restart                         # macOS launchd / Linux systemd --user; Windows: restart the "desktop-bridge" task
```
**Testing without touching a live instance:** start a second copy on other ports with its own data dir, e.g.
`MB_ROOT=/tmp/bridge-test MB_MCP_PORT=9787 MB_ADMIN_PORT=9788 MB_PUBLIC_URL=http://127.0.0.1:9787 MB_MAX_CONCURRENT_RUNS=3 node dist/server.js`
(copy your `config/` into `/tmp/bridge-test/config` first), then `MB_ROOT=/tmp/bridge-test MB_MCP_PORT=9787 node scripts/e2e-local.mjs`.

## Troubleshooting
| Symptom | Fix |
|---|---|
| Browser: "can't find the server" | DNS not created yet or a cached miss: check `dig @8.8.8.8 <host>`; wait ≤30 min or flush the local DNS cache. |
| `403` on the consent page | Your IP is not in the allowlist (panel → Settings → IP allowlist). |
| `401 invalid_token` in a browser at `/mcp` | Expected: `/mcp` needs a bearer token; only MCP clients use it. |
| Panel tab shows "unreachable" | The SSH forward to that remote is down: check the forward service and `ssh <host>` without a password. |
| Runs fail immediately | `data/runs/<id>.stderr.log`; check `claude` / `codex` are logged in for the service user. |
| A run stays `queued` with free slots | It resumes a session another active run is using; it starts when that run ends. |
| Run failed with "bridge restarted" | The service restarted mid-run. Restart only when `/healthz` shows no `active_runs`. |
| "changed outside the admin panel" | Someone edited `config/` directly: review it, then Settings → *Accept on-disk version*. |

## License
[MIT](LICENSE)
