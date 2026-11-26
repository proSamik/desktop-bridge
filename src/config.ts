import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

// Load .env from the working directory (services start in the install dir). Real env vars win.
try { (process as any).loadEnvFile?.(path.join(process.cwd(), ".env")); } catch {}
const env = process.env;

// ---------- platform ----------
export const IS_DARWIN = process.platform === "darwin";
export const IS_WIN = process.platform === "win32";
export const PLATFORM_NAME = IS_DARWIN ? "macOS" : IS_WIN ? "Windows" : "Linux";

// ---------- role ----------
// Legacy MB_MODE: "mac" = guarded + panel, "linux" = open + api.
const legacy = env.MB_MODE;
/** guarded: intent review, strict MCP allowlist, policy prompt. open: no review, full access. */
export const PROFILE: "guarded" | "open" = (env.MB_PROFILE as any) === "open" || (env.MB_PROFILE === undefined && legacy === "linux") ? "open" : "guarded";
export const GUARDED = PROFILE === "guarded";
/** panel: this machine serves the admin web UI (password + TOTP) and can manage remotes. api: key-auth admin API only, managed from another machine's panel. */
export const ADMIN_UI: "panel" | "api" = (env.MB_ADMIN_UI as any) === "api" || (env.MB_ADMIN_UI === undefined && legacy === "linux") ? "api" : "panel";
export const IS_PANEL = ADMIN_UI === "panel";
/** Display name of this machine (consent page, panel, notifications). */
export const NODE_NAME = env.MB_NODE_NAME || os.hostname().split(".")[0];

export const HOME = os.homedir();
/** Install dir: $MB_ROOT, else the working directory (services and npm scripts run from it). */
const defaultRoot = () => (fs.existsSync(path.join(process.cwd(), "package.json")) ? process.cwd() : path.join(HOME, "desktop-bridge"));
export const ROOT = env.MB_ROOT || defaultRoot();
export const CONFIG_DIR = path.join(ROOT, "config");
export const DATA_DIR = path.join(ROOT, "data");
export const RUNS_DIR = path.join(DATA_DIR, "runs");
export const DB_PATH = path.join(DATA_DIR, "bridge.db");
export const ALLOWED_MCP_PATH = path.join(CONFIG_DIR, "allowed-mcp.json");
export const POLICY_PATH = path.join(CONFIG_DIR, "policy.md");
export const CODEX_HOME_DIR = path.join(DATA_DIR, "codex-home");

export const MCP_PORT = Number(env.MB_MCP_PORT || 8787);
export const ADMIN_PORT = Number(env.MB_ADMIN_PORT || 8788);
export const BIND = "127.0.0.1";
export const DEFAULT_PUBLIC_URL = env.MB_PUBLIC_URL || `http://127.0.0.1:${env.MB_MCP_PORT || 8787}`;

/** Machines this panel manages: MB_REMOTES="air=http://127.0.0.1:18798,win=http://127.0.0.1:18799" (each URL is that machine's admin API, usually via an SSH forward). */
export const REMOTES: { name: string; url: string }[] = IS_PANEL
  ? (env.MB_REMOTES || "")
      .split(",").map((s) => s.trim()).filter(Boolean)
      .map((s) => { const i = s.indexOf("="); return { name: s.slice(0, i).trim(), url: s.slice(i + 1).trim().replace(/\/+$/, "") }; })
      .filter((r) => /^[a-z0-9-]{1,32}$/i.test(r.name) && /^https?:\/\//.test(r.url))
  : [];

// ---------- binaries ----------
const APPDATA = env.APPDATA || path.join(HOME, "AppData", "Roaming");
function firstExisting(...ps: string[]) {
  return ps.find((p) => { try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; } }) || ps[0];
}
export const CLAUDE_BIN = env.MB_CLAUDE_BIN || (IS_WIN
  ? firstExisting(path.join(HOME, ".local", "bin", "claude.exe"), path.join(APPDATA, "npm", "claude.cmd"))
  : firstExisting(path.join(HOME, ".local/bin/claude"), "/usr/local/bin/claude", "/opt/homebrew/bin/claude"));
export const CODEX_BIN = env.MB_CODEX_BIN || (IS_WIN
  ? firstExisting(path.join(APPDATA, "npm", "codex.cmd"), path.join(HOME, ".local", "bin", "codex.exe"))
  : firstExisting(path.join(HOME, ".local/bin/codex"), "/usr/local/bin/codex", "/opt/homebrew/bin/codex"));
/** Built-in tools for guarded runs; mcp__<server> is added for every server in allowed-mcp.json. */
export const GUARDED_BUILTIN_TOOLS = "Bash Read Write Edit Glob Grep WebFetch";
/** Subagent tool for guarded runs when allow_subagents is on. Older Claude Code calls it Task, newer calls it Agent; both are listed. */
export const SUBAGENT_TOOLS = "Task Agent";
/** Optional override of the max_concurrent_runs setting (1-10). */
/** MB_NOTIFY=0 turns off desktop notifications (test copies on other ports, headless boxes). Alerts are still recorded. */
export const NOTIFY_ENABLED = !/^(0|false|off|no)$/i.test(env.MB_NOTIFY?.trim() || "");
export const MAX_CONCURRENT_ENV = env.MB_MAX_CONCURRENT_RUNS?.trim() || undefined;

export const ACCESS_TTL_S = 3600;
export const REFRESH_TTL_S = 30 * 24 * 3600;
export const ADMIN_SESSION_TTL_S = 12 * 3600;

/** PATH for child processes (launchd/systemd/Task Scheduler give a bare PATH). */
export const CHILD_PATH = IS_WIN
  ? [path.join(HOME, ".local", "bin"), path.join(APPDATA, "npm"), env.PATH || env.Path || ""].join(path.delimiter)
  : [
      path.join(HOME, ".local/bin"), path.join(HOME, ".bun/bin"), path.join(HOME, ".npm-global/bin"),
      "/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    ].join(":");

// ---------- secrets: macOS Keychain (service $MB_KEYCHAIN_SERVICE, default "desktop-bridge"); elsewhere one file per secret in <ROOT>/secrets ----------
const KC_SERVICE = env.MB_KEYCHAIN_SERVICE || "desktop-bridge";
const SAFE_VALUE = /^[A-Za-z0-9_\-.$=+/:]+$/;
const SECRETS_DIR = path.join(ROOT, "secrets");

export function kcGet(account: string): string | null {
  if (!IS_DARWIN) {
    try { return fs.readFileSync(path.join(SECRETS_DIR, account), "utf8").trim() || null; } catch { return null; }
  }
  try {
    return execFileSync("security", ["find-generic-password", "-s", KC_SERVICE, "-a", account, "-w"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return null;
  }
}

/** macOS: writes via `security -i` on stdin so the secret never appears in argv / ps. */
export function kcSet(account: string, value: string): void {
  if (!SAFE_VALUE.test(value) || !SAFE_VALUE.test(account)) throw new Error("secret value has unsupported characters");
  if (!IS_DARWIN) {
    fs.mkdirSync(SECRETS_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(SECRETS_DIR, account), value, { mode: 0o600 });
    return;
  }
  const r = spawnSync("security", ["-i"], {
    input: `add-generic-password -U -s ${KC_SERVICE} -a ${account} -w "${value}"\n`,
    encoding: "utf8",
  });
  if (r.status !== 0 || /error/i.test(r.stderr || "")) throw new Error(`keychain write failed: ${r.stderr}`);
}

export const KC = {
  adminPasswordHash: "admin-password-hash",
  totpSecret: "totp-secret",
  tunnelToken: "tunnel-token",
  cloudflareApiToken: "cloudflare-api-token",
  /** On an "api" machine: the key its admin API accepts. */
  adminApiKey: "admin-api-key",
} as const;
/** On the panel machine: the key for remote <name>. */
export const remoteKeyName = (name: string) => `remote-key-${name}`;
/** Secrets injected into guarded runs: every ${NAME} referenced in allowed-mcp.json is read from secret "env-NAME". */
export const envSecretName = (v: string) => `env-${v}`;
export const ALLOWED_MCP_EXAMPLE = path.join(CONFIG_DIR, "allowed-mcp.example.json");
export const POLICY_EXAMPLE = path.join(CONFIG_DIR, "policy.example.md");
