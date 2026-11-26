import fs from "node:fs";
import Database from "better-sqlite3";
import { DATA_DIR, DB_PATH, RUNS_DIR, DEFAULT_PUBLIC_URL, GUARDED, IS_WIN } from "./config.js";

fs.mkdirSync(RUNS_DIR, { recursive: true, mode: 0o700 });
if (!IS_WIN) fs.chmodSync(DATA_DIR, 0o700);

export const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");

db.exec(`
CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',          -- pending | approved | revoked
  is_mine INTEGER NOT NULL DEFAULT 0,
  auth_method TEXT NOT NULL DEFAULT 'none',
  secret_hash TEXT,
  reg_ip TEXT,
  reg_ua TEXT,
  ips TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL,
  first_seen INTEGER,
  last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id),
  kind TEXT NOT NULL,                               -- access | refresh
  hash TEXT NOT NULL UNIQUE,
  family_id TEXT NOT NULL,
  scope TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_used INTEGER,
  revoked_at INTEGER,
  rotated_at INTEGER
);
CREATE INDEX IF NOT EXISTS tokens_client ON tokens(client_id);
CREATE TABLE IF NOT EXISTS auth_requests (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id),
  redirect_uri TEXT NOT NULL,
  state TEXT,
  code_challenge TEXT NOT NULL,
  scope TEXT,
  resource TEXT,
  ip TEXT,
  ua TEXT,
  status TEXT NOT NULL DEFAULT 'pending',          -- pending | approved | denied | delivered
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope TEXT,
  resource TEXT,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  client_id TEXT,
  token_id TEXT,
  ip TEXT,
  cf_ray TEXT,
  ua TEXT,
  method TEXT,
  path TEXT,
  tool TEXT,
  status INTEGER,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS requests_ts ON requests(ts);
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  client_id TEXT,
  token_id TEXT,
  ip TEXT,
  prompt TEXT NOT NULL,
  cwd TEXT NOT NULL,
  resume_session_id TEXT,
  model TEXT,
  max_turns INTEGER,
  permission_mode TEXT,
  status TEXT NOT NULL,      -- reviewing | awaiting_approval | queued | running | succeeded | failed | cancelled | denied
  verdict TEXT,
  verdict_reason TEXT,
  verdict_stage TEXT,        -- regex | llm | admin
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  ended_at INTEGER,
  exit_code INTEGER,
  duration_ms INTEGER,
  cost_usd REAL,
  session_id TEXT,
  result_text TEXT,
  mcp_servers TEXT,
  pid INTEGER,
  error TEXT
);
CREATE INDEX IF NOT EXISTS runs_created ON runs(created_at);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin_sessions (
  id_hash TEXT PRIMARY KEY,
  csrf TEXT NOT NULL,
  ip TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS known_ips (ip TEXT PRIMARY KEY, first_seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  acked INTEGER NOT NULL DEFAULT 0
);
`);

const DEFAULTS: Record<string, string> = {
  kill_switch: "0",
  rate_limit_per_hour: "30",
  permission_mode: GUARDED ? "default" : "bypassPermissions",
  codex_sandbox: GUARDED ? "workspace-write" : "danger-full-access",
  public_base_url: DEFAULT_PUBLIC_URL,
  review_model: "sonnet",
  allowed_mcp_sha256: "",
  policy_sha256: "",
  last_totp_counter: "0",
  max_concurrent_runs: "6",
  allow_subagents: "1",
  ip_allowlist: "160.79.104.0/21, 153.61.208.0/20",
};
// migrations
const runCols = (db.prepare("PRAGMA table_info(runs)").all() as any[]).map((c) => c.name);
if (!runCols.includes("engine")) db.exec("ALTER TABLE runs ADD COLUMN engine TEXT NOT NULL DEFAULT 'claude'");

const ins = db.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)");
for (const [k, v] of Object.entries(DEFAULTS)) ins.run(k, v);

export function getSetting(key: string): string {
  const row = db.prepare("SELECT value FROM settings WHERE key=?").get(key) as { value: string } | undefined;
  return row?.value ?? DEFAULTS[key] ?? "";
}
export function setSetting(key: string, value: string) {
  db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(key, value);
}
export const now = () => Math.floor(Date.now() / 1000);
