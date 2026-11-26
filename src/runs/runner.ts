import fs from "node:fs";
import path from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import {
  ALLOWED_MCP_PATH, POLICY_PATH, RUNS_DIR, CLAUDE_BIN, CODEX_BIN, CODEX_HOME_DIR, CHILD_PATH, HOME, GUARDED_BUILTIN_TOOLS, ROOT,
  kcGet, envSecretName, GUARDED, IS_DARWIN, IS_WIN, MAX_CONCURRENT_ENV, SUBAGENT_TOOLS,
} from "../config.js";
import { db, now, getSetting } from "../db.js";
import { fileSha, alert, randId } from "../util.js";
import { reviewIntent, type Verdict } from "../review/review.js";

export const PERMISSION_MODES = ["default", "acceptEdits", "dontAsk", "plan", "bypassPermissions"] as const;
export const CODEX_SANDBOXES = ["read-only", "workspace-write", "danger-full-access"] as const;
export const ENGINES = ["claude", "codex"] as const;
export type Engine = (typeof ENGINES)[number];

type ActiveRun = { runId: string; child: ChildProcess; caffeinate?: ChildProcess; resumeId: string | null };
/** Runs currently executing, keyed by run id. Up to maxConcurrentRuns() at once. */
const active = new Map<string, ActiveRun>();

/** $MB_MAX_CONCURRENT_RUNS wins over the panel setting; clamped to 1-10. */
export function maxConcurrentRuns() {
  const n = Number(MAX_CONCURRENT_ENV ?? getSetting("max_concurrent_runs"));
  return Number.isFinite(n) ? Math.min(10, Math.max(1, Math.floor(n))) : 6;
}

export type NewRun = {
  prompt: string; cwd?: string; resume_session_id?: string; model?: string; max_turns?: number; engine?: Engine;
  clientId: string; tokenId: string; ip: string;
};

export function runsInLastHour(clientId: string) {
  return (db.prepare("SELECT COUNT(*) n FROM runs WHERE client_id=? AND created_at>?").get(clientId, now() - 3600) as any).n as number;
}

export async function createRun(r: NewRun): Promise<{ run_id: string; status: string; engine: Engine; verdict?: string; reason?: string }> {
  if (getSetting("kill_switch") === "1") throw new Error("kill switch is on; runs are disabled");
  const limit = Number(getSetting("rate_limit_per_hour")) || 30;
  if (runsInLastHour(r.clientId) >= limit) throw new Error(`rate limit: ${limit} runs/hour for this client`);
  const engine: Engine = r.engine === "codex" ? "codex" : "claude";

  const cwd = path.resolve(r.cwd ? r.cwd.replace(/^~(?=$|\/)/, HOME) : HOME);
  if (!fs.existsSync(cwd) || !fs.statSync(cwd).isDirectory()) throw new Error(`cwd does not exist: ${cwd}`);
  if (r.resume_session_id && !/^[0-9a-f-]{36}$/i.test(r.resume_session_id)) throw new Error("resume_session_id must be a session UUID");
  if (r.model && !/^[A-Za-z0-9._\-[\]]{1,64}$/.test(r.model)) throw new Error("invalid model");

  const id = randId("run");
  db.prepare(
    `INSERT INTO runs(id,client_id,token_id,ip,prompt,cwd,resume_session_id,model,max_turns,engine,status,created_at)
     VALUES(?,?,?,?,?,?,?,?,?,?,'reviewing',?)`
  ).run(id, r.clientId, r.tokenId, r.ip, r.prompt, cwd, r.resume_session_id || null, r.model || null, r.max_turns ?? null, engine, now());

  // "open" profile: no intent review (owner's choice); auth, IP allowlist, rate limit and kill switch still apply.
  const v: Verdict | { verdict: "allow"; reason: string; stage: "none" } = !GUARDED
    ? { verdict: "allow", reason: "review disabled (open profile)", stage: "none" }
    : await reviewIntent(r.prompt, cwd, r.resume_session_id);
  const status = v.verdict === "allow" ? "queued" : v.verdict === "deny" ? "denied" : "awaiting_approval";
  db.prepare("UPDATE runs SET status=?, verdict=?, verdict_reason=?, verdict_stage=? WHERE id=? AND status='reviewing'").run(
    status, v.verdict, v.reason, v.stage, id
  );
  if (v.verdict === "deny") alert("run_denied", `Run refused (${v.stage}): ${v.reason}`);
  if (v.verdict === "ask") alert("run_ask", `Run waiting for your approval: ${r.prompt.slice(0, 80)}`);
  pump();
  return { run_id: id, status, engine, verdict: v.verdict, reason: v.reason };
}

export function approveAskRun(id: string) {
  const r = db.prepare("UPDATE runs SET status='queued', verdict_stage='admin', verdict_reason=verdict_reason||' | approved by owner' WHERE id=? AND status='awaiting_approval'").run(id);
  pump();
  return r.changes > 0;
}
export function rejectAskRun(id: string) {
  return db.prepare("UPDATE runs SET status='denied', verdict_stage='admin', verdict_reason=verdict_reason||' | rejected by owner', ended_at=? WHERE id=? AND status='awaiting_approval'").run(now(), id).changes > 0;
}

function killTree(child: ChildProcess) {
  if (!child.pid) return;
  if (IS_WIN) {
    spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore", windowsHide: true });
    return;
  }
  try { process.kill(-child.pid, "SIGTERM"); } catch {}
  setTimeout(() => { try { process.kill(-child.pid!, "SIGKILL"); } catch {} }, 5000).unref();
}

export function cancelRun(id: string, reason = "cancelled"): boolean {
  const row = db.prepare("SELECT status FROM runs WHERE id=?").get(id) as any;
  if (!row) return false;
  if (["queued", "reviewing", "awaiting_approval"].includes(row.status)) {
    db.prepare("UPDATE runs SET status='cancelled', error=?, ended_at=? WHERE id=?").run(reason, now(), id);
    return true;
  }
  const a = active.get(id);
  if (row.status === "running" && a) {
    db.prepare("UPDATE runs SET error=? WHERE id=?").run(reason, id);
    killTree(a.child);
    return true;
  }
  return false;
}

export function cancelRunsForClient(clientId: string) {
  const ids = db.prepare("SELECT id FROM runs WHERE client_id=? AND status IN ('queued','reviewing','awaiting_approval','running')").all(clientId) as any[];
  for (const { id } of ids) cancelRun(id, "client revoked");
}
export function cancelAllRuns(reason: string) {
  const ids = db.prepare("SELECT id FROM runs WHERE status IN ('queued','reviewing','awaiting_approval','running')").all() as any[];
  for (const { id } of ids) cancelRun(id, reason);
}

function configIntact(): string | null {
  if (!GUARDED) return null;
  const a = fileSha(ALLOWED_MCP_PATH), p = fileSha(POLICY_PATH);
  if (a !== getSetting("allowed_mcp_sha256")) return "config/allowed-mcp.json changed outside the admin panel";
  if (p !== getSetting("policy_sha256")) return "config/policy.md changed outside the admin panel";
  return null;
}

/** Oldest queued run that doesn't resume a session an active run is already using. */
function nextQueued(): any | undefined {
  const busy = new Set([...active.values()].map((a) => a.resumeId).filter(Boolean));
  const queued = db.prepare("SELECT * FROM runs WHERE status='queued' ORDER BY created_at, rowid").all() as any[];
  return queued.find((q) => !q.resume_session_id || !busy.has(q.resume_session_id));
}

/** Starts queued runs until the concurrency limit is reached or nothing eligible is left. */
export function pump() {
  if (getSetting("kill_switch") === "1") return;
  while (active.size < maxConcurrentRuns()) {
    const next = nextQueued();
    if (!next) return;
    const c = db.prepare("SELECT status FROM clients WHERE id=?").get(next.client_id) as any;
    if (c && c.status !== "approved") {
      db.prepare("UPDATE runs SET status='cancelled', error='client not approved', ended_at=? WHERE id=?").run(now(), next.id);
      continue;
    }
    const tamper = configIntact();
    if (tamper) {
      db.prepare("UPDATE runs SET status='failed', error=?, ended_at=? WHERE id=?").run(tamper, now(), next.id);
      alert("tamper", `Run blocked: ${tamper}. Review and re-save it in the admin panel.`);
      continue;
    }
    try {
      start(next);
    } catch (e: any) {
      db.prepare("UPDATE runs SET status='failed', error=?, ended_at=? WHERE id=?").run(String(e.message).slice(0, 500), now(), next.id);
      active.delete(next.id);
    }
  }
}

/** 1-based position among queued runs (oldest first), or null if the run isn't queued. */
export function queuePosition(runId: string): number | null {
  const ids = (db.prepare("SELECT id FROM runs WHERE status='queued' ORDER BY created_at, rowid").all() as any[]).map((r) => r.id);
  const i = ids.indexOf(runId);
  return i < 0 ? null : i + 1;
}

// ---------- engine command lines ----------
function allowedMcp(): Record<string, any> {
  try { return JSON.parse(fs.readFileSync(ALLOWED_MCP_PATH, "utf8")).mcpServers || {}; } catch { return {}; }
}
/** Guarded runs get the built-in tools (+ the subagent tool when allowed) plus every server in allowed-mcp.json.
 *  Subagents inherit the same --allowedTools / --disallowedTools, so allowing them widens nothing else. */
function guardedTools() {
  const sub = getSetting("allow_subagents") === "1" ? [SUBAGENT_TOOLS] : [];
  return [GUARDED_BUILTIN_TOOLS, ...sub, ...Object.keys(allowedMcp()).map((n) => `mcp__${n}`)].join(" ");
}
/** ${NAME} references in allowed-mcp.json are filled from secrets named "env-NAME" (Keychain / secrets dir). */
function mcpEnvSecrets(): Record<string, string> {
  const out: Record<string, string> = {};
  let raw = "";
  try { raw = fs.readFileSync(ALLOWED_MCP_PATH, "utf8"); } catch {}
  for (const m of raw.matchAll(/\$\{([A-Z0-9_]+)\}/g)) {
    const v = kcGet(envSecretName(m[1]));
    if (v) out[m[1]] = v;
  }
  return out;
}
function claudeArgs(run: any) {
  const mode = getSetting("permission_mode");
  const args = ["-p", "--output-format", "stream-json", "--verbose"];
  if (GUARDED) {
    args.push(
      "--mcp-config", ALLOWED_MCP_PATH,
      "--strict-mcp-config",
      "--append-system-prompt", fs.readFileSync(POLICY_PATH, "utf8"),
      "--allowedTools", guardedTools(),
      "--disallowedTools", `Edit(${ROOT}/**) Write(${ROOT}/**) Read(${ROOT}/data/**)`,
    );
  }
  args.push("--permission-mode", (PERMISSION_MODES as readonly string[]).includes(mode) ? mode : "default");
  if (run.resume_session_id) args.push("--resume", run.resume_session_id);
  if (run.model) args.push("--model", run.model);
  if (run.max_turns) args.push("--max-turns", String(run.max_turns));
  return { bin: CLAUDE_BIN, args, stdin: run.prompt, mode };
}

const tomlStr = (s: string) => JSON.stringify(s); // JSON string escaping is valid TOML basic-string escaping

/** guarded: a dedicated CODEX_HOME whose config.toml holds only the allowed MCP servers (Codex's version of --strict-mcp-config). */
function prepareGuardedCodexHome() {
  fs.mkdirSync(CODEX_HOME_DIR, { recursive: true, mode: 0o700 });
  let toml = "# generated by desktop-bridge from config/allowed-mcp.json on every run; do not edit\n";
  for (const [name, s] of Object.entries<any>(allowedMcp())) {
    toml += `\n[mcp_servers.${tomlStr(name)}]\n`;
    if (s.url) {
      toml += `url = ${tomlStr(s.url)}\n`;
      const auth = s.headers?.Authorization || s.headers?.authorization;
      const m = typeof auth === "string" ? /^Bearer \$\{([A-Z0-9_]+)\}$/.exec(auth) : null;
      if (m) toml += `bearer_token_env_var = ${tomlStr(m[1])}\n`;
    } else {
      toml += `command = ${tomlStr(s.command)}\nargs = [${(s.args || []).map(tomlStr).join(", ")}]\n`;
    }
  }
  fs.writeFileSync(path.join(CODEX_HOME_DIR, "config.toml"), toml, { mode: 0o600 });
  // Reuse the owner's Codex login.
  const auth = path.join(CODEX_HOME_DIR, "auth.json");
  const src = path.join(HOME, ".codex", "auth.json");
  try { fs.lstatSync(auth); } catch {
    try { fs.symlinkSync(src, auth); } catch { if (fs.existsSync(src)) fs.copyFileSync(src, auth); } // Windows may not allow symlinks
  }
}

function codexArgs(run: any) {
  const sandbox = getSetting("codex_sandbox");
  const sb = (CODEX_SANDBOXES as readonly string[]).includes(sandbox) ? sandbox : "workspace-write";
  const args = ["exec"];
  if (run.resume_session_id) args.push("resume", run.resume_session_id);
  args.push("--json", "--skip-git-repo-check");
  if (sb === "danger-full-access") args.push("--dangerously-bypass-approvals-and-sandbox");
  else args.push("-c", `sandbox_mode="${sb}"`);
  if (run.model) args.push("-m", run.model);
  args.push("-");
  let stdin = run.prompt;
  if (GUARDED) {
    prepareGuardedCodexHome();
    // Codex has no --append-system-prompt; the policy goes first, as instructions from the bridge.
    stdin = `<bridge-policy>\n${fs.readFileSync(POLICY_PATH, "utf8")}\n</bridge-policy>\n\n${run.prompt}`;
  }
  return { bin: CODEX_BIN, args, stdin, mode: `codex:${sb}` };
}

function start(run: any) {
  const engine: Engine = run.engine === "codex" ? "codex" : "claude";
  const cmd = engine === "codex" ? codexArgs(run) : claudeArgs(run);

  const logPath = path.join(RUNS_DIR, `${run.id}.jsonl`);
  const log = fs.createWriteStream(logPath, { flags: "a", mode: 0o600 });
  const errLog = fs.createWriteStream(path.join(RUNS_DIR, `${run.id}.stderr.log`), { flags: "a", mode: 0o600 });

  const env: NodeJS.ProcessEnv = { ...process.env, PATH: CHILD_PATH, HOME, BRIDGE_RUN_ID: run.id };
  if (IS_WIN) env.Path = CHILD_PATH;
  if (GUARDED) {
    Object.assign(env, mcpEnvSecrets());
    if (engine === "codex") env.CODEX_HOME = CODEX_HOME_DIR;
  }

  // Windows .cmd shims (npm-installed codex) need a shell; arguments are fixed flags or regex-validated ids.
  const needsShell = IS_WIN && /\.(cmd|bat)$/i.test(cmd.bin);
  const child = spawn(cmd.bin, cmd.args, { cwd: run.cwd, env, detached: !IS_WIN, windowsHide: true, shell: needsShell, stdio: ["pipe", "pipe", "pipe"] });
  const started = Date.now();
  db.prepare("UPDATE runs SET status='running', started_at=?, pid=?, permission_mode=? WHERE id=?").run(now(), child.pid ?? null, cmd.mode, run.id);
  const caf = IS_DARWIN && child.pid ? spawn("caffeinate", ["-i", "-s", "-w", String(child.pid)], { stdio: "ignore" }) : undefined;
  active.set(run.id, { runId: run.id, child, caffeinate: caf, resumeId: run.resume_session_id || null });

  let buf = "";
  const r = { done: false, isError: false, text: null as string | null, cost: null as number | null, session: null as string | null };
  const onEvent = (ev: any) => {
    if (engine === "claude") {
      if (ev.type === "system" && ev.subtype === "init") {
        db.prepare("UPDATE runs SET session_id=?, mcp_servers=? WHERE id=?").run(ev.session_id ?? null, JSON.stringify(ev.mcp_servers ?? []), run.id);
      } else if (ev.type === "result") {
        r.done = true; r.isError = !!ev.is_error; r.text = ev.result != null ? String(ev.result) : null;
        r.cost = ev.total_cost_usd ?? null; r.session = ev.session_id ?? null;
      }
    } else {
      if (ev.type === "thread.started" && ev.thread_id) {
        r.session = ev.thread_id;
        db.prepare("UPDATE runs SET session_id=? WHERE id=?").run(ev.thread_id, run.id);
      } else if (ev.type === "item.completed" && ev.item?.type === "agent_message") {
        r.text = String(ev.item.text ?? "");
      } else if (ev.type === "turn.completed") {
        r.done = true;
      } else if (ev.type === "turn.failed" || ev.type === "error") {
        r.isError = true; r.text = r.text ?? String(ev.error?.message ?? ev.message ?? "codex error");
      }
    }
  };
  child.stdout!.on("data", (d: Buffer) => {
    log.write(d);
    buf += d.toString();
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      try { onEvent(JSON.parse(line)); } catch {}
    }
  });
  child.stderr!.on("data", (d) => errLog.write(d));
  child.stdin!.on("error", () => {});
  child.stdin!.end(cmd.stdin);

  let finished = false;
  const finish = (code: number | null, errMsg?: string) => {
    if (finished) return; finished = true;
    log.end(); errLog.end();
    try { caf?.kill(); } catch {}
    const row = db.prepare("SELECT error FROM runs WHERE id=?").get(run.id) as any;
    const cancelled = !!row?.error;
    const status = cancelled ? "cancelled" : code === 0 && r.done && !r.isError ? "succeeded" : "failed";
    db.prepare(
      `UPDATE runs SET status=?, exit_code=?, ended_at=?, duration_ms=?, cost_usd=?, session_id=COALESCE(?, session_id),
       result_text=?, error=COALESCE(error, ?) WHERE id=?`
    ).run(status, code, now(), Date.now() - started, r.cost, r.session, r.text != null ? r.text.slice(0, 200_000) : null, errMsg ?? null, run.id);
    active.delete(run.id);
    setImmediate(pump);
  };
  child.on("error", (e) => finish(null, e.message));
  child.on("close", (code) => finish(code));
}

/** On boot: anything left "running"/"reviewing" from a previous process is dead. */
export function recoverOnBoot() {
  db.prepare("UPDATE runs SET status='failed', error='bridge restarted', ended_at=? WHERE status IN ('running','reviewing')").run(now());
  pump();
}
export const activeRunIds = () => [...active.keys()];
/** Backward compatibility: first active run id, or null. */
export const currentRunId = () => activeRunIds()[0] ?? null;
