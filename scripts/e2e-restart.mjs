// End-to-end test: runs interrupted by a bridge restart continue automatically (same run_id, same session).
// Starts its own throwaway instance from dist/ in a temp dir, so no running bridge is touched.
//   npm run build && node scripts/e2e-restart.mjs [claude|codex|hard|all]
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, execFileSync } from "node:child_process";

const REPO = new URL("..", import.meta.url).pathname;
const PORT = Number(process.env.MB_TEST_PORT || 9797);
const B = `http://127.0.0.1:${PORT}`;
const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "bridge-restart-"));
fs.mkdirSync(path.join(ROOT, "config"), { recursive: true });
for (const f of ["allowed-mcp.example.json", "policy.example.md"]) fs.copyFileSync(path.join(REPO, "config", f), path.join(ROOT, "config", f));
const ENV = {
  ...process.env, MB_ROOT: ROOT, MB_MCP_PORT: String(PORT), MB_ADMIN_PORT: String(PORT + 1), MB_PUBLIC_URL: B,
  MB_NODE_NAME: "restart-test", MB_PROFILE: process.env.MB_TEST_PROFILE || "guarded", MB_ADMIN_UI: "panel",
  MB_KEYCHAIN_SERVICE: "desktop-bridge-restart-test",
};
const only = process.argv[2] || "all";
const results = [];
const check = (name, ok, info = "") => { results.push(ok); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${info ? "  — " + info : ""}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ctl = (...a) => JSON.parse(execFileSync("node", [path.join(REPO, "dist/admin/ctl.js"), ...a], { cwd: ROOT, env: ENV, encoding: "utf8" }));

let server;
async function startServer() {
  server = spawn("node", [path.join(REPO, "dist/server.js")], { cwd: ROOT, env: ENV, stdio: ["ignore", "pipe", "pipe"] });
  for (let i = 0; i < 50; i++) { try { if ((await fetch(`${B}/healthz`)).ok) return; } catch {} await sleep(200); }
  throw new Error("server did not start");
}
async function stopServer(signal) {
  const s = server;
  const gone = new Promise((r) => s.once("exit", r));
  s.kill(signal);
  await gone;
}

async function mcp(token, method, params = {}) {
  const r = await fetch(`${B}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  return r.json();
}
const tool = async (T, name, args) => { const j = await mcp(T, "tools/call", { name, arguments: args }); try { return JSON.parse(j.result.content[0].text); } catch { return j; } };

async function token() {
  const reg = await (await fetch(`${B}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "restart test", redirect_uris: ["https://claude.ai/api/mcp/auth_callback"] }) })).json();
  const verifier = crypto.randomBytes(32).toString("base64url");
  const u = new URL(`${B}/authorize`);
  Object.entries({ response_type: "code", client_id: reg.client_id, redirect_uri: "https://claude.ai/api/mcp/auth_callback", code_challenge: crypto.createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256" }).forEach(([k, v]) => u.searchParams.set(k, v));
  const rid = /name="rid" value="([^"]+)"/.exec(await (await fetch(u)).text())[1];
  ctl("approve-auth", rid);
  const code = new URL((await (await fetch(`${B}/authorize/status/${rid}`)).json()).redirect).searchParams.get("code");
  const t = await (await fetch(`${B}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, client_id: reg.client_id, redirect_uri: "https://claude.ai/api/mcp/auth_callback", code_verifier: verifier }) })).json();
  return t.access_token;
}

const pidAlive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
const runRow = (id) => JSON.parse(execFileSync("sqlite3", ["-json", path.join(ROOT, "data/bridge.db"), `select status, pid, session_id, continue_session_id, resume_count, result_text, error from runs where id='${id}'`], { encoding: "utf8" }) || "[]")[0];

async function scenario(label, engine, signal) {
  const T = await token();
  const marker = `${label}-${crypto.randomBytes(3).toString("hex")}`;
  const prompt = `Do these two steps in order. Step 1: run the shell command \`sleep 20\`. Step 2: run \`echo ${marker}\`. Reply with the exact output of step 2 only.`;
  const r = await tool(T, engine === "codex" ? "run_codex" : "run_claude", engine === "codex" ? { prompt } : { prompt, model: "haiku", max_turns: 8 });
  const id = r.run_id;
  if (!id) return check(`${label}: run started`, false, JSON.stringify(r).slice(0, 200));
  // wait until the run is running and has a session, then a bit more so step 1 is in progress
  let row;
  for (let i = 0; i < 90; i++) { row = runRow(id); if (row?.status === "running" && row.session_id) break; await sleep(1000); }
  await sleep(6000);
  row = runRow(id);
  check(`${label}: running with a session before the restart`, row?.status === "running" && !!row.session_id, `${row?.status} ${row?.session_id}`);
  const oldPid = row?.pid;
  await stopServer(signal);
  const afterStop = runRow(id);
  check(`${label}: stays "running" across the ${signal} stop`, afterStop?.status === "running", afterStop?.status);
  await startServer();
  await sleep(1500);
  check(`${label}: old process is gone after boot`, !oldPid || !pidAlive(oldPid), `pid ${oldPid}`);
  const T2 = T; // tokens live in the DB, so the same client keeps working after the restart
  let d;
  for (let i = 0; i < 150; i++) { d = await tool(T2, "get_run", { run_id: id, tail_events: 0 }); if (!["queued", "running"].includes(d?.status)) break; await sleep(2000); }
  const final = runRow(id);
  check(`${label}: same run_id finishes after the restart`, d?.status === "succeeded", `${d?.status} ${d?.error || ""}`);
  check(`${label}: continued the same session (resume_count=1)`, final?.resume_count === 1 && final?.continue_session_id === row.session_id, `continue=${final?.continue_session_id} count=${final?.resume_count}`);
  check(`${label}: finished the original task`, (final?.result_text || "").includes(marker), (final?.result_text || "").slice(0, 100));
}

try {
  await startServer();
  if (only === "all" || only === "claude") await scenario("claude-graceful", "claude", "SIGTERM");
  if (only === "all" || only === "hard") await scenario("claude-hard-kill", "claude", "SIGKILL");
  if (only === "all" || only === "codex") await scenario("codex-graceful", "codex", "SIGTERM");
} catch (e) {
  check("test harness", false, e.message);
} finally {
  try { server.kill("SIGTERM"); } catch {}
  await sleep(1500);
  fs.rmSync(ROOT, { recursive: true, force: true });
}
console.log(`\n${results.filter(Boolean).length}/${results.length} passed`);
process.exit(results.every(Boolean) ? 0 : 1);
