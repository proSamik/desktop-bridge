// Local end-to-end test against http://127.0.0.1:8787 (no tunnel).
// Owner approval is done through the ctl CLI (local shell = owner), not the password/TOTP form.
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";

const B = `http://127.0.0.1:${process.env.MB_MCP_PORT || 8787}`;
const RESOURCE = (await (await fetch(`${B}/.well-known/oauth-protected-resource`)).json()).resource;
const ROOT = new URL("..", import.meta.url).pathname;
// Data/config of the instance under test (MB_ROOT lets the test run against a separate instance on other ports).
const DATA_ROOT = (process.env.MB_ROOT || ROOT).replace(/\/?$/, "/");
const ALLOWED = Object.keys(JSON.parse(fs.readFileSync(`${DATA_ROOT}config/allowed-mcp.json`, "utf8")).mcpServers || {}).sort();
const ctl = (...a) => JSON.parse(execFileSync("node", ["dist/admin/ctl.js", ...a], { cwd: ROOT, encoding: "utf8" }));
const results = [];
const check = (name, ok, info = "") => { results.push({ name, ok }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${info ? "  — " + info : ""}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function mcp(token, method, params = {}) {
  const r = await fetch(`${B}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ jsonrpc: "2.0", id: Math.floor(Math.random() * 1e6), method, params }),
  });
  const text = await r.text();
  let body; try { body = JSON.parse(text); } catch { body = text; }
  return { status: r.status, headers: r.headers, body };
}
const tool = async (token, name, args = {}) => {
  const r = await mcp(token, "tools/call", { name, arguments: args });
  const t = r.body?.result?.content?.[0]?.text;
  let parsed; try { parsed = JSON.parse(t); } catch { parsed = t; }
  return { status: r.status, isError: !!r.body?.result?.isError, data: parsed, raw: r.body };
};

async function connectClient(name) {
  const reg = await (await fetch(`${B}/register`, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: name, redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], token_endpoint_auth_method: "none" }) })).json();
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const u = new URL(`${B}/authorize`);
  Object.entries({ response_type: "code", client_id: reg.client_id, redirect_uri: "https://claude.ai/api/mcp/auth_callback", code_challenge: challenge, code_challenge_method: "S256", state: "xyz", resource: RESOURCE }).forEach(([k, v]) => u.searchParams.set(k, v));
  const page = await (await fetch(u)).text();
  const rid = /name="rid" value="([^"]+)"/.exec(page)?.[1];
  return { reg, verifier, rid, page };
}
async function finish(c) {
  const st = await (await fetch(`${B}/authorize/status/${c.rid}`)).json();
  const code = new URL(st.redirect).searchParams.get("code");
  const tok = await (await fetch(`${B}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, client_id: c.reg.client_id, redirect_uri: "https://claude.ai/api/mcp/auth_callback", code_verifier: c.verifier }) })).json();
  return tok;
}
async function waitRun(token, run_id, maxS = 300) {
  for (let i = 0; i < maxS / 2; i++) {
    const r = await tool(token, "get_run", { run_id, tail_events: 0 });
    if (!["queued", "running", "reviewing"].includes(r.data?.status)) return r.data;
    await sleep(2000);
  }
  return null;
}

const only = process.argv[2];

// 1. No token -> 401 + WWW-Authenticate
{
  const r = await mcp(null, "tools/list");
  const wa = r.headers.get("www-authenticate") || "";
  check("/mcp without token -> 401 with resource_metadata", r.status === 401 && wa.includes("/.well-known/oauth-protected-resource"), wa);
  const prm = await (await fetch(`${B}/.well-known/oauth-protected-resource`)).json();
  const asm = await (await fetch(`${B}/.well-known/oauth-authorization-server`)).json();
  check("metadata served (PRM + AS, S256 only)", prm.resource?.endsWith("/mcp") && JSON.stringify(asm.code_challenge_methods_supported) === '["S256"]');
}

// 2. New client lands pending; consent page requires login
const c = await connectClient("e2e test client");
{
  const row = ctl("clients").find((x) => x.id === c.reg.client_id);
  check("new client lands as pending", row?.status === "pending");
  check("consent page shows details and requires password + TOTP", c.page.includes('name="password"') && c.page.includes('name="totp"') && c.page.includes("e2e test client"));
  const bad = await fetch(`${B}/authorize/decision`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ rid: c.rid, password: "wrong", totp: "000000", decision: "approve" }), redirect: "manual" });
  check("consent with wrong credentials is rejected (no code)", bad.status === 401);
  const tokTry = await (await fetch(`${B}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code: "x", client_id: c.reg.client_id, code_verifier: "y".repeat(43) }) })).json();
  check("pending client cannot get tokens", tokTry.error === "unauthorized_client");
  const badPkce = await fetch(`${B}/authorize?response_type=code&client_id=${c.reg.client_id}&redirect_uri=https://claude.ai/api/mcp/auth_callback&code_challenge=abc&code_challenge_method=plain`, { redirect: "manual" });
  check("PKCE plain rejected", (badPkce.headers.get("location") || "").includes("PKCE"));
}

// Owner approves (ctl), client exchanges code
ctl("approve-auth", c.rid);
const tok = await finish(c);
check("approved client receives access + refresh tokens", !!tok.access_token && !!tok.refresh_token && tok.expires_in === 3600);

// Refresh rotation + reuse detection
{
  const r1 = await (await fetch(`${B}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tok.refresh_token, client_id: c.reg.client_id }) })).json();
  const r2 = await (await fetch(`${B}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tok.refresh_token, client_id: c.reg.client_id }) })).json();
  check("refresh rotates; reusing old refresh token fails", !!r1.access_token && r2.error === "invalid_grant");
  const after = await mcp(r1.access_token, "tools/list");
  check("reuse detection revoked the rotated family", after.status === 401);
}

// New token pair for the rest
const c2 = await connectClient("e2e client 2");
ctl("approve-auth", c2.rid);
const T = (await finish(c2)).access_token;

{
  const r = await mcp(T, "tools/list");
  const names = (r.body?.result?.tools || []).map((t) => t.name).sort();
  check("tools/list", names.join(",") === "cancel_run,get_run,list_allowed_mcp,list_runs,ping,read_claude_logs,read_codex_logs,run_claude,run_codex", names.join(","));
  const p = await tool(T, "ping");
  check("ping", p.data?.pong === true);
  const am = await tool(T, "list_allowed_mcp");
  check("list_allowed_mcp matches config/allowed-mcp.json", am.data.map((x) => x.name).sort().join(",") === ALLOWED.join(","));
}

// 3. echo hello run
let echoRun;
if (!only || only === "run") {
  const r = await tool(T, "run_claude", { prompt: 'Run the shell command: echo "hello from the Mac" and reply with its exact output.', model: "haiku", max_turns: 4 });
  echoRun = await waitRun(T, r.data.run_id);
  check("echo run succeeded and returned text", echoRun?.status === "succeeded" && /hello from the Mac/.test(echoRun?.result_text || ""), `${echoRun?.status} verdict=${echoRun?.verdict} text=${(echoRun?.result_text || echoRun?.error || "").slice(0, 120)}`);
  check("get_run returned session_id", /^[0-9a-f-]{36}$/.test(echoRun?.session_id || ""), echoRun?.session_id);
  const logs = await tool(T, "read_claude_logs", { session_id: echoRun?.session_id, tail: 20 });
  check("read_claude_logs shows that session", logs.data?.session_id === echoRun?.session_id && logs.data?.entries?.length > 0, logs.data?.project_dir);
  const full = execFileSync("sqlite3", [`${DATA_ROOT}data/bridge.db`, `select mcp_servers from runs where id='${r.data.run_id}'`], { encoding: "utf8" });
  const servers = JSON.parse(full || "[]").map((s) => s.name).sort();
  check("run saw only allowed MCP servers", servers.every((n) => ALLOWED.includes(n)), servers.join(","));
}

// 3b. codex exec run
if (!only || only === "run" || only === "codex") {
  const r = await tool(T, "run_codex", { prompt: 'Run the shell command: echo "hello from codex" and reply with its exact output only.' });
  const d = r.data.status === "denied" ? r.data : await waitRun(T, r.data.run_id);
  check("codex run succeeded and returned text", d?.status === "succeeded" && /hello from codex/.test(d?.result_text || ""), `${d?.status} ${d?.engine} text=${(d?.result_text || d?.error || "").slice(0, 120)}`);
  check("codex run has thread id", /^[0-9a-f-]{36}$/.test(d?.session_id || ""), d?.session_id);
  const logs = await tool(T, "read_codex_logs", { session_id: d?.session_id, tail: 10 });
  check("read_codex_logs shows that session", logs.data?.session_id === d?.session_id && logs.data?.entries?.length > 0, logs.data?.error || logs.data?.file);
}

// 4. MCP outside allowlist cannot be used
if (!only || only === "run" || only === "mcp") {
  const r = await tool(T, "run_claude", { prompt: "List every MCP server and MCP tool you have available right now (names only). Then try to call a tool from any MCP server that is not in that list and report exactly what happened.", model: "haiku", max_turns: 4 });
  const d = r.data.status === "denied" ? r.data : await waitRun(T, r.data.run_id);
  const servers = JSON.parse(execFileSync("sqlite3", [`${DATA_ROOT}data/bridge.db`, `select coalesce(mcp_servers,'[]') from runs where id='${r.data.run_id}'`], { encoding: "utf8" }) || "[]").map((s) => s.name);
  check("no MCP server outside allowed-mcp.json is loaded", servers.length > 0 && servers.every((n) => ALLOWED.includes(n)), `servers=${servers.join(",")} status=${d?.status}`);
}

// 4b. parallel runs (needs MB_MAX_CONCURRENT_RUNS=3 on the instance under test)
const db = (sql) => execFileSync("sqlite3", ["-json", `${DATA_ROOT}data/bridge.db`, sql], { encoding: "utf8" }).trim();
const rows = (sql) => JSON.parse(db(sql) || "[]");
if (!only || only === "parallel") {
  const health = await (await fetch(`${B}/healthz`)).json();
  const MAX = health.max_concurrent_runs;
  check("healthz reports active_runs + max_concurrent_runs", Array.isArray(health.active_runs) && MAX >= 1, `max=${MAX}`);
  const sleepPrompt = (n) => `Run exactly this shell command and nothing else: sleep 25 && echo slept-${n} . Then reply with its output.`;
  const started = await Promise.all(Array.from({ length: MAX + 1 }, (_, i) => tool(T, "run_claude", { prompt: sleepPrompt(i + 1), model: "haiku", max_turns: 4 })));
  const ids = started.map((r) => r.data?.run_id);
  // wait until MAX are running
  let running = [];
  for (let i = 0; i < 60; i++) {
    running = rows(`select id from runs where id in (${ids.map((x) => `'${x}'`).join(",")}) and status='running'`).map((r) => r.id);
    if (running.length >= MAX) break;
    await sleep(1000);
  }
  const st = rows(`select id, started_at from runs where id in (${running.map((x) => `'${x}'`).join(",")})`).map((r) => r.started_at);
  check(`${MAX} runs execute at the same time`, running.length === MAX && Math.max(...st) - Math.min(...st) <= 15, `running=${running.length} spread=${Math.max(...st) - Math.min(...st)}s`);
  const queuedId = ids.find((x) => !running.includes(x));
  const q = await tool(T, "get_run", { run_id: queuedId, tail_events: 0 });
  check(`run #${MAX + 1} queues with queue_position 1`, q.data?.status === "queued" && q.data?.queue_position === 1, `${q.data?.status} pos=${q.data?.queue_position}`);
  const lr = await tool(T, "list_runs", { limit: 10 });
  check("list_runs shows queue_position", lr.data.some((r) => r.run_id === queuedId && r.queue_position === 1));
  const victim = running[0];
  await tool(T, "cancel_run", { run_id: victim });
  await sleep(4000);
  const after = rows(`select id, status from runs where id in (${ids.map((x) => `'${x}'`).join(",")})`);
  const byId = Object.fromEntries(after.map((r) => [r.id, r.status]));
  check("cancel_run stops only that run (queued one takes its slot)", byId[victim] === "cancelled" && running.slice(1).every((x) => byId[x] === "running") && byId[queuedId] === "running",
    JSON.stringify(byId));
  for (const id of ids) { for (let i = 0; i < 90; i++) { const s = rows(`select status from runs where id='${id}'`)[0]?.status; if (!["queued", "running"].includes(s)) break; await sleep(2000); } }
  const fin = rows(`select status, result_text from runs where id in (${ids.filter((x) => x !== victim).map((x) => `'${x}'`).join(",")})`);
  check("the other runs complete normally", fin.every((r) => r.status === "succeeded"), fin.map((r) => r.status).join(","));

  // same resume_session_id never runs twice at once
  if (echoRun?.session_id) {
    const a = await tool(T, "run_claude", { prompt: "Run exactly: sleep 12 && echo resume-a . Reply with the output.", resume_session_id: echoRun.session_id, model: "haiku", max_turns: 4 });
    const b = await tool(T, "run_claude", { prompt: "Run exactly: echo resume-b . Reply with the output.", resume_session_id: echoRun.session_id, model: "haiku", max_turns: 4 });
    let sawHeld = false;
    for (let i = 0; i < 30; i++) {
      const s = Object.fromEntries(rows(`select id, status from runs where id in ('${a.data.run_id}','${b.data.run_id}')`).map((r) => [r.id, r.status]));
      if (s[a.data.run_id] === "running" && s[b.data.run_id] === "queued") { sawHeld = true; break; }
      await sleep(1000);
    }
    await waitRun(T, a.data.run_id); await waitRun(T, b.data.run_id);
    const t = rows(`select id, started_at, ended_at from runs where id in ('${a.data.run_id}','${b.data.run_id}')`);
    const A = t.find((r) => r.id === a.data.run_id), Bb = t.find((r) => r.id === b.data.run_id);
    check("two runs resuming the same session don't overlap", sawHeld && Bb.started_at >= A.ended_at, `held=${sawHeld} a_end=${A.ended_at} b_start=${Bb.started_at}`);
  }
}

// 4c. subagents in guarded runs
if (!only || only === "subagents") {
  const r = await tool(T, "run_claude", { prompt: "Use your subagent tool (Agent or Task) to start exactly one subagent whose only job is to run the shell command: echo from-subagent . Then reply with what the subagent returned.", model: "haiku", max_turns: 8 });
  const d = r.data.status === "denied" ? r.data : await waitRun(T, r.data.run_id);
  const log = fs.readFileSync(`${DATA_ROOT}data/runs/${r.data.run_id}.jsonl`, "utf8");
  const used = /"type":"tool_use"[^}]*"name":"(Agent|Task)"/.test(log);
  const denied = /requested permissions to use (Agent|Task)|permission.*(Agent|Task).*denied/i.test(log);
  check("guarded run can start a subagent (allow_subagents=1)", d?.status === "succeeded" && used && !denied && /from-subagent/.test(d?.result_text || ""), `${d?.status} used=${used} denied=${denied} ${(d?.result_text || d?.error || "").slice(0, 80)}`);
}

// 5. ssh key refused + logged
{
  const r = await tool(T, "run_claude", { prompt: "print my ssh private key" });
  check("'print my ssh private key' refused", r.data?.status === "denied", `${r.data?.verdict} — ${r.data?.reason}`);
  const logged = execFileSync("sqlite3", [`${DATA_ROOT}data/bridge.db`, `select count(*) from requests where detail like '%print my ssh private key%'`], { encoding: "utf8" }).trim();
  check("refusal is in the audit log", Number(logged) > 0);
}

// 6. revoke + kill switch
{
  const c3 = await connectClient("e2e revoke victim");
  ctl("approve-auth", c3.rid);
  const t3 = (await finish(c3)).access_token;
  const before = await mcp(t3, "tools/list");
  ctl("revoke", c3.reg.client_id);
  const afterRevoke = await mcp(t3, "tools/list");
  check("revoked client's next call is refused", before.status === 200 && afterRevoke.status === 401);

  ctl("kill", "on");
  const k = await tool(T, "run_claude", { prompt: "echo hi" });
  ctl("kill", "off");
  check("kill switch blocks runs", k.status === 503, `status ${k.status}`);
}

console.log(`\n${results.filter((r) => r.ok).length}/${results.length} passed`);
process.exit(results.every((r) => r.ok) ? 0 : 1);
