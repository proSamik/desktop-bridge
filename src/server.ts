import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import fs from "node:fs";
import { BIND, MCP_PORT, ADMIN_PORT, IS_PANEL, GUARDED, REMOTES, NODE_NAME, remoteKeyName, kcGet, ALLOWED_MCP_PATH, POLICY_PATH, ALLOWED_MCP_EXAMPLE, POLICY_EXAMPLE, CONFIG_DIR } from "./config.js";
import { db, now, getSetting } from "./db.js";
import { clientIp, ipAllowed, notify, pinConfigHashes, panelUrl, SILENT_ALERT_KINDS, flushNotifications } from "./util.js";
import { oauthRouter, requireBearer, base, type AuthedRequest } from "./oauth/router.js";
import { buildMcpServer } from "./mcp.js";
import { adminApp } from "./admin/router.js";
import { recoverOnBoot, activeRunIds, maxConcurrentRuns } from "./runs/runner.js";

// First start (guarded profile): create config/ from the examples and pin their hashes.
if (GUARDED) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  let created = false;
  for (const [real, ex] of [[ALLOWED_MCP_PATH, ALLOWED_MCP_EXAMPLE], [POLICY_PATH, POLICY_EXAMPLE]]) {
    if (!fs.existsSync(real) && fs.existsSync(ex)) { fs.copyFileSync(ex, real); created = true; }
  }
  if (created || !getSetting("allowed_mcp_sha256")) pinConfigHashes();
}

// ---------------- public MCP + OAuth server (tunneled) ----------------
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", false);

// Accept only the public hostname (via tunnel) or loopback.
app.use((req, res, next) => {
  const h = (req.header("host") || "").toLowerCase();
  let pub = "";
  try { pub = new URL(base()).host.toLowerCase(); } catch {}
  if (h !== pub && h !== `127.0.0.1:${MCP_PORT}` && h !== `localhost:${MCP_PORT}`) return res.status(421).send("bad host");
  next();
});

// IP allowlist for anything arriving through Cloudflare (CF-Connecting-IP is set by Cloudflare's edge and can't be forged through it).
app.use((req, res, next) => {
  const tunneled = !!(req.header("cf-ray") || req.header("cf-connecting-ip"));
  if (!tunneled) return next();
  const ip = req.header("cf-connecting-ip") || "";
  if (!ipAllowed(ip, getSetting("ip_allowlist"))) {
    db.prepare("INSERT INTO requests(ts,ip,cf_ray,ua,method,path,status,detail) VALUES(?,?,?,?,?,?,?,?)").run(
      now(), ip, req.header("cf-ray") ?? null, (req.header("user-agent") || "").slice(0, 300), req.method, req.path.slice(0, 200), 403, "blocked by IP allowlist");
    return res.status(403).json({ error: "forbidden" });
  }
  next();
});

// Audit log: every request, written when the response finishes.
app.use((req: AuthedRequest, res, next) => {
  const started = Date.now();
  res.on("finish", () => {
    let tool: string | null = null, detail: string | null = null;
    const b: any = (req as any).body;
    const msgs = Array.isArray(b) ? b : b ? [b] : [];
    for (const m of msgs) {
      if (m?.method === "tools/call") {
        tool = String(m.params?.name ?? "");
        const args = m.params?.arguments ?? {};
        detail = JSON.stringify(args).slice(0, 20_000);
      } else if (m?.method && !tool) tool = `rpc:${m.method}`;
    }
    if (!tool && req.path === "/register" && b?.client_name) detail = `client_name=${String(b.client_name).slice(0, 100)}`;
    db.prepare(
      "INSERT INTO requests(ts,client_id,token_id,ip,cf_ray,ua,method,path,tool,status,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?)"
    ).run(
      now(), req.mbAuth?.clientId ?? null, req.mbAuth?.tokenId ?? null, clientIp(req), req.header("cf-ray") ?? null,
      (req.header("user-agent") || "").slice(0, 300), req.method, req.path.slice(0, 200), tool, res.statusCode,
      detail ?? `${Date.now() - started}ms`
    );
  });
  next();
});

const health = (req: express.Request, res: express.Response) => {
  // Detailed health only on loopback; tunneled callers get a bare ok.
  if (req.header("cf-ray")) return res.json({ ok: true });
  const ids = activeRunIds();
  res.json({
    ok: true, kill_switch: getSetting("kill_switch") === "1",
    active_runs: ids, current_run: ids[0] ?? null, max_concurrent_runs: maxConcurrentRuns(),
    time: new Date().toISOString(),
  });
};
app.get("/healthz", health);
app.get("/health", health);

app.use(oauthRouter());

app.post("/mcp", express.json({ limit: "2mb" }), requireBearer, async (req: AuthedRequest, res) => {
  if (getSetting("kill_switch") === "1") {
    return res.status(503).json({ jsonrpc: "2.0", error: { code: -32000, message: "desktop-bridge kill switch is on" }, id: null });
  }
  const server = buildMcpServer({ clientId: req.mbAuth!.clientId, tokenId: req.mbAuth!.tokenId, ip: clientIp(req) });
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  res.on("close", () => { transport.close(); server.close(); });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e: any) {
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "internal error" }, id: null });
  }
});
// Stateless server: no SSE stream or sessions. GET/DELETE still need auth first so probes get the 401 + metadata.
app.all("/mcp", requireBearer, (_req, res) => {
  res.setHeader("Allow", "POST");
  res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null });
});

app.use((_req, res) => res.status(404).json({ error: "not found" }));

app.listen(MCP_PORT, BIND, () => console.log(`desktop-bridge "${NODE_NAME}" (${GUARDED ? "guarded" : "open"}, admin ${IS_PANEL ? "panel" : "api"}) MCP on http://${BIND}:${MCP_PORT} (public ${base()})`));

// ---------------- admin panel (never tunneled) ----------------
adminApp().listen(ADMIN_PORT, BIND, () => console.log(`desktop-bridge admin ${IS_PANEL ? "panel" : "API"} on http://${BIND}:${ADMIN_PORT}`));

// Housekeeping
recoverOnBoot();
setInterval(() => {
  const t = now();
  db.prepare("DELETE FROM auth_codes WHERE expires_at<?").run(t - 3600);
  db.prepare("DELETE FROM admin_sessions WHERE expires_at<?").run(t);
  db.prepare("DELETE FROM tokens WHERE expires_at<? AND kind='access'").run(t - 7 * 86400);
  db.prepare("DELETE FROM requests WHERE ts<?").run(t - 90 * 86400);
}, 3600_000).unref();

// Panel machine: surface remote alerts (new runs, clients, connection requests) as local notifications.
for (const remote of REMOTES) {
  const k = `remote_alert_seen_${remote.name}`;
  let seen = Number(getSetting(k) || (remote.name === "air" ? getSetting("linux_alert_seen") : "") || 0);
  setInterval(async () => {
    const key = kcGet(remoteKeyName(remote.name));
    if (!key) return;
    try {
      const r = await fetch(`${remote.url}/api/alerts`, { headers: { "x-mb-admin-key": key }, signal: AbortSignal.timeout(8000) });
      if (!r.ok) return;
      const alerts = (await r.json()) as { id: number; kind: string; message: string }[];
      const fresh = alerts.filter((a) => a.id > seen).sort((a, b) => a.id - b.id);
      for (const a of fresh.filter((x) => !SILENT_ALERT_KINDS.has(x.kind)).slice(-20)) notify(`desktop-bridge (${remote.name})`, a.message, panelUrl(remote.name));
      if (fresh.length) {
        seen = fresh[fresh.length - 1].id;
        db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(k, String(seen));
      }
    } catch {}
  }, 20_000).unref();
}

// Don't lose queued notifications on a normal stop/restart.
for (const sig of ["SIGTERM", "SIGINT"] as const) process.once(sig, () => { flushNotifications(); setTimeout(() => process.exit(0), 1500); });

process.on("unhandledRejection", (e) => console.error("unhandledRejection", e));
