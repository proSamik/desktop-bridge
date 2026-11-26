import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express, { type Request, type Response, type NextFunction } from "express";
import { db, now, getSetting, setSetting } from "../db.js";
import { ROOT, RUNS_DIR, ALLOWED_MCP_PATH, POLICY_PATH, ADMIN_PORT, KC, kcGet, kcSet, IS_PANEL, GUARDED, REMOTES, remoteKeyName, NODE_NAME, PLATFORM_NAME } from "../config.js";
import { checkAdminCredentials, createSession, destroySession, getSession, requireAdmin, clientIp } from "./auth.js";
import { revokeClient, approveAuthRequest, denyAuthRequest } from "../oauth/router.js";
import { cancelRun, approveAskRun, rejectAskRun, cancelAllRuns, PERMISSION_MODES, CODEX_SANDBOXES, currentRunId, activeRunIds, maxConcurrentRuns, pump } from "../runs/runner.js";
import { MAX_CONCURRENT_ENV } from "../config.js";
import { pinConfigHashes, fileSha, safeEqual, NOTIFY_BATCH_CHOICES, flushNotifications } from "../util.js";

// The panel ships with the code, not the data dir: resolve it next to this module (dist/admin -> src/admin).
const PANEL = [path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "src", "admin", "panel.html"), path.join(ROOT, "src", "admin", "panel.html")]
  .find((p) => fs.existsSync(p)) ?? path.join(ROOT, "src", "admin", "panel.html");

/** Blocks DNS-rebinding: only loopback Host headers. */
function hostGuard(req: Request, res: Response, next: NextFunction) {
  const h = (req.header("host") || "").toLowerCase();
  const ok = !IS_PANEL ? /^(127\.0\.0\.1|localhost):\d+$/.test(h) : h === `127.0.0.1:${ADMIN_PORT}` || h === `localhost:${ADMIN_PORT}`;
  if (!ok) return res.status(421).send("bad host");
  if (req.header("cf-ray") || req.header("cf-connecting-ip")) return res.status(403).send("admin is local only");
  next();
}

/** "api" machines: no UI, no login; the panel machine calls this with a shared key (usually over an SSH forward). */
function requireKey(req: Request, res: Response, next: NextFunction) {
  const key = kcGet(KC.adminApiKey);
  if (!key || !safeEqual(req.header("x-mb-admin-key") || "", key)) return res.status(401).json({ error: "bad admin key" });
  next();
}

/** Panel side: forwards /api/remote/<name>/* to that machine's admin API (after this panel's login + CSRF check). */
async function remoteProxy(req: Request, res: Response) {
  const m = /^\/([A-Za-z0-9-]+)(\/.*)?$/.exec(req.url);
  const remote = m && REMOTES.find((r) => r.name === m[1]);
  if (!remote) return res.status(404).json({ error: "unknown remote" });
  const key = kcGet(remoteKeyName(remote.name));
  if (!key) return res.status(503).json({ error: `secret ${remoteKeyName(remote.name)} missing on the panel machine` });
  try {
    const r = await fetch(`${remote.url}/api${m![2] || "/"}`, {
      method: req.method,
      headers: { "content-type": "application/json", "x-mb-admin-key": key },
      body: req.method === "GET" ? undefined : JSON.stringify(req.body ?? {}),
      signal: AbortSignal.timeout(15000),
    });
    res.status(r.status).type("json").send(await r.text());
  } catch (e: any) {
    res.status(502).json({ error: `${remote.name} unreachable at ${remote.url} (${e.cause?.code || e.message}). Is its SSH forward / service up?` });
  }
}

export function adminApp() {
  const app = express();
  app.disable("x-powered-by");
  app.use(hostGuard);
  app.use(express.json({ limit: "1mb" }));
  app.use((_req, res, next) => {
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  if (IS_PANEL) {
    app.get("/api/remotes", (req, res, next) => requireAdmin(req, res, next), (_req, res) => res.json({ local: NODE_NAME, platform: PLATFORM_NAME, remotes: REMOTES.map((r) => r.name) }));
    app.use("/api/remote", (req, res, next) => requireAdmin(req, res, next), remoteProxy);
  }

  app.get("/", (_req, res) => {
    if (!IS_PANEL) return res.type("text").send(`desktop-bridge admin API for "${NODE_NAME}". Manage it from your panel machine.`);
    res.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:");
    res.type("html").send(fs.readFileSync(PANEL, "utf8"));
  });

  // ----- auth -----
  app.get("/api/me", (req, res) => {
    const s = getSession(req);
    res.json(s ? { authed: true, csrf: s.csrf } : { authed: false });
  });
  app.post("/api/login", (req, res) => {
    const ip = clientIp(req);
    const r = checkAdminCredentials(ip, req.body?.password, req.body?.totp, "admin panel");
    if (!r.ok) return res.status(401).json({ error: r.error });
    const { id, csrf } = createSession(ip);
    res.setHeader("Set-Cookie", `mb_admin=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${12 * 3600}`);
    res.json({ ok: true, csrf });
  });
  app.post("/api/logout", (req, res) => {
    destroySession(req);
    res.setHeader("Set-Cookie", "mb_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    res.json({ ok: true });
  });

  const api = express.Router();
  api.use(IS_PANEL ? requireAdmin : requireKey);

  api.get("/overview", (_req, res) => {
    const c = (sql: string, ...a: any[]) => (db.prepare(sql).get(...a) as any).n;
    res.json({
      kill_switch: getSetting("kill_switch") === "1",
      permission_mode: getSetting("permission_mode"),
      rate_limit_per_hour: Number(getSetting("rate_limit_per_hour")),
      current_run: currentRunId(),
      active_runs: activeRunIds(),
      max_concurrent_runs: maxConcurrentRuns(),
      queued: c("SELECT COUNT(*) n FROM runs WHERE status='queued'"),
      awaiting: c("SELECT COUNT(*) n FROM runs WHERE status='awaiting_approval'"),
      pending_clients: c("SELECT COUNT(*) n FROM clients WHERE status='pending'"),
      pending_auth: c("SELECT COUNT(*) n FROM auth_requests WHERE status='pending' AND created_at>?", now() - 900),
      requests_24h: c("SELECT COUNT(*) n FROM requests WHERE ts>?", now() - 86400),
      runs_24h: c("SELECT COUNT(*) n FROM runs WHERE created_at>?", now() - 86400),
      config_ok: !GUARDED || fileSha(ALLOWED_MCP_PATH) === getSetting("allowed_mcp_sha256") && fileSha(POLICY_PATH) === getSetting("policy_sha256"),
      public_base_url: getSetting("public_base_url"),
      profile: GUARDED ? "guarded" : "open",
      ui: IS_PANEL ? "panel" : "api",
      node: NODE_NAME,
    });
  });

  // ----- alerts -----
  api.get("/alerts", (_req, res) => res.json(db.prepare("SELECT * FROM alerts WHERE acked=0 ORDER BY id DESC LIMIT 50").all()));
  api.post("/alerts/ack", (_req, res) => { db.prepare("UPDATE alerts SET acked=1").run(); res.json({ ok: true }); });

  // ----- clients -----
  api.get("/clients", (_req, res) => {
    res.json(db.prepare(`SELECT c.*, (SELECT COUNT(*) FROM tokens t WHERE t.client_id=c.id AND t.revoked_at IS NULL AND t.expires_at>?) active_tokens
      FROM clients c ORDER BY c.created_at DESC`).all(now()).map((c: any) => ({ ...c, secret_hash: undefined, ips: JSON.parse(c.ips || "[]"), redirect_uris: JSON.parse(c.redirect_uris) })));
  });
  api.post("/clients/:id/approve", (req, res) => {
    res.json({ ok: db.prepare("UPDATE clients SET status='approved' WHERE id=? AND status='pending'").run(req.params.id).changes > 0 });
  });
  api.post("/clients/:id/rename", (req, res) => {
    const name = String(req.body?.name || "").trim().slice(0, 100);
    if (!name) return res.status(400).json({ error: "name required" });
    db.prepare("UPDATE clients SET name=? WHERE id=?").run(name, req.params.id);
    res.json({ ok: true });
  });
  api.post("/clients/:id/mine", (req, res) => {
    db.prepare("UPDATE clients SET is_mine=? WHERE id=?").run(req.body?.mine ? 1 : 0, req.params.id);
    res.json({ ok: true });
  });
  api.post("/clients/:id/revoke", (req, res) => { revokeClient(String(req.params.id)); res.json({ ok: true }); });

  // ----- pending authorizations -----
  api.get("/auth-requests", (_req, res) => {
    res.json(db.prepare(`SELECT a.id, a.client_id, c.name client_name, c.status client_status, a.redirect_uri, a.ip, a.ua, a.scope, a.created_at
      FROM auth_requests a JOIN clients c ON c.id=a.client_id WHERE a.status='pending' AND a.created_at>? ORDER BY a.created_at DESC`).all(now() - 900));
  });
  api.post("/auth-requests/:id/approve", (req, res) => res.json({ ok: approveAuthRequest(String(req.params.id)) }));
  api.post("/auth-requests/:id/deny", (req, res) => { denyAuthRequest(String(req.params.id)); res.json({ ok: true }); });

  // ----- tokens -----
  api.get("/tokens", (_req, res) => {
    res.json(db.prepare(`SELECT t.id, t.client_id, c.name client_name, t.kind, t.created_at, t.expires_at, t.last_used, t.family_id
      FROM tokens t JOIN clients c ON c.id=t.client_id WHERE t.revoked_at IS NULL AND t.expires_at>? ORDER BY t.created_at DESC`).all(now()));
  });
  api.post("/tokens/:id/revoke", (req, res) => {
    const t = db.prepare("SELECT family_id, kind FROM tokens WHERE id=?").get(req.params.id) as any;
    if (!t) return res.status(404).json({ error: "not found" });
    // Revoking any token kills its family (the access+refresh chain).
    db.prepare("UPDATE tokens SET revoked_at=? WHERE family_id=? AND revoked_at IS NULL").run(now(), t.family_id);
    res.json({ ok: true });
  });

  // ----- requests (audit log) -----
  api.get("/requests", (req, res) => {
    const q = req.query as Record<string, string>;
    const where: string[] = [], args: any[] = [];
    if (q.client) { where.push("r.client_id=?"); args.push(q.client); }
    if (q.ip) { where.push("r.ip=?"); args.push(q.ip); }
    if (q.status) { where.push(q.status === "error" ? "r.status>=400" : "r.status=?"); if (q.status !== "error") args.push(Number(q.status)); }
    if (q.tool) { where.push("r.tool=?"); args.push(q.tool); }
    if (q.q) { where.push("(r.detail LIKE ? OR r.path LIKE ? OR r.ua LIKE ?)"); args.push(`%${q.q}%`, `%${q.q}%`, `%${q.q}%`); }
    if (q.since_id) { where.push("r.id>?"); args.push(Number(q.since_id)); }
    const sql = `SELECT r.*, c.name client_name FROM requests r LEFT JOIN clients c ON c.id=r.client_id
      ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY r.id DESC LIMIT ?`;
    res.json(db.prepare(sql).all(...args, Math.min(Number(q.limit) || 200, 1000)));
  });

  // ----- runs -----
  api.get("/runs", (_req, res) => {
    res.json(db.prepare(`SELECT r.id, r.client_id, c.name client_name, r.ip, r.prompt, r.cwd, r.status, r.verdict, r.verdict_reason, r.verdict_stage,
      r.created_at, r.started_at, r.ended_at, r.exit_code, r.duration_ms, r.cost_usd, r.session_id, r.error, r.permission_mode, r.mcp_servers, r.engine
      FROM runs r LEFT JOIN clients c ON c.id=r.client_id ORDER BY r.created_at DESC LIMIT 200`).all());
  });
  api.get("/runs/:id/log", (req, res) => {
    const f = path.join(RUNS_DIR, `${path.basename(String(req.params.id))}.jsonl`);
    const r = db.prepare("SELECT result_text FROM runs WHERE id=?").get(req.params.id) as any;
    const stderr = path.join(RUNS_DIR, `${path.basename(String(req.params.id))}.stderr.log`);
    res.json({
      result_text: r?.result_text ?? null,
      jsonl: fs.existsSync(f) ? fs.readFileSync(f, "utf8").slice(-400_000) : "",
      stderr: fs.existsSync(stderr) ? fs.readFileSync(stderr, "utf8").slice(-20_000) : "",
    });
  });
  api.post("/runs/:id/cancel", (req, res) => res.json({ ok: cancelRun(String(req.params.id), "cancelled by owner") }));
  api.post("/runs/:id/approve", (req, res) => res.json({ ok: approveAskRun(String(req.params.id)) }));
  api.post("/runs/:id/reject", (req, res) => res.json({ ok: rejectAskRun(String(req.params.id)) }));

  // ----- settings -----
  api.get("/settings", (_req, res) => {
    res.json({
      kill_switch: getSetting("kill_switch") === "1",
      rate_limit_per_hour: Number(getSetting("rate_limit_per_hour")),
      permission_mode: getSetting("permission_mode"),
      permission_modes: PERMISSION_MODES,
      codex_sandbox: getSetting("codex_sandbox"),
      max_concurrent_runs: maxConcurrentRuns(),
      max_concurrent_env_override: MAX_CONCURRENT_ENV != null,
      allow_subagents: getSetting("allow_subagents") === "1",
      notify_batch_seconds: Number(getSetting("notify_batch_seconds") || 60),
      codex_sandboxes: CODEX_SANDBOXES,
      profile: GUARDED ? "guarded" : "open",
      ui: IS_PANEL ? "panel" : "api",
      node: NODE_NAME,
      review_model: getSetting("review_model"),
      public_base_url: getSetting("public_base_url"),
      ip_allowlist: getSetting("ip_allowlist"),
    });
  });
  api.post("/settings", (req, res) => {
    const b = req.body || {};
    if (b.kill_switch !== undefined) {
      setSetting("kill_switch", b.kill_switch ? "1" : "0");
      if (b.kill_switch) cancelAllRuns("kill switch");
      else pump();
    }
    if (b.rate_limit_per_hour !== undefined) {
      const n = Number(b.rate_limit_per_hour);
      if (!Number.isInteger(n) || n < 0 || n > 10000) return res.status(400).json({ error: "rate limit must be 0-10000" });
      setSetting("rate_limit_per_hour", String(n));
    }
    if (b.permission_mode !== undefined) {
      if (!(PERMISSION_MODES as readonly string[]).includes(b.permission_mode)) return res.status(400).json({ error: "bad mode" });
      setSetting("permission_mode", b.permission_mode);
    }
    if (b.max_concurrent_runs !== undefined) {
      const n = Number(b.max_concurrent_runs);
      if (!Number.isInteger(n) || n < 1 || n > 10) return res.status(400).json({ error: "max concurrent runs must be 1-10" });
      setSetting("max_concurrent_runs", String(n));
      pump();
    }
    if (b.notify_batch_seconds !== undefined) {
      const n = Number(b.notify_batch_seconds);
      if (!NOTIFY_BATCH_CHOICES.includes(n)) return res.status(400).json({ error: "notification grouping must be 0, 60 or 300 seconds" });
      setSetting("notify_batch_seconds", String(n));
      flushNotifications();
    }
    if (b.allow_subagents !== undefined) setSetting("allow_subagents", b.allow_subagents ? "1" : "0");
    if (b.codex_sandbox !== undefined) {
      if (!(CODEX_SANDBOXES as readonly string[]).includes(b.codex_sandbox)) return res.status(400).json({ error: "bad sandbox" });
      setSetting("codex_sandbox", b.codex_sandbox);
    }
    if (b.review_model !== undefined) {
      if (!/^[A-Za-z0-9._\-[\]]{1,64}$/.test(b.review_model)) return res.status(400).json({ error: "bad model" });
      setSetting("review_model", b.review_model);
    }
    if (b.ip_allowlist !== undefined) {
      const v = String(b.ip_allowlist).trim();
      if (!v || !/^[0-9a-fA-F:.,\/\s]+$/.test(v)) return res.status(400).json({ error: "comma-separated IPs/CIDRs" });
      setSetting("ip_allowlist", v);
    }
    if (b.public_base_url !== undefined) {
      try { const u = new URL(b.public_base_url); if (u.protocol !== "https:") throw 0; } catch { return res.status(400).json({ error: "must be https URL" }); }
      setSetting("public_base_url", String(b.public_base_url).replace(/\/+$/, ""));
    }
    res.json({ ok: true });
  });

  // ----- config files -----
  const files: Record<string, string> = { "allowed-mcp": ALLOWED_MCP_PATH, policy: POLICY_PATH };
  api.get("/config/:name", (req, res) => {
    const p = files[String(req.params.name)];
    if (!p) return res.status(404).json({ error: "unknown" });
    res.json({ content: fs.existsSync(p) ? fs.readFileSync(p, "utf8") : "", intact: fileSha(p) === getSetting(req.params.name === "policy" ? "policy_sha256" : "allowed_mcp_sha256") });
  });
  api.post("/config/:name", (req, res) => {
    const p = files[String(req.params.name)];
    if (!p) return res.status(404).json({ error: "unknown" });
    const content = String(req.body?.content ?? "");
    if (req.params.name === "allowed-mcp") {
      try {
        const j = JSON.parse(content);
        if (!j.mcpServers || typeof j.mcpServers !== "object") throw new Error("needs mcpServers object");
      } catch (e: any) { return res.status(400).json({ error: `invalid JSON: ${e.message}` }); }
    }
    fs.writeFileSync(p, content, { mode: 0o600 });
    pinConfigHashes();
    res.json({ ok: true });
  });
  api.get("/cloudflare-token", (_req, res) => res.json({ present: !!kcGet(KC.cloudflareApiToken) }));
  api.post("/cloudflare-token", (req, res) => {
    const t = String(req.body?.token || "").trim();
    if (!/^[A-Za-z0-9_-]{30,200}$/.test(t)) return res.status(400).json({ error: "That doesn't look like a Cloudflare API token" });
    kcSet(KC.cloudflareApiToken, t);
    res.json({ ok: true });
  });
  api.post("/config-accept", (_req, res) => { pinConfigHashes(); res.json({ ok: true }); });

  app.use("/api", api);
  return app;
}
