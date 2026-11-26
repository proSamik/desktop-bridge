import crypto from "node:crypto";
import express, { type Request, type Response, type NextFunction } from "express";
import { db, now, getSetting } from "../db.js";
import { ACCESS_TTL_S, REFRESH_TTL_S, IS_PANEL, NODE_NAME, PLATFORM_NAME } from "../config.js";
import { sha256, randToken, randId, safeEqual, clientIp, alert, trackIp } from "../util.js";
import { checkAdminCredentials } from "../admin/auth.js";
import { cancelRunsForClient } from "../runs/runner.js";

export const base = () => getSetting("public_base_url").replace(/\/+$/, "");
export const resourceUrl = () => `${base()}/mcp`;
const prmUrl = () => `${base()}/.well-known/oauth-protected-resource`;

const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

// ---------- token helpers ----------
export function issueTokens(clientId: string, scope: string | null, familyId = randId("fam")) {
  const access = randToken(32), refresh = randToken(32);
  const t = now();
  const ins = db.prepare(
    "INSERT INTO tokens(id,client_id,kind,hash,family_id,scope,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)"
  );
  ins.run(randId("at"), clientId, "access", sha256(access), familyId, scope, t, t + ACCESS_TTL_S);
  ins.run(randId("rt"), clientId, "refresh", sha256(refresh), familyId, scope, t, t + REFRESH_TTL_S);
  return {
    access_token: access,
    token_type: "Bearer",
    expires_in: ACCESS_TTL_S,
    refresh_token: refresh,
    scope: scope || "mcp",
  };
}

export function revokeClient(clientId: string) {
  db.prepare("UPDATE clients SET status='revoked' WHERE id=?").run(clientId);
  db.prepare("UPDATE tokens SET revoked_at=? WHERE client_id=? AND revoked_at IS NULL").run(now(), clientId);
  cancelRunsForClient(clientId);
}

function approveRequestAndIssueCode(reqId: string): string | null {
  const ar = db.prepare("SELECT * FROM auth_requests WHERE id=?").get(reqId) as any;
  if (!ar || ar.status !== "approved") return null;
  const client = db.prepare("SELECT status FROM clients WHERE id=?").get(ar.client_id) as any;
  if (client?.status !== "approved") return null;
  const code = randToken(32);
  db.prepare(
    "INSERT INTO auth_codes(code_hash,client_id,redirect_uri,code_challenge,scope,resource,expires_at) VALUES(?,?,?,?,?,?,?)"
  ).run(sha256(code), ar.client_id, ar.redirect_uri, ar.code_challenge, ar.scope, ar.resource, now() + 120);
  db.prepare("UPDATE auth_requests SET status='delivered' WHERE id=?").run(reqId);
  const u = new URL(ar.redirect_uri);
  u.searchParams.set("code", code);
  if (ar.state) u.searchParams.set("state", ar.state);
  u.searchParams.set("iss", base());
  return u.toString();
}

/** Admin approval path (from the admin panel or the consent page). */
export function approveAuthRequest(reqId: string) {
  const ar = db.prepare("SELECT client_id FROM auth_requests WHERE id=? AND status='pending'").get(reqId) as any;
  if (!ar) return false;
  db.prepare("UPDATE clients SET status='approved' WHERE id=? AND status!='revoked'").run(ar.client_id);
  db.prepare("UPDATE auth_requests SET status='approved' WHERE id=?").run(reqId);
  return true;
}
export function denyAuthRequest(reqId: string) {
  db.prepare("UPDATE auth_requests SET status='denied' WHERE id=? AND status='pending'").run(reqId);
}

// ---------- bearer middleware for /mcp ----------
export type AuthedRequest = Request & { mbAuth?: { clientId: string; tokenId: string; clientName: string } };

export function requireBearer(req: AuthedRequest, res: Response, next: NextFunction) {
  const deny = (desc: string) => {
    res.setHeader(
      "WWW-Authenticate",
      `Bearer resource_metadata="${prmUrl()}", error="invalid_token", error_description="${desc}"`
    );
    res.status(401).json({ error: "invalid_token", error_description: desc });
  };
  const m = /^Bearer\s+([A-Za-z0-9_-]+)$/.exec(req.header("authorization") || "");
  if (!m) return deny("missing bearer token");
  const row = db
    .prepare(
      `SELECT t.id, t.client_id, t.expires_at, t.revoked_at, c.status, c.name FROM tokens t JOIN clients c ON c.id=t.client_id
       WHERE t.hash=? AND t.kind='access'`
    )
    .get(sha256(m[1])) as any;
  if (!row || row.revoked_at || row.expires_at < now()) return deny("token invalid or expired");
  if (row.status !== "approved") return deny("client not approved");
  const ip = clientIp(req);
  db.prepare("UPDATE tokens SET last_used=? WHERE id=?").run(now(), row.id);
  const c = db.prepare("SELECT ips, first_seen FROM clients WHERE id=?").get(row.client_id) as any;
  const ips: string[] = JSON.parse(c.ips || "[]");
  if (ip && !ips.includes(ip)) ips.push(ip);
  db.prepare("UPDATE clients SET last_seen=?, first_seen=COALESCE(first_seen,?), ips=? WHERE id=?").run(
    now(), now(), JSON.stringify(ips.slice(-50)), row.client_id
  );
  trackIp(ip, `client ${row.name}`);
  req.mbAuth = { clientId: row.client_id, tokenId: row.id, clientName: row.name };
  next();
}

// ---------- router ----------
export function oauthRouter() {
  const r = express.Router();
  const body = [express.urlencoded({ extended: false, limit: "64kb" }), express.json({ limit: "64kb" })];

  const prm = (_req: Request, res: Response) =>
    res.json({
      resource: resourceUrl(),
      authorization_servers: [base()],
      bearer_methods_supported: ["header"],
      scopes_supported: ["mcp"],
      resource_name: `desktop-bridge (${NODE_NAME})`,
    });
  r.get("/.well-known/oauth-protected-resource", prm);
  r.get("/.well-known/oauth-protected-resource/mcp", prm);

  const asMeta = (_req: Request, res: Response) =>
    res.json({
      issuer: base(),
      authorization_endpoint: `${base()}/authorize`,
      token_endpoint: `${base()}/token`,
      registration_endpoint: `${base()}/register`,
      revocation_endpoint: `${base()}/revoke`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
      revocation_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
      scopes_supported: ["mcp"],
      authorization_response_iss_parameter_supported: true,
    });
  r.get("/.well-known/oauth-authorization-server", asMeta);
  r.get("/.well-known/oauth-authorization-server/mcp", asMeta);

  // ---- Dynamic Client Registration (RFC 7591) ----
  r.post("/register", ...body, (req, res) => {
    const b = req.body || {};
    const uris: unknown = b.redirect_uris;
    if (!Array.isArray(uris) || uris.length === 0 || uris.length > 5)
      return res.status(400).json({ error: "invalid_redirect_uri", error_description: "redirect_uris required" });
    for (const u of uris) {
      let p: URL;
      try { p = new URL(String(u)); } catch { return res.status(400).json({ error: "invalid_redirect_uri" }); }
      const loopback = p.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(p.hostname);
      if (p.protocol !== "https:" && !loopback) return res.status(400).json({ error: "invalid_redirect_uri", error_description: "https or loopback only" });
      if (p.hash) return res.status(400).json({ error: "invalid_redirect_uri" });
    }
    const method = ["client_secret_post", "client_secret_basic"].includes(b.token_endpoint_auth_method) ? b.token_endpoint_auth_method : "none";
    const id = randId("mbc");
    const secret = method === "none" ? null : randToken(32);
    const name = String(b.client_name || "Unnamed client").slice(0, 100);
    const ip = clientIp(req);
    db.prepare(
      "INSERT INTO clients(id,name,redirect_uris,status,auth_method,secret_hash,reg_ip,reg_ua,created_at) VALUES(?,?,?,?,?,?,?,?,?)"
    ).run(id, name, JSON.stringify(uris), "pending", method, secret ? sha256(secret) : null, ip, req.header("user-agent") || "", now());
    alert("new_client", `New client registered: "${name}" from ${ip || "?"} (pending)`);
    trackIp(ip, "client registration");
    res.status(201).json({
      client_id: id,
      client_id_issued_at: now(),
      client_name: name,
      redirect_uris: uris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: method,
      ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
    });
  });

  // ---- Authorization endpoint ----
  const authErr = (res: Response, msg: string) => res.status(400).type("html").send(page("Authorization error", `<p>${esc(msg)}</p>`));

  r.get("/authorize", (req, res) => {
    const q = req.query as Record<string, string>;
    const client = db.prepare("SELECT * FROM clients WHERE id=?").get(String(q.client_id || "")) as any;
    if (!client) return authErr(res, "Unknown client_id.");
    if (client.status === "revoked") return authErr(res, "This client has been revoked.");
    const uris: string[] = JSON.parse(client.redirect_uris);
    const redirect = String(q.redirect_uri || (uris.length === 1 ? uris[0] : ""));
    if (!uris.includes(redirect)) return authErr(res, "redirect_uri does not match the registered value.");
    // From here, errors can go back to the client.
    const back = (error: string, desc: string) => {
      const u = new URL(redirect);
      u.searchParams.set("error", error); u.searchParams.set("error_description", desc);
      if (q.state) u.searchParams.set("state", String(q.state));
      return res.redirect(302, u.toString());
    };
    if (q.response_type !== "code") return back("unsupported_response_type", "only code");
    if (q.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43,128}$/.test(String(q.code_challenge || "")))
      return back("invalid_request", "PKCE S256 required");
    if (q.resource && String(q.resource).replace(/\/+$/, "") !== resourceUrl()) return back("invalid_target", "unknown resource");

    const rid = randId("ar");
    const ip = clientIp(req);
    db.prepare(
      "INSERT INTO auth_requests(id,client_id,redirect_uri,state,code_challenge,scope,resource,ip,ua,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)"
    ).run(rid, client.id, redirect, q.state || null, q.code_challenge, q.scope || "mcp", q.resource || null, ip, req.header("user-agent") || "", now());
    alert("auth_request", `Authorization request from "${client.name}" at ${ip || "?"}`);
    res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self' https: http://localhost:* http://127.0.0.1:*");
    res.setHeader("X-Frame-Options", "DENY");
    res.type("html").send(consentPage(rid, client, redirect, ip, String(q.scope || "mcp")));
  });

  r.post("/authorize/decision", ...body, (req, res) => {
    if (!IS_PANEL) return res.status(404).send(`Approve this connection in your admin panel (${NODE_NAME} tab).`);
    const { rid, password, totp, decision } = req.body || {};
    const ar = db.prepare("SELECT * FROM auth_requests WHERE id=?").get(String(rid || "")) as any;
    if (!ar || ar.status !== "pending" || ar.created_at < now() - 900) return authErr(res, "Request expired. Start the connection again.");
    const ip = clientIp(req);
    const login = checkAdminCredentials(ip, password, totp, "consent page");
    if (!login.ok) {
      const client = db.prepare("SELECT * FROM clients WHERE id=?").get(ar.client_id) as any;
      return res.status(401).type("html").send(consentPage(ar.id, client, ar.redirect_uri, ar.ip, ar.scope, login.error));
    }
    if (decision !== "approve") {
      denyAuthRequest(ar.id);
      const u = new URL(ar.redirect_uri);
      u.searchParams.set("error", "access_denied");
      if (ar.state) u.searchParams.set("state", ar.state);
      return res.redirect(302, u.toString());
    }
    approveAuthRequest(ar.id);
    const url = approveRequestAndIssueCode(ar.id);
    if (!url) return authErr(res, "Could not issue a code.");
    res.redirect(302, url);
  });

  // Polled by the consent page so approval in the local admin panel also completes the flow.
  r.get("/authorize/status/:rid", (req, res) => {
    const ar = db.prepare("SELECT status, created_at FROM auth_requests WHERE id=?").get(req.params.rid) as any;
    if (!ar || ar.created_at < now() - 900) return res.json({ status: "expired" });
    if (ar.status === "approved") {
      const url = approveRequestAndIssueCode(req.params.rid);
      return res.json(url ? { status: "approved", redirect: url } : { status: "error" });
    }
    res.json({ status: ar.status });
  });

  // ---- Token endpoint ----
  function authClient(req: Request): { client?: any; error?: string } {
    const b = req.body || {};
    let id = b.client_id, secret = b.client_secret;
    const basic = /^Basic\s+(.+)$/.exec(req.header("authorization") || "");
    if (basic) {
      const [u, p] = Buffer.from(basic[1], "base64").toString().split(":");
      id = decodeURIComponent(u || ""); secret = decodeURIComponent(p || "");
    }
    const client = db.prepare("SELECT * FROM clients WHERE id=?").get(String(id || "")) as any;
    if (!client) return { error: "invalid_client" };
    if (client.auth_method !== "none") {
      if (!secret || !client.secret_hash || !safeEqual(sha256(String(secret)), client.secret_hash)) return { error: "invalid_client" };
    }
    return { client };
  }

  r.post("/token", ...body, (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    const b = req.body || {};
    const { client, error } = authClient(req);
    if (!client) return res.status(401).json({ error });
    if (client.status !== "approved") return res.status(400).json({ error: "unauthorized_client", error_description: "client not approved" });

    if (b.grant_type === "authorization_code") {
      const row = db.prepare("SELECT * FROM auth_codes WHERE code_hash=?").get(sha256(String(b.code || ""))) as any;
      if (!row || row.used || row.expires_at < now() || row.client_id !== client.id) return res.status(400).json({ error: "invalid_grant" });
      db.prepare("UPDATE auth_codes SET used=1 WHERE code_hash=?").run(row.code_hash);
      if (b.redirect_uri && b.redirect_uri !== row.redirect_uri) return res.status(400).json({ error: "invalid_grant", error_description: "redirect_uri mismatch" });
      const verifier = String(b.code_verifier || "");
      if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return res.status(400).json({ error: "invalid_grant", error_description: "bad code_verifier" });
      const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
      if (!safeEqual(challenge, row.code_challenge)) return res.status(400).json({ error: "invalid_grant", error_description: "PKCE failed" });
      return res.json(issueTokens(client.id, row.scope));
    }

    if (b.grant_type === "refresh_token") {
      const row = db.prepare("SELECT * FROM tokens WHERE hash=? AND kind='refresh'").get(sha256(String(b.refresh_token || ""))) as any;
      if (!row || row.client_id !== client.id) return res.status(400).json({ error: "invalid_grant" });
      if (row.rotated_at || row.revoked_at) {
        // Reuse of a rotated refresh token: assume theft, kill the whole family.
        if (row.rotated_at) {
          db.prepare("UPDATE tokens SET revoked_at=? WHERE family_id=? AND revoked_at IS NULL").run(now(), row.family_id);
          alert("refresh_reuse", `Refresh token reuse detected for client ${client.name}; token family revoked`);
        }
        return res.status(400).json({ error: "invalid_grant" });
      }
      if (row.expires_at < now()) return res.status(400).json({ error: "invalid_grant" });
      db.prepare("UPDATE tokens SET rotated_at=?, revoked_at=? WHERE id=?").run(now(), now(), row.id);
      // Old access tokens of this family stay valid until expiry; that is standard.
      return res.json(issueTokens(client.id, row.scope, row.family_id));
    }
    res.status(400).json({ error: "unsupported_grant_type" });
  });

  // ---- Revocation (RFC 7009) ----
  r.post("/revoke", ...body, (req, res) => {
    const { client } = authClient(req);
    const tok = String((req.body || {}).token || "");
    if (client && tok) {
      const row = db.prepare("SELECT * FROM tokens WHERE hash=?").get(sha256(tok)) as any;
      if (row && row.client_id === client.id) {
        if (row.kind === "refresh") db.prepare("UPDATE tokens SET revoked_at=? WHERE family_id=? AND revoked_at IS NULL").run(now(), row.family_id);
        else db.prepare("UPDATE tokens SET revoked_at=? WHERE id=?").run(now(), row.id);
      }
    }
    res.status(200).json({});
  });

  return r;
}

// ---------- HTML ----------
function page(title: string, body: string) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>
:root{color-scheme:light dark;--bg:#f6f6f4;--fg:#1b1b1a;--card:#fff;--mut:#6b6b66;--line:#e2e2dd;--acc:#1f6feb;--bad:#c2372f}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ececea;--card:#1e1e1c;--mut:#9a9a94;--line:#2f2f2c;--acc:#5b9bff;--bad:#ff6b61}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,system-ui,sans-serif;display:flex;justify-content:center;padding:40px 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px;max-width:460px;width:100%}
h1{font-size:19px;margin:0 0 4px}dl{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;margin:16px 0}dt{color:var(--mut)}dd{margin:0;word-break:break-all}
input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;font:inherit;margin:4px 0 10px}
.row{display:flex;gap:10px}button{flex:1;padding:10px;border-radius:8px;border:1px solid var(--line);font:inherit;cursor:pointer;background:transparent;color:inherit}
button.primary{background:var(--acc);border-color:var(--acc);color:#fff}.err{color:var(--bad)}.mut{color:var(--mut);font-size:13px}
</style></head><body><div class="card">${body}</div></body></html>`;
}

function consentPage(rid: string, client: any, redirect: string, ip: string, scope: string, error?: string) {
  return page(
    "Approve connection",
    `<h1>Allow access to ${esc(NODE_NAME)}?</h1>
<p class="mut">An app wants to run Claude Code / Codex on your ${PLATFORM_NAME} machine "${esc(NODE_NAME)}" through desktop-bridge.</p>
<dl><dt>Client</dt><dd>${esc(client.name)}</dd><dt>Client ID</dt><dd>${esc(client.id)}</dd>
<dt>Redirect</dt><dd>${esc(redirect)}</dd><dt>Requesting IP</dt><dd>${esc(ip)}</dd><dt>Scope</dt><dd>${esc(scope)}</dd>
<dt>Status</dt><dd>${esc(client.status)}</dd></dl>
${error ? `<p class="err">${esc(error)}</p>` : ""}
${!IS_PANEL ? `<p><b>Waiting for approval.</b> Open your admin panel, switch to <b>${esc(NODE_NAME)}</b>, and approve this request. This page continues on its own.</p>` : `<form method="post" action="/authorize/decision" autocomplete="off">
<input type="hidden" name="rid" value="${esc(rid)}">
<label>Admin password<input type="password" name="password" required autocomplete="current-password"></label>
<label>Authenticator code<input name="totp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code"></label>
<div class="row"><button name="decision" value="deny">Deny</button><button class="primary" name="decision" value="approve">Approve</button></div>
</form>
<p class="mut">You can also approve it in the local admin panel on the Mac. This page will continue on its own.</p>`}
<script>
setInterval(async()=>{try{const r=await fetch('/authorize/status/${esc(rid)}');const j=await r.json();
if(j.status==='approved'&&j.redirect)location.href=j.redirect;}catch(e){}},3000);
</script>`
  );
}
