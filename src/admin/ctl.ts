/**
 * Local control CLI (owner only; anyone with a shell on this Mac already owns it).
 *   npm run ctl -- status | clients | approve <client_id> | revoke <client_id> | kill on|off | runs | pin-config | approve-auth <auth_request_id>
 */
import { db, getSetting, setSetting, now } from "../db.js";
import { pinConfigHashes } from "../util.js";
import { kcGet, kcSet, KC } from "../config.js";
import fs from "node:fs";

const [cmd, arg] = process.argv.slice(2);
const out = (v: unknown) => console.log(JSON.stringify(v, null, 2));

switch (cmd) {
  case "status":
    out({
      kill_switch: getSetting("kill_switch"), permission_mode: getSetting("permission_mode"), rate_limit_per_hour: getSetting("rate_limit_per_hour"),
      public_base_url: getSetting("public_base_url"),
      clients: db.prepare("SELECT status, COUNT(*) n FROM clients GROUP BY status").all(),
      runs: db.prepare("SELECT status, COUNT(*) n FROM runs GROUP BY status").all(),
    });
    break;
  case "clients":
    out(db.prepare("SELECT id, name, status, is_mine, reg_ip, created_at, last_seen FROM clients ORDER BY created_at DESC").all());
    break;
  case "approve":
    out({ changed: db.prepare("UPDATE clients SET status='approved' WHERE id=? AND status='pending'").run(arg).changes });
    break;
  case "approve-auth": {
    const ar = db.prepare("SELECT client_id FROM auth_requests WHERE id=? AND status='pending'").get(arg) as any;
    if (!ar) { out({ error: "no pending request" }); break; }
    db.prepare("UPDATE clients SET status='approved' WHERE id=? AND status!='revoked'").run(ar.client_id);
    db.prepare("UPDATE auth_requests SET status='approved' WHERE id=?").run(arg);
    out({ ok: true });
    break;
  }
  case "revoke":
    // Service picks up revocation on next request; running jobs are cancelled by the server on its next pump/refresh.
    db.prepare("UPDATE clients SET status='revoked' WHERE id=?").run(arg);
    db.prepare("UPDATE tokens SET revoked_at=? WHERE client_id=? AND revoked_at IS NULL").run(now(), arg);
    db.prepare("UPDATE runs SET status='cancelled', error='client revoked', ended_at=? WHERE client_id=? AND status IN ('queued','awaiting_approval')").run(now(), arg);
    out({ ok: true, note: "running jobs: cancel from the admin panel" });
    break;
  case "kill":
    setSetting("kill_switch", arg === "on" ? "1" : "0");
    out({ kill_switch: getSetting("kill_switch"), note: "use the admin panel to also stop a run in progress" });
    break;
  case "runs":
    out(db.prepare("SELECT id, status, verdict, verdict_reason, substr(prompt,1,80) prompt, cost_usd, session_id FROM runs ORDER BY created_at DESC LIMIT 20").all());
    break;
  case "pin-config":
    pinConfigHashes();
    out({ ok: true });
    break;
  case "tunnel-token": {
    // Used by the tunnel launch scripts; prints the token only to the calling process.
    const t = kcGet(KC.tunnelToken);
    if (!t) { console.error("secret tunnel-token not set"); process.exit(1); }
    process.stdout.write(t);
    break;
  }
  case "secret-set": {
    // Reads the value from stdin so it never appears in argv: echo -n VALUE | npm run -s ctl -- secret-set <name>
    const allowed = /^(tunnel-token|admin-api-key|remote-key-[A-Za-z0-9-]+|env-[A-Z0-9_]+|cloudflare-api-token)$/;
    if (!allowed.test(arg || "")) { console.error("name must be tunnel-token | admin-api-key | remote-key-<name> | env-<VAR> | cloudflare-api-token"); process.exit(1); }
    const v = fs.readFileSync(0, "utf8").trim();
    if (!v) { console.error("empty value on stdin"); process.exit(1); }
    kcSet(arg, v);
    console.log(`stored ${arg}`);
    break;
  }
  default:
    console.log("usage: npm run ctl -- status|clients|approve <id>|approve-auth <id>|revoke <id>|kill on|off|runs|pin-config|tunnel-token|secret-set <name>");
}
