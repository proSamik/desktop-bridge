// Create (or reuse) a remote-managed Cloudflare Tunnel for this machine, route ONLY the MCP port, store its token.
//   node scripts/cloudflare-tunnel.mjs --name my-bridge --hostname mcp.example.com [--port 8787] [--account <id>] [--dns]
// Auth: $CLOUDFLARE_API_TOKEN, else the token from `npx wrangler login` (its connectivity:admin scope covers tunnels).
// --dns also creates the proxied CNAME; that needs a token with Zone DNS:Edit (wrangler's login does not have it) —
// otherwise use:  cloudflared tunnel login  &&  cloudflared tunnel route dns <tunnel-id> <hostname>
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { kcSet, KC, MCP_PORT } from "../dist/config.js";

const argv = process.argv.slice(2);
const opt = (k, d) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };
const NAME = opt("name"), HOST = opt("hostname"), PORT = Number(opt("port", MCP_PORT));
if (!NAME || !HOST) { console.log("usage: node scripts/cloudflare-tunnel.mjs --name NAME --hostname HOST [--port 8787] [--account ID] [--dns]"); process.exit(1); }

function wranglerToken() {
  const h = os.homedir();
  const files = [
    path.join(h, "Library/Preferences/.wrangler/config/default.toml"),
    path.join(h, ".config/.wrangler/config/default.toml"),
    path.join(h, ".wrangler/config/default.toml"),
    path.join(process.env.APPDATA || "", "xdg.config/.wrangler/config/default.toml"),
  ];
  for (const f of files) { try { const m = /^oauth_token\s*=\s*"([^"]+)"/m.exec(fs.readFileSync(f, "utf8")); if (m) return m[1]; } catch {} }
  return null;
}
const TOKEN = process.env.CLOUDFLARE_API_TOKEN || wranglerToken();
if (!TOKEN) { console.log("No Cloudflare credentials: set CLOUDFLARE_API_TOKEN or run `npx wrangler login`."); process.exit(1); }
async function cf(method, p, body) {
  const r = await fetch(`https://api.cloudflare.com/client/v4${p}`, { method, headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json();
  if (!j.success) throw new Error(`${method} ${p}: ${JSON.stringify(j.errors)}`);
  return j.result;
}

let account = opt("account");
if (!account) {
  const accts = await cf("GET", "/accounts");
  if (accts.length !== 1) { console.log("Several accounts; pass --account <id>:", accts.map((a) => `${a.id} ${a.name}`).join(", ")); process.exit(1); }
  account = accts[0].id;
}
let tunnel = (await cf("GET", `/accounts/${account}/cfd_tunnel?name=${encodeURIComponent(NAME)}&is_deleted=false`))[0];
if (!tunnel) tunnel = await cf("POST", `/accounts/${account}/cfd_tunnel`, { name: NAME, config_src: "cloudflare" });
console.log(`tunnel ${NAME}: ${tunnel.id}`);

await cf("PUT", `/accounts/${account}/cfd_tunnel/${tunnel.id}/configurations`, {
  config: { ingress: [{ hostname: HOST, service: `http://127.0.0.1:${PORT}`, originRequest: { httpHostHeader: HOST } }, { service: "http_status:404" }] },
});
console.log(`ingress: ${HOST} -> http://127.0.0.1:${PORT} (admin port is NOT routed)`);

kcSet(KC.tunnelToken, await cf("GET", `/accounts/${account}/cfd_tunnel/${tunnel.id}/token`));
console.log("tunnel token stored as secret tunnel-token (run it with bin/run-tunnel.sh or the installer's --tunnel option)");

if (argv.includes("--dns")) {
  const zone = (await cf("GET", `/zones?name=${HOST.split(".").slice(-2).join(".")}`))[0];
  if (!zone) throw new Error("zone not found for " + HOST);
  const rec = { type: "CNAME", name: HOST, content: `${tunnel.id}.cfargotunnel.com`, proxied: true, ttl: 1 };
  const existing = (await cf("GET", `/zones/${zone.id}/dns_records?name=${HOST}`))[0];
  if (existing) await cf("PATCH", `/zones/${zone.id}/dns_records/${existing.id}`, rec); else await cf("POST", `/zones/${zone.id}/dns_records`, rec);
  console.log(`DNS: ${HOST} CNAME ${tunnel.id}.cfargotunnel.com (proxied)`);
} else {
  console.log(`Next (DNS): cloudflared tunnel login  &&  cloudflared tunnel route dns ${tunnel.id} ${HOST}`);
}
console.log("Don't open the hostname before its DNS record exists: resolvers cache the miss for up to 30 minutes.");
