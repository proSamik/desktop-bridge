// Optional edge filter: a Cloudflare WAF custom rule that blocks HOST unless the client IP is allowlisted.
// The bridge already enforces the same allowlist at the origin (Settings -> IP allowlist); this stops traffic earlier.
//   CLOUDFLARE_API_TOKEN=... node scripts/cloudflare-waf.mjs --hostname mcp.example.com [--allow "1.2.3.4,5.6.7.0/24"]
// Token needs Zone WAF:Edit on the zone. Anthropic's outbound ranges are always included.
const ANTHROPIC_OUTBOUND = ["160.79.104.0/21", "153.61.208.0/20"]; // https://platform.claude.com/docs/en/api/ip-addresses
const argv = process.argv.slice(2);
const opt = (k, d) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };
const HOST = opt("hostname");
const ALLOW = [...ANTHROPIC_OUTBOUND, ...String(opt("allow", "")).split(",").map((s) => s.trim()).filter(Boolean)];
const TOKEN = process.env.CLOUDFLARE_API_TOKEN;
if (!HOST || !TOKEN) { console.log("usage: CLOUDFLARE_API_TOKEN=... node scripts/cloudflare-waf.mjs --hostname HOST [--allow IPs]"); process.exit(1); }
async function cf(method, p, body) {
  const r = await fetch(`https://api.cloudflare.com/client/v4${p}`, { method, headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json();
  if (!j.success && r.status !== 404) throw new Error(`${method} ${p}: ${JSON.stringify(j.errors)}`);
  return { status: r.status, ...j };
}
const zone = (await cf("GET", `/zones?name=${HOST.split(".").slice(-2).join(".")}`)).result[0];
if (!zone) throw new Error("zone not found");
const ref = `desktop-bridge-${HOST.replace(/[^a-z0-9]/gi, "-")}`.slice(0, 60);
const rule = { ref, description: `desktop-bridge: ${HOST} allowlist`, expression: `(http.host eq "${HOST}" and not ip.src in {${ALLOW.join(" ")}})`, action: "block", enabled: true };
const phase = `/zones/${zone.id}/rulesets/phases/http_request_firewall_custom/entrypoint`;
const ep = await cf("GET", phase);
if (ep.status === 404) await cf("PUT", phase, { rules: [rule] });
else {
  const ex = (ep.result.rules || []).find((r) => r.ref === ref);
  if (ex) await cf("PATCH", `/zones/${zone.id}/rulesets/${ep.result.id}/rules/${ex.id}`, rule);
  else await cf("POST", `/zones/${zone.id}/rulesets/${ep.result.id}/rules`, rule);
}
console.log("WAF rule live:", rule.expression);
