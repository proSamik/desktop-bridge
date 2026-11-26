/**
 * Interactive setup. Run in your own terminal from the install directory:
 *   npm run setup                      # panel machine: admin password + TOTP, then MCP env secrets
 *   npm run setup -- password | totp   # one step
 *   npm run setup -- mcp-env           # secrets for ${VARS} referenced in config/allowed-mcp.json
 *   npm run setup -- api-key           # "api" machine: create the key its admin API accepts (shown once)
 *   npm run setup -- remote-key <name> # panel machine: store the api-key of remote <name>
 * Secrets go to the macOS Keychain, or to <install dir>/secrets/ on Linux/Windows.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import readline from "node:readline";
import QRCode from "qrcode";
import { KC, kcGet, kcSet, IS_PANEL, NODE_NAME, ALLOWED_MCP_PATH, envSecretName, remoteKeyName, IS_DARWIN } from "../config.js";
import { hashPassword, base32Encode, totpAt } from "./auth.js";

const store = IS_DARWIN ? "Keychain" : "secrets/";

function ask(q: string, hidden = false): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) (rl as any)._writeToOutput = (s: string) => process.stdout.write(s.includes(q) ? s : "*");
    rl.question(q, (a) => { rl.close(); if (hidden) process.stdout.write("\n"); resolve(a); });
  });
}
const yes = async (q: string) => (await ask(q)).trim().toLowerCase() === "y";

async function password() {
  if (kcGet(KC.adminPasswordHash) && !(await yes("Admin password already set. Replace it? [y/N] "))) return;
  for (;;) {
    const a = await ask("New admin password (min 12 chars): ", true);
    if (a.length < 12) { console.log("Too short."); continue; }
    if (a !== (await ask("Repeat: ", true))) { console.log("Didn't match."); continue; }
    kcSet(KC.adminPasswordHash, hashPassword(a));
    console.log(`✓ Password hash saved (${store}).`);
    return;
  }
}

async function totp() {
  if (kcGet(KC.totpSecret) && !(await yes("TOTP already enrolled. Re-enroll (old codes stop working)? [y/N] "))) return;
  const secret = base32Encode(crypto.randomBytes(20));
  const uri = `otpauth://totp/desktop-bridge:${encodeURIComponent(NODE_NAME)}?secret=${secret}&issuer=desktop-bridge&algorithm=SHA1&digits=6&period=30`;
  console.log("\nScan with your authenticator app:\n");
  console.log(await QRCode.toString(uri, { type: "terminal", small: true }));
  console.log(`Or enter manually: ${secret}\n`);
  for (;;) {
    const code = (await ask("Enter the 6-digit code to confirm: ")).trim();
    const c = Math.floor(Date.now() / 30000);
    if ([-1, 0, 1].some((d) => totpAt(secret, c + d) === code)) break;
    console.log("Code didn't match, try again.");
  }
  kcSet(KC.totpSecret, secret);
  console.clear();
  console.log(`✓ TOTP enrolled (${store}); screen cleared.`);
}

async function mcpEnv() {
  let raw = "";
  try { raw = fs.readFileSync(ALLOWED_MCP_PATH, "utf8"); } catch { console.log("No config/allowed-mcp.json yet (it is created on first start)."); return; }
  const vars = [...new Set([...raw.matchAll(/\$\{([A-Z0-9_]+)\}/g)].map((m) => m[1]))];
  if (!vars.length) { console.log("allowed-mcp.json references no ${VARS}; nothing to store."); return; }
  for (const v of vars) {
    const name = envSecretName(v);
    if (kcGet(name) && !(await yes(`${v} already stored. Replace? [y/N] `))) continue;
    const val = (await ask(`Value for ${v} (blank to skip): `, true)).trim();
    if (val) { kcSet(name, val); console.log(`✓ ${v} saved as secret "${name}" (${store}).`); }
  }
}

function apiKey() {
  if (kcGet(KC.adminApiKey)) { console.log(`An admin API key already exists (${store}: ${KC.adminApiKey}). Delete it first to rotate.`); return; }
  const key = crypto.randomBytes(32).toString("base64url");
  kcSet(KC.adminApiKey, key);
  console.log(`\nAdmin API key for "${NODE_NAME}" (shown once). On the panel machine run:\n  npm run setup -- remote-key ${NODE_NAME}\nand paste:\n\n  ${key}\n`);
}

async function remoteKey(name: string) {
  if (!/^[A-Za-z0-9-]{1,32}$/.test(name || "")) { console.log("usage: npm run setup -- remote-key <name>   (name as used in MB_REMOTES)"); return; }
  const v = (await ask(`Admin API key of remote "${name}": `, true)).trim();
  if (!v) return;
  kcSet(remoteKeyName(name), v);
  console.log(`✓ Stored as "${remoteKeyName(name)}" (${store}). Add "${name}=<admin url>" to MB_REMOTES and restart.`);
}

async function main() {
  const [step, arg] = process.argv.slice(2);
  switch (step) {
    case "password": return password();
    case "totp": return totp();
    case "mcp-env": return mcpEnv();
    case "api-key": return apiKey();
    case "remote-key": return remoteKey(arg);
    case undefined:
      if (IS_PANEL) { await password(); await totp(); }
      else apiKey();
      await mcpEnv();
      console.log("\nDone. Restart the service so it picks up the changes.");
      return;
    default:
      console.log("usage: npm run setup [-- password|totp|mcp-env|api-key|remote-key <name>]");
  }
}
main().catch((e) => { console.error(e.message); process.exit(1); });
