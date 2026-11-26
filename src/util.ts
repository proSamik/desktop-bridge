import crypto from "node:crypto";
import fs from "node:fs";
import { execFile } from "node:child_process";
import type { Request } from "express";
import { db, now, setSetting } from "./db.js";
import { ALLOWED_MCP_PATH, POLICY_PATH, IS_DARWIN, IS_WIN, NODE_NAME } from "./config.js";

export const sha256 = (s: string | Buffer) => crypto.createHash("sha256").update(s).digest("hex");
export const randToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");
export const randId = (prefix: string) => `${prefix}_${crypto.randomBytes(9).toString("base64url")}`;
export function safeEqual(a: string, b: string) {
  const ab = Buffer.from(a), bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

/** Real client IP: Cloudflare header when tunneled, socket address otherwise. */
export function clientIp(req: Request): string {
  return (req.header("cf-connecting-ip") || req.socket.remoteAddress || "").replace(/^::ffff:/, "");
}

/** macOS notification. Text goes through argv, never interpolated into AppleScript. */
export function notify(title: string, message: string) {
  if (IS_WIN) return;
  if (!IS_DARWIN) { execFile("notify-send", [title, message.slice(0, 240)], () => {}); return; }
  execFile(
    "osascript",
    ["-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", title, message.slice(0, 240)],
    () => {}
  );
}

export function alert(kind: string, message: string) {
  db.prepare("INSERT INTO alerts(ts,kind,message) VALUES(?,?,?)").run(now(), kind, message);
  notify(`desktop-bridge (${NODE_NAME})`, message);
}

/** Records an IP; raises an alert the first time it is seen. */
export function trackIp(ip: string, context: string) {
  if (!ip) return;
  const r = db.prepare("INSERT OR IGNORE INTO known_ips(ip, first_seen) VALUES(?,?)").run(ip, now());
  if (r.changes > 0) alert("new_ip", `Request from new IP ${ip} (${context})`);
}

export function fileSha(p: string) {
  try {
    return sha256(fs.readFileSync(p));
  } catch {
    return "missing";
  }
}

/** Snapshot of config hashes, taken whenever the admin saves config. Runs refuse to start if files drift. */
export function pinConfigHashes() {
  setSetting("allowed_mcp_sha256", fileSha(ALLOWED_MCP_PATH));
  setSetting("policy_sha256", fileSha(POLICY_PATH));
}

// ---------- IP allowlist (applied to tunneled traffic) ----------
function v4(ip: string): number | null {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((x) => x > 255)) return null;
  return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
}
export function ipAllowed(ip: string, list: string): boolean {
  const addr = v4(ip);
  for (const raw of list.split(/[\s,]+/).filter(Boolean)) {
    const [net, bitsS] = raw.split("/");
    if (addr === null || v4(net) === null) { if (raw.toLowerCase() === ip.toLowerCase()) return true; continue; }
    const bits = bitsS === undefined ? 32 : Number(bitsS);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if (((addr & mask) >>> 0) === ((v4(net)! & mask) >>> 0)) return true;
  }
  return false;
}
