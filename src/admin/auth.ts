import crypto from "node:crypto";
import type { Request, Response, NextFunction } from "express";
import { KC, kcGet, ADMIN_SESSION_TTL_S } from "../config.js";
import { db, now, getSetting, setSetting } from "../db.js";
import { sha256, randToken, safeEqual, clientIp, alert } from "../util.js";

// ---------- password (scrypt) ----------
export function hashPassword(pw: string): string {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(pw, salt, 64, { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  return `scrypt$15$${salt.toString("base64url")}$${h.toString("base64url")}`;
}
export function verifyPassword(pw: string, stored: string | null): boolean {
  if (!stored) return false;
  const [alg, logN, saltB, hashB] = stored.split("$");
  if (alg !== "scrypt") return false;
  const h = crypto.scryptSync(pw, Buffer.from(saltB, "base64url"), 64, { N: 1 << Number(logN), r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  return crypto.timingSafeEqual(h, Buffer.from(hashB, "base64url"));
}

// ---------- TOTP (RFC 6238, SHA1, 6 digits, 30s) ----------
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export function base32Encode(buf: Buffer) {
  let bits = 0, val = 0, out = "";
  for (const b of buf) {
    val = (val << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
function base32Decode(s: string) {
  let bits = 0, val = 0; const out: number[] = [];
  for (const c of s.replace(/=+$/, "").toUpperCase()) {
    const i = B32.indexOf(c); if (i < 0) continue;
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
export function totpAt(secret: string, counter: number) {
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac("sha1", base32Decode(secret)).update(buf).digest();
  const o = h[h.length - 1] & 15;
  const code = ((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
  return code;
}
/** Accepts ±1 step; rejects replay of an already-used step. */
function verifyTotp(code: string): boolean {
  const secret = kcGet(KC.totpSecret);
  if (!secret || !/^\d{6}$/.test(code)) return false;
  const c = Math.floor(Date.now() / 30000);
  const last = Number(getSetting("last_totp_counter"));
  for (const d of [-1, 0, 1]) {
    if (c + d > last && safeEqual(totpAt(secret, c + d), code)) {
      setSetting("last_totp_counter", String(c + d));
      return true;
    }
  }
  return false;
}

// ---------- lockout ----------
const failures = new Map<string, number[]>();
function locked(ip: string) {
  const cutoff = Date.now() - 15 * 60_000;
  const f = (failures.get(ip) || []).filter((t) => t > cutoff);
  failures.set(ip, f);
  const global = [...failures.values()].flat().filter((t) => t > Date.now() - 3600_000).length;
  return f.length >= 5 || global >= 20;
}

export type LoginResult = { ok: true } | { ok: false; error: string };
export function checkAdminCredentials(ip: string, password: string, totp: string, where: string): LoginResult {
  if (locked(ip)) return { ok: false, error: "Too many failed attempts. Try again in 15 minutes." };
  const okPw = verifyPassword(String(password || ""), kcGet(KC.adminPasswordHash));
  const okTotp = okPw && verifyTotp(String(totp || "").trim());
  if (okPw && okTotp) return { ok: true };
  failures.set(ip, [...(failures.get(ip) || []), Date.now()]);
  if ((failures.get(ip) || []).length >= 3) alert("login_fail", `Failed admin login from ${ip} (${where})`);
  return { ok: false, error: "Invalid password or code." };
}

// ---------- sessions ----------
export function createSession(ip: string) {
  const id = randToken(32), csrf = randToken(24);
  db.prepare("INSERT INTO admin_sessions(id_hash,csrf,ip,created_at,expires_at) VALUES(?,?,?,?,?)").run(
    sha256(id), csrf, ip, now(), now() + ADMIN_SESSION_TTL_S
  );
  return { id, csrf };
}
export function getSession(req: Request): { csrf: string } | null {
  const m = /(?:^|;\s*)mb_admin=([A-Za-z0-9_-]+)/.exec(req.header("cookie") || "");
  if (!m) return null;
  const row = db.prepare("SELECT csrf, expires_at FROM admin_sessions WHERE id_hash=?").get(sha256(m[1])) as any;
  if (!row || row.expires_at < now()) return null;
  return { csrf: row.csrf };
}
export function destroySession(req: Request) {
  const m = /(?:^|;\s*)mb_admin=([A-Za-z0-9_-]+)/.exec(req.header("cookie") || "");
  if (m) db.prepare("DELETE FROM admin_sessions WHERE id_hash=?").run(sha256(m[1]));
}
export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: "login required" });
  if (req.method !== "GET" && !safeEqual(req.header("x-mb-csrf") || "", s.csrf)) return res.status(403).json({ error: "bad csrf" });
  next();
}
export { clientIp };
