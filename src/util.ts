import crypto from "node:crypto";
import fs from "node:fs";
import { execFile } from "node:child_process";
import type { Request } from "express";
import { db, now, setSetting } from "./db.js";
import { ALLOWED_MCP_PATH, POLICY_PATH, IS_DARWIN, IS_WIN, NODE_NAME, IS_PANEL, ADMIN_PORT } from "./config.js";

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

/** Admin panel URL on this machine (only panel machines have one); `remote` opens that remote's tab. */
export function panelUrl(remote?: string): string | undefined {
  if (!IS_PANEL) return undefined;
  return `http://127.0.0.1:${ADMIN_PORT}/${remote ? `#remote=${encodeURIComponent(remote)}` : ""}`;
}

const firstFile = (...ps: string[]) => ps.find((p) => { try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; } });
const TERMINAL_NOTIFIER = IS_DARWIN ? firstFile("/opt/homebrew/bin/terminal-notifier", "/usr/local/bin/terminal-notifier") : undefined;

/**
 * Desktop notification; clicking it opens `url` (the admin panel) where the platform allows.
 * Text is always passed as argv / env, never interpolated into a script.
 *  - macOS: terminal-notifier if installed (click opens the URL), else AppleScript (click can't open a URL).
 *  - Linux: notify-send with an "Open admin panel" action (libnotify >= 0.7.9), else a plain notify-send.
 *  - Windows: a toast whose click opens the URL (built-in PowerShell + WinRT, no module needed).
 */
export function notify(title: string, message: string, url?: string) {
  const msg = message.slice(0, 240);
  if (IS_DARWIN) {
    if (TERMINAL_NOTIFIER) {
      const args = ["-title", title, "-message", msg.replace(/^[-\[\\]/, " $&")];
      if (url) args.push("-open", url);
      execFile(TERMINAL_NOTIFIER, args, () => {});
      return;
    }
    execFile("osascript", ["-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", title, msg], () => {});
    return;
  }
  if (IS_WIN) {
    const ps = `
$e=[Security.SecurityElement]
$launch = if ($env:MB_N_URL) { ' activationType="protocol" launch="' + $e::Escape($env:MB_N_URL) + '"' } else { '' }
$xml = '<toast' + $launch + '><visual><binding template="ToastGeneric"><text>' + $e::Escape($env:MB_N_TITLE) + '</text><text>' + $e::Escape($env:MB_N_MSG) + '</text></binding></visual></toast>'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
$d = New-Object Windows.Data.Xml.Dom.XmlDocument; $d.LoadXml($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe').Show((New-Object Windows.UI.Notifications.ToastNotification $d))`;
    execFile("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps],
      { windowsHide: true, env: { ...process.env, MB_N_TITLE: title, MB_N_MSG: msg, MB_N_URL: url || "" } }, () => {});
    return;
  }
  // Linux
  if (!url) { execFile("notify-send", [title, msg], () => {}); return; }
  execFile("notify-send", ["--app-name=desktop-bridge", "--action=open=Open admin panel", "--wait", title, msg], { timeout: 10 * 60_000 }, (err, stdout) => {
    if (!err && String(stdout).trim() === "open") execFile("xdg-open", [url], () => {});
    else if (err && !(err as any).killed && /unknown option|unrecognized|invalid option/i.test(String((err as any).stderr ?? err.message))) {
      execFile("notify-send", [title, msg], () => {}); // libnotify without actions
    }
  });
}

export function alert(kind: string, message: string) {
  db.prepare("INSERT INTO alerts(ts,kind,message) VALUES(?,?,?)").run(now(), kind, message);
  notify(`desktop-bridge (${NODE_NAME})`, message, panelUrl());
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
