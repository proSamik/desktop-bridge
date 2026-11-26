import crypto from "node:crypto";
import fs from "node:fs";
import { execFile } from "node:child_process";
import type { Request } from "express";
import { db, now, setSetting, getSetting } from "./db.js";
import { ALLOWED_MCP_PATH, POLICY_PATH, IS_DARWIN, IS_WIN, NODE_NAME, IS_PANEL, ADMIN_PORT } from "./config.js";
import { NOTIFY_ENABLED } from "./config.js";

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
let tnBrokenUntil = 0;
/** deploy/macos/notifier: posts as "Desktop Bridge", so a click / "Show" opens the URL. Looked up on every call. */
const bridgeNotifier = () => IS_DARWIN
  ? firstFile(`${process.env.HOME}/Applications/Desktop Bridge.app/Contents/MacOS/notifier`, "/Applications/Desktop Bridge.app/Contents/MacOS/notifier")
  : undefined;
let bnBrokenUntil = 0;

/**
 * Desktop notification; clicking it opens `url` (the admin panel) where the platform allows.
 * Text is always passed as argv / env, never interpolated into a script.
 *  - macOS: terminal-notifier if installed (click opens the URL), else AppleScript (click can't open a URL).
 *  - Linux: notify-send with an "Open admin panel" action (libnotify >= 0.7.9), else a plain notify-send.
 *  - Windows: a toast whose click opens the URL (built-in PowerShell + WinRT, no module needed).
 */
// ---------- batching: one summary notification per machine per window ----------
/** Allowed values of the notify_batch_seconds setting: 0 = instant, 60 = 1 minute, 300 = 5 minutes. */
export const NOTIFY_BATCH_CHOICES = [0, 60, 300];
const batchSeconds = () => {
  const n = Number(getSetting("notify_batch_seconds"));
  return NOTIFY_BATCH_CHOICES.includes(n) ? n : 60;
};
const pending = new Map<string, { url?: string; msgs: string[] }>(); // key: notification title (one per machine)
let flushTimer: NodeJS.Timeout | null = null;

/**
 * Queue a desktop notification. Within a batch window (Settings → Notifications, default 1 minute) all
 * notifications with the same title (= the same machine) become one: a single alert is shown as is,
 * several become "N alerts in the last minute" with the latest ones listed. Clicking opens the panel tab.
 */
export function notify(title: string, message: string, url?: string) {
  if (!NOTIFY_ENABLED) return; // MB_NOTIFY=0: e.g. a test copy, whose links would point at its own temporary port
  const win = batchSeconds();
  if (win === 0) return deliver(title, message, url);
  const p = pending.get(title) ?? { url, msgs: [] };
  p.msgs.push(message);
  if (url) p.url = url;
  pending.set(title, p);
  if (!flushTimer) flushTimer = setTimeout(flushNotifications, win * 1000);
}

/** Sends everything queued now (also used on shutdown and when the window is changed). */
export function flushNotifications() {
  if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
  const span = batchSeconds() >= 300 ? "5 minutes" : "minute";
  for (const [title, p] of pending) {
    if (p.msgs.length === 1) { deliver(title, p.msgs[0], p.url); continue; }
    const uniq = [...new Set(p.msgs)];
    const lines = uniq.slice(-3).map((m) => `• ${m.slice(0, 110)}`).join("\n");
    const more = uniq.length > 3 ? `\n+${uniq.length - 3} more in the admin panel` : "";
    deliver(title, `${p.msgs.length} alerts in the last ${span}:\n${lines}${more}`, p.url);
  }
  pending.clear();
}

function deliver(title: string, message: string, url?: string) {
  const msg = message.slice(0, 600);
  if (IS_DARWIN) {
    const plain = () => execFile("osascript", ["-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", title, msg], () => {});
    const tryTerminalNotifier = () => {
      if (!TERMINAL_NOTIFIER || Date.now() <= tnBrokenUntil) return plain();
      const args = ["-title", title, "-message", msg.replace(/^[-\[\\]/, " $&")];
      if (url) args.push("-open", url);
      execFile(TERMINAL_NOTIFIER, args, { timeout: 15_000 }, (err) => { if (err) { tnBrokenUntil = Date.now() + 3600_000; plain(); } });
    };
    const bn = bridgeNotifier();
    if (bn && Date.now() > bnBrokenUntil) {
      const args = ["--title", title, "--message", msg, "--group", title];
      if (url) args.push("--url", url);
      // Exit 3 = not allowed yet (System Settings > Notifications > Desktop Bridge); fall back and retry in 10 min.
      execFile(bn, args, { timeout: 120_000 }, (err) => { if (err) { bnBrokenUntil = Date.now() + 600_000; tryTerminalNotifier(); } });
      return;
    }
    if (TERMINAL_NOTIFIER && Date.now() > tnBrokenUntil) {
      const args = ["-title", title, "-message", msg.replace(/^[-\[\\]/, " $&")];
      if (url) args.push("-open", url);
      // terminal-notifier exits non-zero when macOS refuses it permission (e.g. newer macOS): fall back, retry in an hour.
      execFile(TERMINAL_NOTIFIER, args, { timeout: 15_000 }, (err) => { if (err) { tnBrokenUntil = Date.now() + 3600_000; plain(); } });
      return;
    }
    plain();
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

/** Alert kinds that are recorded (panel) but never pop up as desktop notifications. */
export const SILENT_ALERT_KINDS = new Set(["new_ip"]);

export function alert(kind: string, message: string) {
  db.prepare("INSERT INTO alerts(ts,kind,message) VALUES(?,?,?)").run(now(), kind, message);
  if (!SILENT_ALERT_KINDS.has(kind)) notify(`desktop-bridge (${NODE_NAME})`, message, panelUrl());
}

/** First few non-empty lines of a prompt, for notifications. */
export function promptExcerpt(prompt: string, maxLines = 3, maxChars = 220) {
  const lines = String(prompt).split(/\r?\n/).map((l) => l.trim()).filter(Boolean).slice(0, maxLines);
  const s = lines.join("\n");
  return s.length > maxChars ? s.slice(0, maxChars - 1) + "…" : s;
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
