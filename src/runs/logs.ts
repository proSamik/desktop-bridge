import fs from "node:fs";
import path from "node:path";
import { HOME, CODEX_HOME_DIR, IS_WIN } from "../config.js";

const PROJECTS = path.join(HOME, ".claude", "projects");

function summarize(line: string) {
  try {
    const e = JSON.parse(line);
    const base: any = { type: e.type, ts: e.timestamp, session_id: e.sessionId };
    const msg = e.message;
    if (msg?.content) {
      const parts = Array.isArray(msg.content) ? msg.content : [{ type: "text", text: String(msg.content) }];
      base.role = msg.role;
      base.content = parts.map((p: any) => {
        if (p.type === "text") return { text: String(p.text).slice(0, 2000) };
        if (p.type === "tool_use") return { tool_use: p.name, input: JSON.stringify(p.input).slice(0, 800) };
        if (p.type === "tool_result") {
          const t = Array.isArray(p.content) ? p.content.map((c: any) => c.text || "").join("\n") : String(p.content ?? "");
          return { tool_result: t.slice(0, 1200), is_error: !!p.is_error };
        }
        if (p.type === "thinking") return { thinking: "[omitted]" };
        return { type: p.type };
      });
    } else if (e.summary) base.summary = e.summary;
    return base;
  } catch {
    return { raw: line.slice(0, 500) };
  }
}

function tailLines(file: string, n: number) {
  const lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
  return { total: lines.length, lines: lines.slice(-n) };
}

/** Claude Code encodes a project path by replacing "/" and "." with "-". */
const encodeProject = (p: string) => path.resolve(p.replace(/^~(?=$|[\\/])/, HOME)).replace(IS_WIN ? /[\\/:.]/g : /[/.]/g, "-");

export function readClaudeLogs(opts: { session_id?: string; project_path?: string; tail?: number }) {
  const tail = Math.min(Math.max(opts.tail ?? 40, 1), 300);
  if (!fs.existsSync(PROJECTS)) return { error: "no ~/.claude/projects directory" };

  if (opts.session_id) {
    if (!/^[0-9a-f-]{36}$/i.test(opts.session_id)) return { error: "session_id must be a UUID" };
    const dirs = opts.project_path ? [encodeProject(opts.project_path)] : fs.readdirSync(PROJECTS);
    for (const d of dirs) {
      const f = path.join(PROJECTS, d, `${opts.session_id}.jsonl`);
      if (f.startsWith(PROJECTS + path.sep) && fs.existsSync(f)) {
        const { total, lines } = tailLines(f, tail);
        return { session_id: opts.session_id, project_dir: d, file: f, total_entries: total, entries: lines.map(summarize) };
      }
    }
    return { error: "session not found" };
  }

  if (opts.project_path) {
    const dir = path.join(PROJECTS, encodeProject(opts.project_path));
    if (!dir.startsWith(PROJECTS + path.sep) || !fs.existsSync(dir)) return { error: "no transcripts for that project", project_dir: path.basename(dir) };
    const sessions = fs.readdirSync(dir).filter((f) => f.endsWith(".jsonl"))
      .map((f) => ({ session_id: f.replace(/\.jsonl$/, ""), mtime: fs.statSync(path.join(dir, f)).mtimeMs, size: fs.statSync(path.join(dir, f)).size }))
      .sort((a, b) => b.mtime - a.mtime).slice(0, 30)
      .map((s) => ({ ...s, mtime: new Date(s.mtime).toISOString() }));
    return { project_dir: path.basename(dir), sessions, hint: "pass session_id to read one" };
  }

  const recent = fs.readdirSync(PROJECTS).flatMap((d) => {
    const dir = path.join(PROJECTS, d);
    if (!fs.statSync(dir).isDirectory()) return [];
    return fs.readdirSync(dir).filter((f) => f.endsWith(".jsonl")).map((f) => ({ project_dir: d, session_id: f.replace(/\.jsonl$/, ""), mtime: fs.statSync(path.join(dir, f)).mtimeMs }));
  }).sort((a, b) => b.mtime - a.mtime).slice(0, 30).map((s) => ({ ...s, mtime: new Date(s.mtime).toISOString() }));
  return { recent_sessions: recent, hint: "pass session_id or project_path" };
}

// ---------- Codex transcripts (~/.codex/sessions/YYYY/MM/DD/rollout-*-<id>.jsonl) ----------

function walkJsonl(dir: string, out: string[] = [], depth = 0): string[] {
  if (depth > 4 || !fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walkJsonl(p, out, depth + 1);
    else if (e.name.endsWith(".jsonl")) out.push(p);
  }
  return out;
}
function summarizeCodex(line: string) {
  try {
    const e = JSON.parse(line);
    const p = e.payload ?? {};
    const base: any = { ts: e.timestamp, type: e.type, kind: p.type };
    if (p.type === "message") base.content = (p.content || []).map((c: any) => String(c.text ?? "").slice(0, 2000)).join("\n");
    else if (p.type === "function_call") base.content = `${p.name}(${String(p.arguments ?? "").slice(0, 800)})`;
    else if (p.type === "function_call_output") base.content = String(p.output?.content ?? p.output ?? "").slice(0, 1200);
    else if (p.type === "reasoning") base.content = "[reasoning omitted]";
    else if (e.type === "session_meta") base.content = { id: p.id, cwd: p.cwd, model: p.model };
    return base;
  } catch {
    return { raw: line.slice(0, 500) };
  }
}
export function readCodexLogs(opts: { session_id?: string; tail?: number }) {
  const tail = Math.min(Math.max(opts.tail ?? 40, 1), 300);
  const roots = [path.join(HOME, ".codex", "sessions"), path.join(CODEX_HOME_DIR, "sessions")];
  const files = roots.flatMap((r) => walkJsonl(r));
  if (opts.session_id) {
    if (!/^[0-9a-f-]{36}$/i.test(opts.session_id)) return { error: "session_id must be a UUID" };
    const f = files.find((x) => x.endsWith(`${opts.session_id}.jsonl`));
    if (!f) return { error: "session not found" };
    const { total, lines } = tailLines(f, tail);
    return { session_id: opts.session_id, file: f, total_entries: total, entries: lines.map(summarizeCodex) };
  }
  const recent = files.map((f) => ({ file: f, session_id: /([0-9a-f-]{36})\.jsonl$/.exec(f)?.[1], mtime: fs.statSync(f).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime).slice(0, 30).map((s) => ({ ...s, mtime: new Date(s.mtime).toISOString() }));
  return { recent_sessions: recent, hint: "pass session_id to read one" };
}
