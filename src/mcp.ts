import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { db } from "./db.js";
import { ALLOWED_MCP_PATH, RUNS_DIR, GUARDED, HOME, NODE_NAME, PLATFORM_NAME } from "./config.js";
import { createRun, cancelRun, queuePosition } from "./runs/runner.js";
import { readClaudeLogs, readCodexLogs } from "./runs/logs.js";

const json = (v: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(v, null, 2) }] });
const fail = (msg: string) => ({ content: [{ type: "text" as const, text: msg }], isError: true });

const RUN_COLS = `id run_id, engine, status, verdict, verdict_reason, verdict_stage, prompt, cwd, model, resume_session_id, created_at, started_at, ended_at,
  exit_code, duration_ms, cost_usd, session_id, error`;

export type Caller = { clientId: string; tokenId: string; ip: string };

export function buildMcpServer(caller: Caller) {
  const s = new McpServer({ name: `desktop-bridge (${NODE_NAME})`, version: "1.2.0" });
  const where = `the owner's ${PLATFORM_NAME} machine "${NODE_NAME}"`;

  s.registerTool("ping", { description: "Health check. Returns pong and server time.", inputSchema: {} }, async () =>
    json({ pong: true, time: new Date().toISOString() })
  );

  const runSchema = {
    prompt: z.string().min(1).max(100_000),
    cwd: z.string().max(1024).optional().describe("Working directory; defaults to $HOME"),
    resume_session_id: z.string().optional().describe("Session/thread id to continue (Claude session_id or Codex thread id)"),
    model: z.string().optional(),
    max_turns: z.number().int().min(1).max(500).optional().describe("Claude only"),
  };
  const startRun = async (a: any, engine: "claude" | "codex") => {
    try { return json(await createRun({ ...a, engine, ...caller })); } catch (e: any) { return fail(e.message); }
  };
  const reviewNote = !GUARDED ? "" : " Every prompt passes an intent review first; it may be denied or held for the owner's approval.";

  s.registerTool(
    "run_claude",
    {
      description: `Start an async headless coding-agent run on ${where}. engine "claude" (default) runs \`claude -p\`; engine "codex" runs \`codex exec\`. Returns run_id immediately; poll get_run.${reviewNote}`,
      inputSchema: { ...runSchema, engine: z.enum(["claude", "codex"]).optional() },
    },
    async (a) => startRun(a, a.engine === "codex" ? "codex" : "claude")
  );
  s.registerTool(
    "run_codex",
    {
      description: `Start an async \`codex exec\` run on ${where} (same as run_claude with engine "codex"). Returns run_id; poll get_run.${reviewNote}`,
      inputSchema: runSchema,
    },
    async (a) => startRun(a, "codex")
  );

  const ownRun = (id: string) => db.prepare(`SELECT ${RUN_COLS}, result_text FROM runs WHERE id=? AND client_id=?`).get(id, caller.clientId) as any;

  s.registerTool(
    "get_run",
    {
      description: "Status and result of a run: status, verdict, exit code, duration, cost, session_id, final text, and the last stream events.",
      inputSchema: { run_id: z.string(), tail_events: z.number().int().min(0).max(200).optional() },
    },
    async ({ run_id, tail_events }) => {
      const r = ownRun(run_id);
      if (!r) return fail("run not found");
      let events: unknown[] = [];
      const f = path.join(RUNS_DIR, `${path.basename(run_id)}.jsonl`);
      if (fs.existsSync(f) && (tail_events ?? 10) > 0) {
        events = fs.readFileSync(f, "utf8").split("\n").filter(Boolean).slice(-(tail_events ?? 10)).map((l) => {
          try { const e = JSON.parse(l); return { type: e.type, subtype: e.subtype, text: JSON.stringify(e.message?.content ?? e.result ?? "").slice(0, 1500) }; } catch { return null; }
        }).filter(Boolean);
      }
      return json({ ...r, result_text: r.result_text, ...(r.status === "queued" ? { queue_position: queuePosition(r.run_id) } : {}), recent_events: events });
    }
  );

  s.registerTool(
    "list_runs",
    { description: "Recent runs started by this client.", inputSchema: { limit: z.number().int().min(1).max(100).optional() } },
    async ({ limit }) =>
      json(db.prepare(`SELECT ${RUN_COLS} FROM runs WHERE client_id=? ORDER BY created_at DESC LIMIT ?`).all(caller.clientId, limit ?? 20).map((r: any) => ({ ...r, prompt: String(r.prompt).slice(0, 300), ...(r.status === "queued" ? { queue_position: queuePosition(r.run_id) } : {}) })))
  );

  s.registerTool(
    "cancel_run",
    { description: "Cancel a queued or running run (kills the whole process tree).", inputSchema: { run_id: z.string() } },
    async ({ run_id }) => {
      if (!ownRun(run_id)) return fail("run not found");
      return json({ run_id, cancelled: cancelRun(run_id, "cancelled by client") });
    }
  );

  s.registerTool(
    "read_claude_logs",
    {
      description:
        "Read Claude Code transcripts under ~/.claude/projects. With session_id: the last `tail` entries of that session. " +
        "With project_path: list that project's sessions. With neither: most recent sessions across projects.",
      inputSchema: {
        session_id: z.string().optional(),
        project_path: z.string().optional(),
        tail: z.number().int().min(1).max(300).optional(),
      },
    },
    async (a) => json(readClaudeLogs(a))
  );

  s.registerTool(
    "read_codex_logs",
    {
      description: "Read Codex transcripts (~/.codex/sessions). With session_id (Codex thread id): last `tail` entries. Without: most recent sessions.",
      inputSchema: { session_id: z.string().optional(), tail: z.number().int().min(1).max(300).optional() },
    },
    async (a) => json(readCodexLogs(a))
  );

  if (!GUARDED) {
    s.registerTool("list_allowed_mcp", { description: "MCP servers available to runs on this box (the user's own Claude Code and Codex config; no restriction).", inputSchema: {} }, async () => {
      let claude: string[] = [], codex: string[] = [];
      try { claude = Object.keys(JSON.parse(fs.readFileSync(path.join(HOME, ".claude.json"), "utf8")).mcpServers || {}); } catch {}
      try { codex = [...fs.readFileSync(path.join(HOME, ".codex", "config.toml"), "utf8").matchAll(/^\[mcp_servers\.("?)([^\]."]+)\1\]/gm)].map((m) => m[2]); } catch {}
      return json({ restricted: false, claude, codex });
    });
    return s;
  }

  s.registerTool("list_allowed_mcp", { description: "MCP servers runs may use (from allowed-mcp.json; secrets not shown).", inputSchema: {} }, async () => {
    const cfg = JSON.parse(fs.readFileSync(ALLOWED_MCP_PATH, "utf8"));
    const out = Object.entries(cfg.mcpServers || {}).map(([name, v]: [string, any]) => ({
      name, type: v.type || "stdio", url: v.url, command: v.command, args: v.args,
    }));
    return json(out);
  });

  return s;
}
