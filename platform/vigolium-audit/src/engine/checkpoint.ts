import { existsSync } from "fs";
import { readFile, unlink } from "fs/promises";
import { join } from "path";
import { atomicWrite, round2 } from "./util.js";

export interface CheckpointData {
  startedAt: number;
  toolCalls: number;
  lastTool?: string;
  usd: number;
  tokens: { input: number; output: number };
}

export interface LoadedCheckpoint {
  usd: number;
  tokens: { input: number; output: number };
  toolCalls: number;
  lastTool: string | null;
}

/**
 * Persists per-phase progress mid-stream so an interrupted phase leaves a
 * record the next run can surface and bill against the chained budget. The
 * phase itself still has to restart from scratch — adapters don't expose
 * conversation replay, so we can't resume mid-conversation. Files live under
 * `<resultsDir>/.checkpoint/<auditId>/<phaseId>.json`.
 */
export class CheckpointStore {
  constructor(private readonly resultsDir: string) {}

  private path(auditId: string, phaseId: string): string {
    return join(this.resultsDir, ".checkpoint", encodePathSegment(auditId), `${encodePathSegment(phaseId)}.json`);
  }

  async write(auditId: string, phaseId: string, data: CheckpointData): Promise<void> {
    const payload = {
      audit_id: auditId,
      phase_id: phaseId,
      started_at_ms: data.startedAt,
      updated_at_ms: Date.now(),
      tool_calls: data.toolCalls,
      ...(data.lastTool !== undefined ? { last_tool: data.lastTool } : {}),
      usd: round2(data.usd),
      tokens: data.tokens,
    };
    await atomicWrite(this.path(auditId, phaseId), JSON.stringify(payload, null, 2) + "\n");
  }

  async clear(auditId: string, phaseId: string): Promise<void> {
    try {
      await unlink(this.path(auditId, phaseId));
    } catch {
      /* missing is fine */
    }
  }

  /**
   * Read a checkpoint left behind by a prior interrupted attempt, if any.
   * Returns the cost+tokens that should be rolled into the audit total even
   * though the phase itself will run again from scratch.
   */
  async load(auditId: string, phaseId: string): Promise<LoadedCheckpoint | null> {
    const path = this.path(auditId, phaseId);
    if (!existsSync(path)) return null;
    try {
      const raw = await readFile(path, "utf8");
      const json = JSON.parse(raw) as {
        usd?: number;
        tokens?: { input: number; output: number };
        tool_calls?: number;
        last_tool?: string;
      };
      return {
        usd: typeof json.usd === "number" ? json.usd : 0,
        tokens: json.tokens ?? { input: 0, output: 0 },
        toolCalls: json.tool_calls ?? 0,
        lastTool: json.last_tool ?? null,
      };
    } catch {
      return null;
    }
  }
}

/**
 * Make an audit-id or phase-id safe to use as a filename. Audit IDs are ISO
 * timestamps, which contain `:` (illegal on Windows / awkward in shells), so
 * replace anything outside [A-Za-z0-9._-] with `_`.
 */
export function encodePathSegment(s: string): string {
  return s.replace(/[^A-Za-z0-9._-]+/g, "_");
}
