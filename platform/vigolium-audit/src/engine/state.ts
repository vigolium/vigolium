import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import { z } from "zod";
import { atomicWrite, sha256OfFile } from "./util.js";
import type { AuditContext, AuditMode, AuditRecord, AuditState, PhaseStatus } from "./types.js";

const PhaseRecordSchema = z.object({
  status: z.enum(["pending", "in_progress", "complete", "failed", "skipped"]),
  started_at: z.string().optional(),
  completed_at: z.string().optional(),
  failed_at: z.string().optional(),
  error: z.string().optional(),
});

const AuditRecordSchema = z.object({
  audit_id: z.string(),
  commit: z.string().nullable(),
  branch: z.string().nullable(),
  repository: z.string().nullable(),
  mode: z.string(),
  model: z.string().nullable(),
  agent_sdk: z.string(),
  started_at: z.string(),
  completed_at: z.string().nullable(),
  status: z.enum(["in_progress", "complete", "failed", "aborted"]),
  phases: z.record(z.string(), PhaseRecordSchema),
  usage: z
    .object({
      input_tokens: z.number(),
      output_tokens: z.number(),
      cost_usd: z.number(),
    })
    .optional(),
  context: z
    .object({
      focus: z.string().optional(),
      expected_behaviors: z.string().optional(),
    })
    .optional(),
  triggered_via: z.string().optional(),
});

const AuditStateSchema = z.object({
  schema_version: z.literal(1).default(1),
  audits: z.array(AuditRecordSchema),
});

const FILENAME_AUDIT = "audit-state.json";
const FILENAME_FILE = "file-state.json";

const FileStateSchema = z.object({
  schema_version: z.literal(1).default(1),
  files: z.record(
    z.string(),
    z.object({
      sha256: z.string(),
      last_audits: z.array(z.string()),
      last_phases: z.array(z.string()),
    }),
  ),
});

export type FileState = z.infer<typeof FileStateSchema>;

export class StateStore {
  /**
   * Tail of an in-flight write chain. Every read-modify-write awaits this and
   * then assigns its own promise, serializing concurrent updates so two
   * phases running in parallel don't lose each other's writes.
   */
  private writeChain: Promise<unknown> = Promise.resolve();

  constructor(private readonly resultsDir: string) {}

  private auditPath(): string {
    return join(this.resultsDir, FILENAME_AUDIT);
  }
  private filePath(): string {
    return join(this.resultsDir, FILENAME_FILE);
  }

  /** Serialize an async section against any other in-flight write on this store. */
  private async withWriteLock<T>(fn: () => Promise<T>): Promise<T> {
    const prev = this.writeChain;
    let release: (v: unknown) => void = () => {};
    this.writeChain = new Promise((r) => { release = r; });
    try {
      await prev.catch(() => {});
      return await fn();
    } finally {
      release(undefined);
    }
  }

  async load(): Promise<AuditState> {
    if (!existsSync(this.auditPath())) {
      return { schema_version: 1, audits: [] };
    }
    const raw = await readFile(this.auditPath(), "utf8");
    let json: unknown;
    try {
      json = JSON.parse(raw);
    } catch (err) {
      throw new Error(`audit-state.json: invalid JSON: ${(err as Error).message}`);
    }
    const parsed = AuditStateSchema.safeParse(json);
    if (!parsed.success) {
      throw new Error(`audit-state.json: schema mismatch: ${parsed.error.message}`);
    }
    return parsed.data as AuditState;
  }

  async save(state: AuditState): Promise<void> {
    await atomicWrite(this.auditPath(), JSON.stringify(state, null, 2) + "\n");
  }

  async appendAudit(record: AuditRecord): Promise<AuditState> {
    return this.withWriteLock(async () => {
      const state = await this.load();
      state.audits.push(record);
      await this.save(state);
      return state;
    });
  }

  async updatePhase(
    auditId: string,
    phaseId: string,
    update: Partial<{ status: PhaseStatus; started_at: string; completed_at: string; failed_at: string; error: string }>,
  ): Promise<void> {
    return this.withWriteLock(async () => {
      const state = await this.load();
      const audit = state.audits.find((a) => a.audit_id === auditId);
      if (!audit) throw new Error(`audit ${auditId} not found in state`);
      const existing = audit.phases[phaseId] ?? { status: "pending" as PhaseStatus };
      audit.phases[phaseId] = { ...existing, ...update };
      await this.save(state);
    });
  }

  async updateAudit(
    auditId: string,
    update: Partial<Pick<AuditRecord, "status" | "completed_at" | "model" | "usage">>,
  ): Promise<void> {
    return this.withWriteLock(async () => {
      const state = await this.load();
      const audit = state.audits.find((a) => a.audit_id === auditId);
      if (!audit) throw new Error(`audit ${auditId} not found in state`);
      Object.assign(audit, update);
      await this.save(state);
    });
  }

  async latestAudit(mode?: AuditMode | "any"): Promise<AuditRecord | null> {
    const state = await this.load();
    const candidates = mode && mode !== "any" ? state.audits.filter((a) => a.mode === mode) : state.audits;
    if (candidates.length === 0) return null;
    return candidates[candidates.length - 1] ?? null;
  }

  async loadFileState(): Promise<FileState> {
    if (!existsSync(this.filePath())) {
      return { schema_version: 1, files: {} };
    }
    const raw = await readFile(this.filePath(), "utf8");
    const parsed = FileStateSchema.safeParse(JSON.parse(raw));
    if (!parsed.success) throw new Error(`file-state.json: schema mismatch: ${parsed.error.message}`);
    return parsed.data;
  }

  async saveFileState(state: FileState): Promise<void> {
    await atomicWrite(this.filePath(), JSON.stringify(state, null, 2) + "\n");
  }

  /**
   * Hash each file in `files` (relative to targetDir) and merge into
   * file-state.json with the given audit + phase attribution. last_audits /
   * last_phases keep the most recent five entries each — enough for diff /
   * incremental routing without unbounded growth.
   */
  async recordFileSnapshot(args: {
    targetDir: string;
    files: string[];
    auditId: string;
    completedPhaseIds: string[];
  }): Promise<void> {
    return this.withWriteLock(async () => {
      const existing = await this.loadFileState().catch(() => ({
        schema_version: 1 as const,
        files: {} as FileState["files"],
      }));
      // Parallelize the hashing — IO-bound and the file count can run into
      // the tens of thousands. Returns null entries for unreadable files.
      const hashes = await Promise.all(
        args.files.map(async (rel) => ({ rel, sha: await sha256OfFile(join(args.targetDir, rel)) })),
      );
      for (const { rel, sha } of hashes) {
        if (sha === null) continue;
        const prev = existing.files[rel];
        const lastAudits = appendUnique(prev?.last_audits ?? [], args.auditId, 5);
        const lastPhases = mergeUnique(prev?.last_phases ?? [], args.completedPhaseIds, 5);
        existing.files[rel] = { sha256: sha, last_audits: lastAudits, last_phases: lastPhases };
      }
      await this.saveFileState(existing);
    });
  }
}

function appendUnique(list: string[], item: string, cap: number): string[] {
  const filtered = list.filter((x) => x !== item);
  filtered.push(item);
  return filtered.slice(-cap);
}

function mergeUnique(existing: string[], incoming: string[], cap: number): string[] {
  const seen = new Set(existing);
  const out = [...existing];
  for (const v of incoming) {
    if (!seen.has(v)) {
      seen.add(v);
      out.push(v);
    }
  }
  return out.slice(-cap);
}

export function buildAuditId(now: Date = new Date()): string {
  return now.toISOString();
}

export function newAuditRecord(opts: {
  audit_id: string;
  mode: AuditMode;
  agent_sdk: string;
  model: string | null;
  commit: string | null;
  branch: string | null;
  repository: string | null;
  phaseIds: string[];
  startedAt?: string;
  context?: AuditContext;
  triggeredVia?: string;
}): AuditRecord {
  const phases: Record<string, { status: PhaseStatus }> = {};
  for (const id of opts.phaseIds) phases[id] = { status: "pending" };
  return {
    audit_id: opts.audit_id,
    commit: opts.commit,
    branch: opts.branch,
    repository: opts.repository,
    mode: opts.mode,
    model: opts.model,
    agent_sdk: opts.agent_sdk,
    started_at: opts.startedAt ?? new Date().toISOString(),
    completed_at: null,
    status: "in_progress",
    phases,
    ...(opts.context !== undefined && hasContextContent(opts.context)
      ? { context: opts.context }
      : {}),
    ...(opts.triggeredVia !== undefined && opts.triggeredVia.length > 0
      ? { triggered_via: opts.triggeredVia }
      : {}),
  };
}

function hasContextContent(c: AuditContext): boolean {
  return (
    (typeof c.focus === "string" && c.focus.length > 0) ||
    (typeof c.expected_behaviors === "string" && c.expected_behaviors.length > 0)
  );
}
