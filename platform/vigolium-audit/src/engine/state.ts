import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import { z } from "zod";
import { atomicWrite, sha256OfFile, sweepStaleTempFiles } from "./util.js";
import type { AuditContext, AuditMode, AuditRecord, AuditState, PhaseStatus } from "./types.js";

/**
 * Agent-driven (interactive harness) runs write `audit-state.json` themselves and
 * occasionally drift from our canonical status vocabulary — most commonly
 * `"completed"` for a phase the schema calls `"complete"`. Coalesce the known
 * synonyms (and any casing) on read so a merge / resume / status over an
 * agent-written file doesn't hard-fail on a cosmetic mismatch. This mirrors the
 * existing tolerance in this schema (the `mode:"full"→"deep"` migration and the
 * `branch` / `completed_at` defaulting). Re-saving the parsed state then persists
 * the canonical form, self-healing the file. Unknown tokens fall through
 * unchanged and still fail the enum loudly, so genuinely corrupt files are caught.
 */
const STATUS_SYNONYMS: Record<string, string> = {
  completed: "complete",
  done: "complete",
  success: "complete",
  succeeded: "complete",
  passed: "complete",
  "in-progress": "in_progress",
  inprogress: "in_progress",
  running: "in_progress",
  started: "in_progress",
  failure: "failed",
  errored: "failed",
  error: "failed",
  skip: "skipped",
  skip_and_continue: "skipped",
  queued: "pending",
  not_started: "pending",
  "not-started": "pending",
  cancelled: "aborted",
  canceled: "aborted",
  abort: "aborted",
};

function normalizeStatus(value: unknown): unknown {
  if (typeof value !== "string") return value;
  const key = value.trim().toLowerCase();
  return STATUS_SYNONYMS[key] ?? key;
}

const PhaseRecordSchema = z.object({
  status: z.preprocess(normalizeStatus, z.enum(["pending", "in_progress", "complete", "failed", "skipped"])),
  started_at: z.string().optional(),
  completed_at: z.string().optional(),
  failed_at: z.string().optional(),
  error: z.string().optional(),
});

const AuditRecordSchema = z.object({
  audit_id: z.string(),
  commit: z.string().nullable().default(null),
  // Older Codex handoff dispatches wrote audit-state.json without branch.
  // Defaulting keeps the handoff poller live instead of silently dropping
  // all per-phase progress on schema mismatch.
  branch: z.string().nullable().default(null),
  repository: z.string().nullable().default(null),
  history_available: z.boolean().optional(),
  mode: z.string(),
  model: z.string().nullable(),
  agent_sdk: z.string(),
  started_at: z.string(),
  // In-progress audits legitimately have no completion timestamp yet; tolerate
  // missing values from agent-written state and normalize to null.
  completed_at: z.string().nullable().default(null),
  status: z.preprocess(normalizeStatus, z.enum(["in_progress", "complete", "failed", "aborted"])),
  phases: z.record(z.string(), PhaseRecordSchema).default({}),
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
}).passthrough();

/**
 * Schema version this build reads and writes. Bump when the on-disk shape
 * changes and add a migration step to `migrateAuditState`. A file tagged with
 * a *higher* version is rejected with a clear message rather than a cryptic
 * schema error (see `load`).
 */
export const CURRENT_AUDIT_SCHEMA_VERSION = 1;

const AuditStateSchema = z.object({
  schema_version: z.literal(1).default(1),
  audits: z.array(AuditRecordSchema),
}).passthrough();

/** Read `schema_version` without full validation, for the forward-compat guard. */
function peekSchemaVersion(json: unknown): number | null {
  if (json && typeof json === "object" && "schema_version" in json) {
    const v = (json as { schema_version?: unknown }).schema_version;
    if (typeof v === "number") return v;
  }
  return null;
}

/**
 * Bring a freshly-loaded AuditState up to the current schema, in place. This is
 * the single seam for on-disk migrations; add cases here as the schema evolves
 * rather than scattering normalization across readers.
 */
function migrateAuditState(data: AuditState): void {
  for (const audit of data.audits) {
    // Early Codex dispatch builds used `mode: "full"` for deep audits. The CLI
    // only accepts `deep`, so normalize on read to keep status/resume flows alive.
    if ((audit as { mode?: string }).mode === "full") {
      (audit as { mode: string }).mode = "deep";
    }
  }
}

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

  /** One-shot cleanup of staging files orphaned by a crash mid-write. */
  private sweepOnce: Promise<void> | null = null;

  constructor(private readonly resultsDir: string) {}

  /** Sweep orphaned `atomicWrite` staging files once, before the first write. */
  private sweep(): Promise<void> {
    if (!this.sweepOnce) this.sweepOnce = sweepStaleTempFiles(this.resultsDir);
    return this.sweepOnce;
  }

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
      await this.sweep();
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
    // Forward-compat: a file written by a newer build may carry a structure
    // this build can't safely interpret. Detect that explicitly so users get an
    // actionable "upgrade" message instead of a cryptic schema error.
    const version = peekSchemaVersion(json);
    if (version !== null && version > CURRENT_AUDIT_SCHEMA_VERSION) {
      throw new Error(
        `audit-state.json: schema_version ${version} is newer than this build supports (${CURRENT_AUDIT_SCHEMA_VERSION}); upgrade vigolium-audit`,
      );
    }
    const parsed = AuditStateSchema.safeParse(json);
    if (!parsed.success) {
      throw new Error(`audit-state.json: schema mismatch: ${parsed.error.message}`);
    }
    const data = parsed.data as AuditState;
    migrateAuditState(data);
    return data;
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

/**
 * Pick the latest audit for `mode` that didn't reach `complete` — the single
 * resume-resolution rule shared by the Orchestrator and the handoff drivers.
 * `in_progress` covers process-killed-mid-phase; `failed`/`aborted` cover
 * orderly terminal states (cost cap, strict failure, SIGINT). Each is
 * resumable: completed phases are skipped, pending re-runs, stale in_progress
 * phases get quarantined in phase prep. Returns null when nothing matches.
 */
export function findResumableAudit(audits: AuditRecord[], mode: AuditMode): AuditRecord | null {
  return (
    [...audits]
      .reverse()
      .find(
        (a) => a.mode === mode && (a.status === "in_progress" || a.status === "failed" || a.status === "aborted"),
      ) ?? null
  );
}

export function newAuditRecord(opts: {
  audit_id: string;
  mode: AuditMode;
  agent_sdk: string;
  model: string | null;
  commit: string | null;
  branch: string | null;
  repository: string | null;
  historyAvailable: boolean;
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
    history_available: opts.historyAvailable,
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
