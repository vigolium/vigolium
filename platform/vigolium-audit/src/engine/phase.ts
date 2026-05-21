import { parse as parseYaml } from "yaml";
import { z } from "zod";
import type { CommandDef, PhaseDef } from "./types.js";

const PhaseSchema = z.object({
  id: z.union([z.string(), z.number()]).transform((v) => String(v)),
  title: z.string(),
  agent: z.string().nullable(),
  requires_git: z.boolean().default(false),
  parallel_with: z.array(z.union([z.string(), z.number()]).transform((v) => String(v))).default([]),
  depends_on: z.array(z.union([z.string(), z.number()]).transform((v) => String(v))).default([]),
});

const FrontmatterSchema = z.object({
  description: z.string(),
  mode: z.string(),
  phases: z.array(PhaseSchema).default([]),
  "allowed-tools": z.string().optional(),
});

export class CommandDefParseError extends Error {
  constructor(message: string, public readonly path: string) {
    super(`${path}: ${message}`);
    this.name = "CommandDefParseError";
  }
}

const FRONTMATTER_RE = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

export function parseCommandDef(source: string, sourcePath: string): CommandDef {
  const match = source.match(FRONTMATTER_RE);
  if (!match) {
    throw new CommandDefParseError("missing YAML frontmatter block", sourcePath);
  }
  const [, fmRaw, body] = match;

  let fmRaw_obj: unknown;
  try {
    fmRaw_obj = parseYaml(fmRaw!);
  } catch (err) {
    throw new CommandDefParseError(`invalid YAML frontmatter: ${(err as Error).message}`, sourcePath);
  }

  const parsed = FrontmatterSchema.safeParse(fmRaw_obj);
  if (!parsed.success) {
    throw new CommandDefParseError(
      `frontmatter schema mismatch: ${parsed.error.issues.map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`).join("; ")}`,
      sourcePath,
    );
  }

  validatePhaseGraph(parsed.data.phases, sourcePath);

  return {
    mode: parsed.data.mode as CommandDef["mode"],
    description: parsed.data.description,
    phases: parsed.data.phases as PhaseDef[],
    ...(parsed.data["allowed-tools"] !== undefined && { allowed_tools_raw: parsed.data["allowed-tools"] }),
    body: body ?? "",
    source_path: sourcePath,
  };
}

function validatePhaseGraph(phases: { id: string; depends_on: string[]; parallel_with: string[] }[], sourcePath: string): void {
  const ids = new Set(phases.map((p) => p.id));
  if (ids.size !== phases.length) {
    throw new CommandDefParseError("duplicate phase ids in `phases:`", sourcePath);
  }
  for (const p of phases) {
    for (const dep of p.depends_on) {
      if (!ids.has(dep)) {
        throw new CommandDefParseError(`phase ${p.id} depends_on unknown phase ${dep}`, sourcePath);
      }
    }
    for (const sib of p.parallel_with) {
      if (!ids.has(sib)) {
        throw new CommandDefParseError(`phase ${p.id} parallel_with unknown phase ${sib}`, sourcePath);
      }
    }
  }
  detectCycles(phases, sourcePath);
}

function detectCycles(phases: { id: string; depends_on: string[] }[], sourcePath: string): void {
  const adj = new Map<string, string[]>();
  for (const p of phases) adj.set(p.id, p.depends_on);
  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Map<string, number>();
  for (const p of phases) color.set(p.id, WHITE);
  const visit = (id: string): void => {
    color.set(id, GRAY);
    for (const dep of adj.get(id) ?? []) {
      const c = color.get(dep) ?? WHITE;
      if (c === GRAY) {
        throw new CommandDefParseError(`phase dependency cycle involving ${id} → ${dep}`, sourcePath);
      }
      if (c === WHITE) visit(dep);
    }
    color.set(id, BLACK);
  };
  for (const p of phases) {
    if (color.get(p.id) === WHITE) visit(p.id);
  }
}

/**
 * Topological order honoring depends_on. Stable: ties resolved by source order.
 * v1 engine walks this list sequentially; future parallelism would batch siblings.
 */
export function topologicalOrder(phases: PhaseDef[]): PhaseDef[] {
  const remaining = new Map<string, PhaseDef>();
  const remainingDeps = new Map<string, Set<string>>();
  for (const p of phases) {
    remaining.set(p.id, p);
    remainingDeps.set(p.id, new Set(p.depends_on));
  }
  const ordered: PhaseDef[] = [];
  while (remaining.size > 0) {
    const next = phases.find((p) => remaining.has(p.id) && remainingDeps.get(p.id)!.size === 0);
    if (!next) {
      throw new Error(`unresolvable phase order: remaining=${[...remaining.keys()].join(",")}`);
    }
    ordered.push(next);
    remaining.delete(next.id);
    for (const deps of remainingDeps.values()) deps.delete(next.id);
  }
  return ordered;
}

/**
 * Group phases into batches that can run concurrently.
 *
 * A batch is a set of phases whose `depends_on` is fully satisfied by earlier
 * batches AND that are mutually declared in each other's `parallel_with` list.
 * Mutual is conservative — a one-sided declaration is ignored. This keeps the
 * default behavior identical to serial when nobody explicitly opted in.
 *
 * The returned batches preserve source order within each batch; flatten them
 * and you get the same result as topologicalOrder.
 */
export function scheduleBatches(phases: PhaseDef[]): PhaseDef[][] {
  const byId = new Map(phases.map((p) => [p.id, p]));
  const remaining = new Map<string, PhaseDef>();
  const remainingDeps = new Map<string, Set<string>>();
  for (const p of phases) {
    remaining.set(p.id, p);
    remainingDeps.set(p.id, new Set(p.depends_on));
  }
  const batches: PhaseDef[][] = [];

  while (remaining.size > 0) {
    // Eligible: deps fully satisfied (by previously-batched phases).
    const eligible = phases.filter((p) => remaining.has(p.id) && remainingDeps.get(p.id)!.size === 0);
    if (eligible.length === 0) {
      throw new Error(`unresolvable phase order: remaining=${[...remaining.keys()].join(",")}`);
    }

    // Seed the batch with the first eligible phase (source order), then add
    // any other eligible phase that's mutually parallel with EVERY phase
    // already in the batch.
    const batch: PhaseDef[] = [];
    for (const p of eligible) {
      if (batch.length === 0) {
        batch.push(p);
        continue;
      }
      const compatible = batch.every((q) => {
        const pwq = new Set(byId.get(p.id)!.parallel_with);
        const qwp = new Set(byId.get(q.id)!.parallel_with);
        return pwq.has(q.id) && qwp.has(p.id);
      });
      if (compatible) batch.push(p);
    }

    batches.push(batch);
    for (const p of batch) remaining.delete(p.id);
    for (const deps of remainingDeps.values()) {
      for (const p of batch) deps.delete(p.id);
    }
  }
  return batches;
}
