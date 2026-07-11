import { existsSync, statSync, readdirSync, readFileSync, mkdirSync, copyFileSync, cpSync } from "fs";
import { resolve, join, basename, dirname, relative, extname } from "path";
import { StateStore } from "./state.js";
import { atomicWrite } from "./util.js";
import type { AuditRecord, AuditState } from "./types.js";

/**
 * The deterministic pre-merge step that the `merge` mode (command-defs/merge.md)
 * depends on. It physically consolidates two-or-more `vigolium-results/` output
 * folders into a single one and stamps a top-level `merge_metadata` object into
 * the destination's `audit-state.json` — which is how merge mode's M1 pre-flight
 * confirms the consolidation actually ran.
 *
 * This step is purely mechanical: it copies finding directories (collision-safe,
 * never overwriting) and concatenates audit records. The *semantic* work —
 * deduplicating findings by root cause, renumbering, regenerating reports — is
 * the LLM pass that `vigolium-audit run --mode merge` performs afterwards.
 */

/** Finding buckets, in the order they're walked. IDs share one namespace across both. */
const BUCKETS = ["findings", "findings-theoretical"] as const;
type Bucket = (typeof BUCKETS)[number];

/** `<Severity><N>-<slug>` directory name, e.g. `C1-sqli-login`. */
const FINDING_DIR_RE = /^([CHML])(\d+)-(.+)$/;

export interface PremergeIdRemap {
  /** Resolved source results dir the finding came from. */
  source: string;
  bucket: Bucket;
  /** Original directory name in the source. */
  from: string;
  /** New (collision-free) directory name in the destination. */
  to: string;
}

export interface PremergeAttackRemap {
  /** Resolved source results dir the file came from. */
  source: string;
  /** Path (relative to attack-surface/) in the source. */
  from: string;
  /** Path (relative to attack-surface/) it was written under in the destination. */
  to: string;
}

export interface PremergeSourceInfo {
  /** Resolved `vigolium-results/` dir. */
  dir: string;
  audit_ids: string[];
  /** Distinct `agent_sdk` values across this source's audits. */
  agents: string[];
  /** Distinct non-null `model` values across this source's audits. */
  models: string[];
}

export interface PremergeResult {
  /** Destination `vigolium-results/` dir (== first source when in-place). */
  destResultsDir: string;
  /** `dirname(destResultsDir)` — the path to pass to `run --mode merge --target`. */
  destProjectDir: string;
  /** True when the destination is the first input's folder (mutated in place). */
  destinationInPlace: boolean;
  /** Resolved results dirs of every input, in order. */
  sources: string[];
  sourceInfo: PremergeSourceInfo[];
  /** Number of finding directories copied *into* the destination. */
  findingsCopied: number;
  idRemap: PremergeIdRemap[];
  /** Every source that contributed at least one `attack-surface/` file. */
  attackSurfaceSources: string[];
  /** Count of attack-surface files copied *into* the destination. */
  attackSurfaceCopied: number;
  /** Same-named attack-surface files whose contents differed, kept under a labelled name. */
  attackSurfaceRenamed: PremergeAttackRemap[];
  /** Path to the backed-up `audit-state.json.pre-merge.bak` (in-place only). */
  backup: string | null;
  /** Human-readable notes about artifacts that were not carried over. */
  skipped: string[];
}

export interface PremergeOptions {
  /** Raw `--dir` inputs (project dir or `vigolium-results/` dir); at least two. */
  inputs: string[];
  /**
   * Non-destructive destination. When set, the merged result is written to
   * `<output>/vigolium-results/` and no source is mutated. When omitted, the
   * first input's results dir is the destination (consolidated in place).
   */
  output?: string;
  /** Allow writing into a non-empty `--output` destination that isn't a source. */
  force?: boolean;
}

/**
 * Resolve a user-supplied path to its `vigolium-results/` dir, accepting either
 * the project dir or the results dir directly (mirrors `cli/strip.ts`).
 */
function resolveResultsDir(inputPath: string): string {
  const resolved = resolve(inputPath);
  if (!existsSync(resolved)) throw new Error(`merge input does not exist: ${resolved}`);
  if (!statSync(resolved).isDirectory()) throw new Error(`merge input is not a directory: ${resolved}`);
  const looksLikeResultsDir =
    basename(resolved) === "vigolium-results" || existsSync(join(resolved, "audit-state.json"));
  const resultsDir = looksLikeResultsDir ? resolved : join(resolved, "vigolium-results");
  if (!existsSync(resultsDir)) {
    throw new Error(`no vigolium-results/ directory found at ${resultsDir} (input: ${inputPath})`);
  }
  if (!existsSync(join(resultsDir, "audit-state.json"))) {
    throw new Error(`${resultsDir} has no audit-state.json — not an audit output directory`);
  }
  return resultsDir;
}

/**
 * Tracks which finding *IDs* (`<Severity><N>`, e.g. `C1`) and full dir names are
 * taken across the destination's buckets. The ID — not the slug — is the
 * collision key, because merge.md cross-references findings by `<Severity><N>`
 * and IDs share one namespace across `findings/` + `findings-theoretical/`. So
 * `C1-foo` and `C1-bar` collide even though their slugs differ.
 */
class IdSpace {
  private readonly usedIds = new Set<string>();
  private readonly usedNames = new Set<string>();
  private readonly maxN = new Map<string, number>();

  /** Seed from an existing results dir's finding buckets (both share one namespace). */
  seedFrom(resultsDir: string): void {
    for (const bucket of BUCKETS) {
      for (const name of listFindingDirs(join(resultsDir, bucket))) this.observe(name);
    }
  }

  private observe(name: string): void {
    this.usedNames.add(name);
    const m = FINDING_DIR_RE.exec(name);
    if (!m) return;
    const sev = m[1]!;
    const n = Number(m[2]);
    this.usedIds.add(`${sev}${n}`);
    this.maxN.set(sev, Math.max(this.maxN.get(sev) ?? 0, n));
  }

  /**
   * Resolve `name` to a collision-free dir name in this space, reserving it.
   * Conformant names whose ID is taken are bumped to the next free N for their
   * severity (slug preserved); non-conformant names that collide get a `-src<i>`
   * discriminator.
   */
  place(name: string, sourceIndex: number): string {
    const m = FINDING_DIR_RE.exec(name);
    if (m) {
      const sev = m[1]!;
      const slug = m[3]!;
      if (!this.usedIds.has(`${sev}${Number(m[2])}`)) {
        this.observe(name);
        return name;
      }
      let n = (this.maxN.get(sev) ?? 0) + 1;
      let candidate = `${sev}${n}-${slug}`;
      while (this.usedIds.has(`${sev}${n}`) || this.usedNames.has(candidate)) {
        n += 1;
        candidate = `${sev}${n}-${slug}`;
      }
      this.observe(candidate);
      return candidate;
    }
    if (!this.usedNames.has(name)) {
      this.observe(name);
      return name;
    }
    let candidate = `${name}-src${sourceIndex}`;
    let dup = 2;
    while (this.usedNames.has(candidate)) candidate = `${name}-src${sourceIndex}-${dup++}`;
    this.observe(candidate);
    return candidate;
  }
}

/** Directory entries of `dir`, or `[]` if it's missing. Sorted for deterministic order. */
function listFindingDirs(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

/** Files under `dir` as paths relative to it, recursive, sorted (deterministic). */
function listFilesRecursive(dir: string, base: string = dir): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const full = join(dir, e.name);
    if (e.isDirectory()) out.push(...listFilesRecursive(full, base));
    else if (e.isFile()) out.push(relative(base, full));
  }
  return out;
}

/** Byte-for-byte file equality, used to dedupe identical recon across sources. */
function sameBytes(a: string, b: string): boolean {
  try {
    // Cheap early-out before reading both files: differing sizes can't be equal,
    // which avoids slurping two large recon files (KB report, SAST summary) just
    // to find they differ — the common case for same-named-but-distinct recon.
    if (statSync(a).size !== statSync(b).size) return false;
    return readFileSync(a).equals(readFileSync(b));
  } catch {
    return false;
  }
}

/**
 * Short, human-readable label for a source, used to disambiguate same-named
 * attack-surface files whose contents differ. Prefers the project-dir name
 * (e.g. `next.js-run-b`), falls back to the results-dir name, then `srcN`.
 */
function sourceLabel(resultsDir: string, index: number): string {
  const name = basename(resultsDir) === "vigolium-results" ? basename(dirname(resultsDir)) : basename(resultsDir);
  return name && name !== "." && name !== "/" ? name : `src${index}`;
}

async function loadSourceState(resultsDir: string): Promise<AuditState> {
  try {
    return await new StateStore(resultsDir).load();
  } catch (err) {
    throw new Error(`failed to read ${join(resultsDir, "audit-state.json")}: ${(err as Error).message}`);
  }
}

function summarizeSource(dir: string, state: AuditState): PremergeSourceInfo {
  const audit_ids = state.audits.map((a) => a.audit_id);
  const agents = [...new Set(state.audits.map((a) => a.agent_sdk).filter(Boolean))];
  const models = [...new Set(state.audits.map((a) => a.model).filter((m): m is string => !!m))];
  return { dir, audit_ids, agents, models };
}

/**
 * Concatenate every source's audit records into one array, disambiguating any
 * duplicate `audit_id` (ISO timestamps can collide across independent runs) by
 * suffixing later occurrences with `#<n>`.
 */
function mergeAuditRecords(states: AuditState[]): AuditRecord[] {
  const out: AuditRecord[] = [];
  const seen = new Set<string>();
  for (const state of states) {
    for (const audit of state.audits) {
      let id = audit.audit_id;
      if (seen.has(id)) {
        let n = 2;
        while (seen.has(`${audit.audit_id}#${n}`)) n += 1;
        id = `${audit.audit_id}#${n}`;
      }
      seen.add(id);
      out.push(id === audit.audit_id ? audit : { ...audit, audit_id: id });
    }
  }
  return out;
}

export async function premergeResults(opts: PremergeOptions): Promise<PremergeResult> {
  if (opts.inputs.length < 2) {
    throw new Error(`merge needs at least two --dir inputs (got ${opts.inputs.length})`);
  }

  // Resolve every input to a results dir and reject duplicates pointing at the
  // same folder (would otherwise self-merge and double-count).
  const sources = opts.inputs.map(resolveResultsDir);
  const dupe = sources.find((s, i) => sources.indexOf(s) !== i);
  if (dupe) throw new Error(`the same results dir was passed twice: ${dupe}`);

  // Pick the destination.
  let destResultsDir: string;
  let destinationInPlace: boolean;
  if (opts.output !== undefined) {
    destResultsDir = join(resolve(opts.output), "vigolium-results");
    destinationInPlace = false;
    if (sources.includes(destResultsDir)) {
      throw new Error(`--output (${destResultsDir}) is also a --dir input; choose a different output`);
    }
    if (existsSync(destResultsDir) && readdirSync(destResultsDir).length > 0 && !opts.force) {
      throw new Error(`--output ${destResultsDir} is not empty; pass --force to merge into it`);
    }
    mkdirSync(destResultsDir, { recursive: true });
  } else {
    destResultsDir = sources[0]!;
    destinationInPlace = true;
  }

  // Sources whose findings get copied *into* the destination. In-place: the
  // first source already lives at the destination, so only copy the rest.
  const copyInSources = destinationInPlace ? sources.slice(1) : sources;

  // Load all source states up front (the first source's state is still intact;
  // the backup below is a copy, the original isn't touched until the final write).
  const states = await Promise.all(sources.map(loadSourceState));
  const sourceInfo = sources.map((dir, i) => summarizeSource(dir, states[i]!));

  // Back up the destination's existing state before we overwrite it in place.
  let backup: string | null = null;
  if (destinationInPlace) {
    backup = join(destResultsDir, "audit-state.json.pre-merge.bak");
    copyFileSync(join(destResultsDir, "audit-state.json"), backup);
  }

  // Seed the ID space from whatever already lives at the destination.
  const idSpace = new IdSpace();
  if (destinationInPlace) idSpace.seedFrom(destResultsDir);

  const idRemap: PremergeIdRemap[] = [];
  const skipped: string[] = [];
  let findingsCopied = 0;

  // attack-surface/ is *unified* across sources, not first-wins: every source's
  // recon is carried over so nothing is lost. In-place, source[0]'s files already
  // live at the destination — record it as a contributor up front.
  const attackSurfaceDest = join(destResultsDir, "attack-surface");
  const attackSurfaceSources: string[] = [];
  const attackSurfaceRenamed: PremergeAttackRemap[] = [];
  let attackSurfaceCopied = 0;
  if (destinationInPlace && existsSync(attackSurfaceDest)) attackSurfaceSources.push(destResultsDir);

  for (let i = 0; i < copyInSources.length; i++) {
    const src = copyInSources[i]!;
    // sourceIndex is the index in the original `sources` list (stable labels).
    const sourceIndex = sources.indexOf(src);
    for (const bucket of BUCKETS) {
      const srcBucket = join(src, bucket);
      const names = listFindingDirs(srcBucket);
      if (names.length === 0) continue;
      mkdirSync(join(destResultsDir, bucket), { recursive: true });
      for (const name of names) {
        const placed = idSpace.place(name, sourceIndex);
        cpSync(join(srcBucket, name), join(destResultsDir, bucket, placed), { recursive: true });
        findingsCopied += 1;
        if (placed !== name) idRemap.push({ source: src, bucket, from: name, to: placed });
      }
    }

    // Unify this source's attack-surface/ into the destination (collision-safe
    // union): identical files dedupe silently; same-named files whose contents
    // differ are kept under a source-labelled name so no recon is lost. The
    // semantic consolidation of overlapping recon is the LLM merge-mode pass.
    const srcAttack = join(src, "attack-surface");
    const attackFiles = listFilesRecursive(srcAttack);
    if (attackFiles.length > 0) {
      const label = sourceLabel(src, sourceIndex);
      let contributed = false;
      for (const rel of attackFiles) {
        const from = join(srcAttack, rel);
        const target = join(attackSurfaceDest, rel);
        if (existsSync(target)) {
          if (sameBytes(from, target)) continue; // identical recon — dedupe
          const ext = extname(rel);
          const stem = rel.slice(0, rel.length - ext.length);
          let to = `${stem}.${label}${ext}`;
          let n = 2;
          while (existsSync(join(attackSurfaceDest, to))) to = `${stem}.${label}-${n++}${ext}`;
          mkdirSync(dirname(join(attackSurfaceDest, to)), { recursive: true });
          copyFileSync(from, join(attackSurfaceDest, to));
          attackSurfaceRenamed.push({ source: src, from: rel, to });
        } else {
          mkdirSync(dirname(target), { recursive: true });
          copyFileSync(from, target);
        }
        attackSurfaceCopied += 1;
        contributed = true;
      }
      if (contributed && !attackSurfaceSources.includes(src)) attackSurfaceSources.push(src);
    }

    // Reports / quarantine / drafts are rebuilt or re-derived by merge mode.
    for (const leftover of ["quarantine", "findings-draft"]) {
      if (existsSync(join(src, leftover))) {
        skipped.push(`${join(src, leftover)} (not carried; merge mode rebuilds it)`);
      }
    }
  }

  // Write the merged state with the merge_metadata contract merge mode reads.
  const mergedState: AuditState & { merge_metadata: unknown } = {
    schema_version: 1,
    audits: mergeAuditRecords(states),
    merge_metadata: {
      generated_by: "vigolium-audit premerge",
      generated_at: new Date().toISOString(),
      sources,
      source_audits: sourceInfo,
      premerge_id_remap: idRemap,
      attack_surface_sources: attackSurfaceSources,
      attack_surface_renamed: attackSurfaceRenamed,
      destination_in_place: destinationInPlace,
    },
  };
  await atomicWrite(join(destResultsDir, "audit-state.json"), JSON.stringify(mergedState, null, 2) + "\n");

  return {
    destResultsDir,
    destProjectDir: dirname(destResultsDir),
    destinationInPlace,
    sources,
    sourceInfo,
    findingsCopied,
    idRemap,
    attackSurfaceSources,
    attackSurfaceCopied,
    attackSurfaceRenamed,
    backup,
    skipped,
  };
}
