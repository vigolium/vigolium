import { lstat, readFile, readdir, realpath } from "fs/promises";
import { resolve, sep } from "path";
import type { ArtifactRule, PhaseCompletionContract, PhaseDef } from "./types.js";

export interface ArtifactGateFailure {
  rule: ArtifactRule;
  message: string;
}

export interface ArtifactGateResult {
  ok: boolean;
  failures: ArtifactGateFailure[];
}

export interface ArtifactGateOptions {
  /** Require gated files to have been written during the active audit. */
  notBeforeMs?: number;
  /** Filesystem timestamp tolerance. Defaults to two seconds. */
  freshnessToleranceMs?: number;
}

/** Evaluate every declared completion artifact for a phase. */
export async function evaluatePhaseArtifacts(
  phase: PhaseDef,
  resultsDir: string,
  options: ArtifactGateOptions = {},
): Promise<ArtifactGateResult> {
  if (!phase.completion) return { ok: true, failures: [] };
  return evaluateCompletionContract(phase.completion, resultsDir, options);
}

export async function evaluateCompletionContract(
  contract: PhaseCompletionContract,
  resultsDir: string,
  options: ArtifactGateOptions = {},
): Promise<ArtifactGateResult> {
  const failures: ArtifactGateFailure[] = [];
  for (const rule of contract.artifacts) {
    const result = await evaluateRule(rule, resultsDir, options);
    if (!result.ok) failures.push(...result.failures);
  }
  return { ok: failures.length === 0, failures };
}

async function evaluateRule(
  rule: ArtifactRule,
  resultsDir: string,
  options: ArtifactGateOptions,
): Promise<ArtifactGateResult> {
  if (rule.kind === "file") return evaluateFileRule(rule, resultsDir, options);
  if (rule.kind === "glob") return evaluateGlobRule(rule, resultsDir, options);
  if (rule.kind === "finding_reports") return evaluateFindingReportsRule(rule, resultsDir, options);

  const nestedFailures: ArtifactGateFailure[] = [];
  for (const nested of rule.rules) {
    const result = await evaluateRule(nested, resultsDir, options);
    if (result.ok) return { ok: true, failures: [] };
    nestedFailures.push(...result.failures);
  }
  const reasons = nestedFailures.map((failure) => failure.message).join("; ");
  return {
    ok: false,
    failures: [{ rule, message: `none of the alternatives passed${reasons ? `: ${reasons}` : ""}` }],
  };
}

async function evaluateFileRule(
  rule: Extract<ArtifactRule, { kind: "file" }>,
  resultsDir: string,
  options: ArtifactGateOptions,
): Promise<ArtifactGateResult> {
  const path = resolveArtifactPath(resultsDir, rule.path);
  if (path === null) return failure(rule, `${rule.path}: path escapes the results directory`);

  let stat: Awaited<ReturnType<typeof lstat>>;
  try {
    stat = await lstat(path);
  } catch {
    return failure(rule, `${displayPath(rule.path)} is missing`);
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    return failure(rule, `${displayPath(rule.path)} is not a regular file`);
  }
  if (!(await isResolvedInside(resultsDir, path))) {
    return failure(rule, `${displayPath(rule.path)} resolves outside the results directory`);
  }
  if (!isFreshEnough(stat.mtimeMs, options)) {
    return failure(rule, `${displayPath(rule.path)} predates the active audit`);
  }
  if (stat.size < rule.min_bytes) {
    return failure(
      rule,
      `${displayPath(rule.path)} is ${stat.size} bytes; requires at least ${rule.min_bytes}`,
    );
  }

  if (rule.contains.length === 0 && !rule.json) return { ok: true, failures: [] };

  let contents: string;
  try {
    contents = await readFile(path, "utf8");
  } catch {
    return failure(rule, `${displayPath(rule.path)} could not be read as UTF-8 text`);
  }
  const missing = rule.contains.filter((literal) => !contents.includes(literal));
  if (missing.length > 0) {
    return failure(
      rule,
      `${displayPath(rule.path)} is missing required text: ${missing.map((v) => JSON.stringify(v)).join(", ")}`,
    );
  }
  if (rule.json) {
    try {
      JSON.parse(contents);
    } catch (err) {
      return failure(rule, `${displayPath(rule.path)} is invalid JSON: ${(err as Error).message}`);
    }
  }
  return { ok: true, failures: [] };
}

async function evaluateGlobRule(
  rule: Extract<ArtifactRule, { kind: "glob" }>,
  resultsDir: string,
  options: ArtifactGateOptions,
): Promise<ArtifactGateResult> {
  if (resolveArtifactPath(resultsDir, rule.pattern) === null) {
    return failure(rule, `${rule.pattern}: pattern escapes the results directory`);
  }

  const matches: string[] = [];
  const undersized: string[] = [];
  const unreadable: string[] = [];
  const missingContent: string[] = [];
  const selectContains = rule.select_contains ?? [];
  const eachContains = rule.each_contains ?? [];
  const glob = new Bun.Glob(rule.pattern);
  for await (const match of glob.scan({ cwd: resultsDir, dot: true, onlyFiles: true, followSymlinks: false })) {
    const path = resolveArtifactPath(resultsDir, match);
    if (path === null) continue;
    try {
      const stat = await lstat(path);
      if (stat.isSymbolicLink() || !stat.isFile()) continue;
      if (!(await isResolvedInside(resultsDir, path))) continue;
      if (!isFreshEnough(stat.mtimeMs, options)) continue;
      let contents: string | null = null;
      if (selectContains.length > 0 || eachContains.length > 0) {
        try {
          contents = await readFile(path, "utf8");
        } catch {
          unreadable.push(match);
          continue;
        }
      }
      if (contents !== null && selectContains.some((literal) => !contents.includes(literal))) {
        continue;
      }
      matches.push(match);
      if (stat.size < rule.each_min_bytes) undersized.push(match);
      if (contents !== null) {
        const missing = eachContains.filter((literal) => !contents!.includes(literal));
        if (missing.length > 0) {
          missingContent.push(
            `${displayPath(match)} missing ${missing.map((literal) => JSON.stringify(literal)).join(", ")}`,
          );
        }
      }
    } catch {
      /* File disappeared between glob and stat; treat it as absent. */
    }
  }
  if (matches.length < rule.min_matches) {
    return failure(
      rule,
      `${displayPath(rule.pattern)} matched ${matches.length} files; requires at least ${rule.min_matches}`,
    );
  }
  if (undersized.length > 0) {
    return failure(
      rule,
      `${undersized.map(displayPath).join(", ")} below the ${rule.each_min_bytes}-byte minimum`,
    );
  }
  if (unreadable.length > 0) {
    return failure(rule, `${unreadable.map(displayPath).join(", ")} could not be read as UTF-8 text`);
  }
  if (missingContent.length > 0) {
    return failure(rule, `matched files failed content requirements: ${missingContent.join("; ")}`);
  }
  return { ok: true, failures: [] };
}

async function evaluateFindingReportsRule(
  rule: Extract<ArtifactRule, { kind: "finding_reports" }>,
  resultsDir: string,
  options: ArtifactGateOptions,
): Promise<ArtifactGateResult> {
  const findingDirs: string[] = [];
  for (const root of rule.roots) {
    const rootPath = resolveArtifactPath(resultsDir, root);
    if (rootPath === null) return failure(rule, `${root}: path escapes the results directory`);
    try {
      const rootStat = await lstat(rootPath);
      if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
        return failure(rule, `${displayPath(root)} is not a regular directory`);
      }
      if (!(await isResolvedInside(resultsDir, rootPath))) {
        return failure(rule, `${displayPath(root)} resolves outside the results directory`);
      }
      const entries = await readdir(rootPath, { withFileTypes: true });
      for (const entry of entries) {
        if (
          entry.isDirectory() &&
          !entry.isSymbolicLink() &&
          isSafeFindingDirectoryName(entry.name)
        ) {
          findingDirs.push(`${root}/${entry.name}`);
        }
      }
    } catch {
      continue;
    }
  }

  const expectedIds = new Set<string>();
  if (rule.manifest_path) {
    const manifestPath = resolveArtifactPath(resultsDir, rule.manifest_path);
    if (manifestPath === null) {
      return failure(rule, `${rule.manifest_path}: path escapes the results directory`);
    }
    let manifest: unknown;
    try {
      const stat = await lstat(manifestPath);
      if (stat.isSymbolicLink() || !stat.isFile() || !(await isResolvedInside(resultsDir, manifestPath))) {
        return failure(rule, `${displayPath(rule.manifest_path)} is not a safe regular file`);
      }
      if (!isFreshEnough(stat.mtimeMs, options)) {
        return failure(rule, `${displayPath(rule.manifest_path)} predates the active audit`);
      }
      manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    } catch (err) {
      return failure(
        rule,
        `${displayPath(rule.manifest_path)} is missing or invalid JSON: ${(err as Error).message}`,
      );
    }
    if (!isRecord(manifest)) {
      return failure(rule, `${displayPath(rule.manifest_path)} must contain a JSON object`);
    }
    for (const listName of rule.manifest_lists) {
      const list = manifest[listName];
      if (!Array.isArray(list)) {
        return failure(rule, `${displayPath(rule.manifest_path)}.${listName} must be an array`);
      }
      for (const entry of list) {
        if (!isRecord(entry) || typeof entry.id !== "string" || !isSafeFindingId(entry.id)) {
          return failure(
            rule,
            `${displayPath(rule.manifest_path)}.${listName} contains an entry without a safe string id`,
          );
        }
        expectedIds.add(entry.id);
      }
    }
  }

  if (findingDirs.length === 0 && expectedIds.size === 0) {
    return rule.allow_empty
      ? { ok: true, failures: [] }
      : failure(rule, `no finding directories exist under ${rule.roots.map(displayPath).join(", ")}`);
  }

  const incomplete: string[] = [];
  for (const id of expectedIds) {
    const found = findingDirs.some((dir) => {
      const name = dir.slice(dir.lastIndexOf("/") + 1);
      return name === id || name.startsWith(`${id}-`);
    });
    if (!found) incomplete.push(`manifest finding ${id} (directory missing)`);
  }
  for (const dir of findingDirs) {
    const report = `${dir}/${rule.filename}`;
    const path = resolveArtifactPath(resultsDir, report);
    if (path === null) {
      incomplete.push(`${displayPath(report)} (invalid path)`);
      continue;
    }
    try {
      const stat = await lstat(path);
      if (
        stat.isSymbolicLink() ||
        !stat.isFile() ||
        !(await isResolvedInside(resultsDir, path)) ||
        !isFreshEnough(stat.mtimeMs, options) ||
        stat.size < rule.min_bytes
      ) {
        incomplete.push(`${displayPath(report)} (missing, non-regular, or below ${rule.min_bytes} bytes)`);
      }
    } catch {
      incomplete.push(`${displayPath(report)} (missing)`);
    }
  }
  return incomplete.length === 0
    ? { ok: true, failures: [] }
    : failure(rule, `incomplete finding reports: ${incomplete.join(", ")}`);
}

function failure(rule: ArtifactRule, message: string): ArtifactGateResult {
  return { ok: false, failures: [{ rule, message }] };
}

function resolveArtifactPath(resultsDir: string, relativePath: string): string | null {
  const root = resolve(resultsDir);
  const candidate = resolve(root, relativePath);
  if (candidate === root || candidate.startsWith(`${root}${sep}`)) return candidate;
  return null;
}

async function isResolvedInside(resultsDir: string, candidate: string): Promise<boolean> {
  try {
    const root = await realpath(resultsDir);
    const resolvedCandidate = await realpath(candidate);
    return resolvedCandidate === root || resolvedCandidate.startsWith(`${root}${sep}`);
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeFindingId(value: string): boolean {
  return /^[CHML][1-9][0-9]*$/.test(value);
}

function isSafeFindingDirectoryName(value: string): boolean {
  return /^[CHML][1-9][0-9]*(?:-.+)?$/u.test(value);
}

function isFreshEnough(mtimeMs: number, options: ArtifactGateOptions): boolean {
  if (options.notBeforeMs === undefined || !Number.isFinite(options.notBeforeMs)) return true;
  const tolerance = options.freshnessToleranceMs ?? 2_000;
  return mtimeMs >= options.notBeforeMs - tolerance;
}

function displayPath(path: string): string {
  return `vigolium-results/${path}`;
}

export function describeArtifactRule(rule: ArtifactRule): string {
  if (rule.kind === "file") {
    const details = [
      `regular file ${displayPath(rule.path)}`,
      `at least ${rule.min_bytes} bytes`,
      ...(rule.contains.length > 0
        ? [`containing ${rule.contains.map((v) => JSON.stringify(v)).join(", ")}`]
        : []),
      ...(rule.json ? ["valid JSON"] : []),
    ];
    return details.join(", ");
  }
  if (rule.kind === "glob") {
    const selected = (rule.select_contains?.length ?? 0) > 0
      ? ` selected by ${rule.select_contains!.map((value) => JSON.stringify(value)).join(",")}`
      : "";
    const required = (rule.each_contains?.length ?? 0) > 0
      ? `, each containing ${rule.each_contains!.map((value) => JSON.stringify(value)).join(",")}`
      : "";
    return `${displayPath(rule.pattern)}: at least ${rule.min_matches} matching file(s)${selected}, each at least ${rule.each_min_bytes} bytes${required}`;
  }
  if (rule.kind === "finding_reports") {
    const manifest = rule.manifest_path
      ? `, covering every ID in ${displayPath(rule.manifest_path)}`
      : "";
    return `${rule.filename} in every finding directory under ${rule.roots.map(displayPath).join(", ")}, at least ${rule.min_bytes} bytes each${manifest}`;
  }
  return `one of: ${rule.rules.map(describeArtifactRule).join(" OR ")}`;
}

export function formatArtifactFailures(result: ArtifactGateResult): string[] {
  return result.failures.map((failure) => failure.message);
}
