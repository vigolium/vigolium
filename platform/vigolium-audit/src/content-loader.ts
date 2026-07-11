import { createHash } from "crypto";
import { existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "fs";
import { readFile, stat } from "fs/promises";
import { homedir } from "os";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { parse as parseYaml } from "yaml";
import type { AgentDef, CommandDef } from "./engine/types.js";
import { parseCommandDef } from "./engine/phase.js";

/**
 * Resolves and loads vendored content (agent-defs, command-defs, skills,
 * harnesses). Honors local overrides at ~/.config/vigolium-audit/{agents,skills,commands}/.
 *
 * Two run modes:
 *   - Dev (`bun run`): reads from src/content/ next to this module.
 *   - Compiled (`bun build --compile`): reads from a cache dir populated at
 *     first run from an embedded tarball. The embedded-tarball extraction is
 *     wired up by the build pipeline (task #10); this loader just resolves to
 *     wherever the rootDir() resolver points.
 */
export type ContentVariant = "default" | "sdk";

export interface ContentLoader {
  rootDir(): string;
  overrideRoot(): string;
  listAgents(): Promise<string[]>;
  listCommands(): Promise<string[]>;
  listSkills(): Promise<string[]>;
  loadAgent(name: string, opts?: { variant?: ContentVariant }): Promise<AgentDef>;
  loadCommand(mode: string, opts?: { variant?: ContentVariant }): Promise<CommandDef>;
  /** Returns the absolute directory that contains SKILL.md for the named skill. */
  resolveSkillDir(name: string): Promise<string>;
  /** Returns the harness frontmatter.yaml as parsed YAML for the named platform. */
  loadHarness(platform: string): Promise<unknown>;
}

interface ResolvedRoots {
  /** Vendored / extracted content directory. */
  contentRoot: string;
  /** Per-user override directory. */
  overrideRoot: string;
}

const FRONTMATTER_RE = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

/**
 * Split a markdown source into its YAML frontmatter (parsed to an object) and
 * the body after the closing `---`. Non-object / absent frontmatter yields an
 * empty object and the whole source as the body. Shared by every content kind
 * (agent-defs here, bridge task presets) so the frontmatter contract stays in
 * one place.
 */
export function parseFrontmatter(src: string): { data: Record<string, unknown>; body: string } {
  const match = src.match(FRONTMATTER_RE);
  if (!match) return { data: {}, body: src };
  const parsed = parseYaml(match[1]!);
  const data = parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  return { data, body: match[2] ?? "" };
}

class FilesystemContentLoader implements ContentLoader {
  constructor(private readonly roots: ResolvedRoots) {}

  rootDir(): string {
    return this.roots.contentRoot;
  }
  overrideRoot(): string {
    return this.roots.overrideRoot;
  }

  async listAgents(): Promise<string[]> {
    return this.listMarkdown(join(this.roots.contentRoot, "agent-defs"));
  }
  async listCommands(): Promise<string[]> {
    return this.listMarkdown(join(this.roots.contentRoot, "command-defs"));
  }
  async listSkills(): Promise<string[]> {
    const dir = join(this.roots.contentRoot, "skills");
    if (!existsSync(dir)) return [];
    return readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort();
  }

  private async listMarkdown(dir: string): Promise<string[]> {
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
      .filter((f) => f.endsWith(".md"))
      .map((f) => f.replace(/\.md$/, ""))
      .sort();
  }

  async loadAgent(name: string, opts: { variant?: ContentVariant } = {}): Promise<AgentDef> {
    const variant = opts.variant ?? "default";
    const variantPath =
      variant === "sdk"
        ? join(this.roots.contentRoot, "sdk-variants", "agent-defs", `${name}.md`)
        : null;
    const path = (await this.resolveOverride("agents", `${name}.md`))
      ?? (variantPath && existsSync(variantPath) ? variantPath : null)
      ?? join(this.roots.contentRoot, "agent-defs", `${name}.md`);
    if (!existsSync(path)) throw new Error(`agent-def not found: ${name} (looked in ${path})`);
    const src = await readFile(path, "utf8");
    const { data: fm, body } = parseFrontmatter(src);
    const tools = parseToolsList(fm["allowed-tools"] ?? fm["tools"]);
    return {
      name,
      description: typeof fm.description === "string" ? fm.description : "",
      ...(typeof fm.model === "string" ? { model: fm.model } : {}),
      ...(tools.length > 0 ? { tools } : {}),
      body,
    };
  }

  async loadCommand(mode: string, opts: { variant?: ContentVariant } = {}): Promise<CommandDef> {
    const variant = opts.variant ?? "default";
    const overridePath = await this.resolveOverride("commands", `${mode}.md`);
    if (overridePath) {
      const src = await readFile(overridePath, "utf8");
      return parseCommandDef(src, overridePath);
    }

    const canonicalPath = join(this.roots.contentRoot, "command-defs", `${mode}.md`);
    const variantPath =
      variant === "sdk"
        ? join(this.roots.contentRoot, "sdk-variants", "command-defs", `${mode}.md`)
        : null;
    if (!existsSync(canonicalPath)) {
      throw new Error(`command-def not found: ${mode} (looked in ${canonicalPath})`);
    }

    const canonical = parseCommandDef(await readFile(canonicalPath, "utf8"), canonicalPath);
    if (!variantPath || !existsSync(variantPath)) return canonical;

    // SDK variants transform prose and tool names only. Keep orchestration
    // metadata (phase graph, agents, completion contracts) canonical so a
    // stale generated variant can never silently weaken engine enforcement.
    const sdk = parseCommandDef(await readFile(variantPath, "utf8"), variantPath);
    return {
      ...canonical,
      body: sdk.body,
      ...(sdk.allowed_tools_raw !== undefined ? { allowed_tools_raw: sdk.allowed_tools_raw } : {}),
      source_path: variantPath,
    };
  }

  async resolveSkillDir(name: string): Promise<string> {
    const overrideDir = join(this.roots.overrideRoot, "skills", name);
    if (existsSync(join(overrideDir, "SKILL.md"))) return overrideDir;
    const embeddedDir = join(this.roots.contentRoot, "skills", name);
    if (!existsSync(join(embeddedDir, "SKILL.md"))) {
      throw new Error(`skill not found: ${name}`);
    }
    return embeddedDir;
  }

  async loadHarness(platform: string): Promise<unknown> {
    const path = join(this.roots.contentRoot, "harnesses", platform, "frontmatter.yaml");
    if (!existsSync(path)) throw new Error(`harness frontmatter not found for platform: ${platform}`);
    const raw = await readFile(path, "utf8");
    return parseYaml(raw);
  }

  /**
   * Resolve a per-user override file. Takes a kind ("agents" | "skills" |
   * "commands") and a relative file path; returns the absolute override path
   * if present, else null.
   */
  private async resolveOverride(kind: "agents" | "skills" | "commands", relPath: string): Promise<string | null> {
    const path = join(this.roots.overrideRoot, kind, relPath);
    try {
      const s = await stat(path);
      if (s.isFile()) return path;
    } catch {
      /* not present */
    }
    return null;
  }
}

function parseToolsList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((v): v is string => typeof v === "string");
  }
  if (typeof value === "string") {
    return value
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
      .map((s) => s.replace(/\([^)]*\)/g, "").trim())
      .filter((s) => s.length > 0);
  }
  return [];
}

let cached: ContentLoader | null = null;

/**
 * Resolve the content root for the current process. Dev mode reads from
 * src/content/ relative to this module; compiled mode extracts the embedded
 * `content-bundle.json` to ~/.cache/vigolium-audit/content-<bundle-hash>/ on first
 * run and reuses that directory thereafter. Override directory is
 * ~/.config/vigolium-audit/.
 */
export function resolveRoots(): ResolvedRoots {
  const moduleDir = dirname(fileURLToPath(import.meta.url));
  const devRoot = join(moduleDir, "content");
  const overrideRoot = process.env.VIGOLIUM_AUDIT_CONFIG_DIR
    ? join(process.env.VIGOLIUM_AUDIT_CONFIG_DIR)
    : join(homedir(), ".config", "vigolium-audit");
  if (existsSync(devRoot)) {
    return { contentRoot: devRoot, overrideRoot };
  }
  // Compiled mode: extract embedded bundle to cache.
  const cacheRoot = ensureExtractedBundle();
  return { contentRoot: cacheRoot, overrideRoot };
}

/**
 * Lazily extract the embedded content bundle to ~/.cache/vigolium-audit/content-<hash>/
 * and return the absolute path. Idempotent across runs.
 *
 * The dir name is keyed on a SHA-256 of the bundle's content (not its build
 * timestamp), so two builds of identical content reuse the same cache dir
 * rather than orphaning a fresh one each time. After resolving the current
 * dir we prune any stale `content-*` siblings from previous versions.
 */
function ensureExtractedBundle(): string {
  // Embedded as a static import; bun --compile inlines the JSON into the bin.
  // In dev mode this code path is never reached.
  const bundle = require("./content-bundle.json") as {
    generated_at: string;
    content_hash?: string;
    files: Record<string, string>;
  };
  const hash = bundle.content_hash ?? bundleContentHash(bundle.files);
  const cacheParent = join(homedir(), ".cache", "vigolium-audit");
  const dirName = `content-${hash}`;
  const cacheRoot = join(cacheParent, dirName);
  if (!existsSync(cacheRoot)) {
    mkdirSync(cacheRoot, { recursive: true });
    for (const [rel, contents] of Object.entries(bundle.files)) {
      const out = join(cacheRoot, rel);
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, contents);
    }
    // Only sweep on a fresh extraction — i.e. right after a version bump. In
    // steady state (cacheRoot already present) startup does zero extra I/O.
    pruneStaleContentDirs(cacheParent, dirName);
  }
  return cacheRoot;
}

/** Stable hash over the files map — order-independent, content-sensitive. */
export function bundleContentHash(files: Record<string, string>): string {
  const h = createHash("sha256");
  for (const key of Object.keys(files).sort()) {
    h.update(key);
    h.update("\0");
    h.update(files[key]!);
    h.update("\0");
  }
  return h.digest("hex").slice(0, 16);
}

/**
 * Remove `content-*` cache dirs left by previous bundle versions. Best-effort:
 * a dir held open by a concurrently-running older binary may refuse to delete,
 * which is fine — we swallow and move on.
 */
function pruneStaleContentDirs(cacheParent: string, keep: string): void {
  let entries: import("fs").Dirent[];
  try {
    entries = readdirSync(cacheParent, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (!entry.name.startsWith("content-") || entry.name === keep) continue;
    try {
      rmSync(join(cacheParent, entry.name), { recursive: true, force: true });
    } catch {
      /* held open elsewhere — leave it */
    }
  }
}

export function getContentLoader(): ContentLoader {
  if (!cached) {
    const roots = resolveRoots();
    cached = new FilesystemContentLoader(roots);
  }
  return cached;
}

/** For tests: build a loader pointed at explicit roots. */
export function makeContentLoader(roots: ResolvedRoots): ContentLoader {
  return new FilesystemContentLoader(roots);
}
