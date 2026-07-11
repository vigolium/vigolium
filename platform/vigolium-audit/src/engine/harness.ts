import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { copyFile, lstat, mkdir, readFile, readlink, readdir, stat, symlink, unlink, writeFile } from "fs/promises";
import { homedir } from "os";
import { join, relative } from "path";
import { stringify as stringifyYaml } from "yaml";
import { z } from "zod";
import { getContentLoader } from "../content-loader.js";

/**
 * Splice markers used to identify the vigolium-audit-managed block inside the global
 * `~/.codex/AGENTS.md`. Codex auto-loads this file on every `codex exec`, so
 * splicing in a `# BEGIN vigolium-audit ... # END vigolium-audit` block is the
 * codex equivalent of registering the slash-command dispatch we install for
 * claude. Replace-between-markers keeps the install idempotent and never
 * duplicates content.
 */
export const CODEX_AGENTS_BEGIN = "# BEGIN vigolium-audit";
export const CODEX_AGENTS_END = "# END vigolium-audit";
const LEGACY_CODEX_AGENTS_BEGIN = "# BEGIN archon-audit";
const LEGACY_CODEX_AGENTS_END = "# END archon-audit";

/**
 * Install-time merge & install of vendored content into a platform's plugin /
 * agents directory. Mirrors the Go vigolium-audit's `setup` command.
 *
 * Layouts produced:
 *
 *   Claude (Claude Code plugin format):
 *     ~/.config/vigolium-audit/harness-claude/
 *       .claude-plugin/plugin.json
 *       agents/<agent>.md            (canonical body + merged frontmatter)
 *       commands/vigolium-audit/<mode>.md    (verbatim copy of command-defs)
 *       skills/<skill>/...           (verbatim copy of skills tree)
 *
 *   Codex (single-file agents):
 *     ~/.codex/agents/vigolium-audit-<agent>.toml
 *       (TOML with name="vigolium-audit:<agent>", merged config, developer_instructions=body)
 */

export interface SetupResult {
  platform: "claude" | "codex";
  installPath: string;
  agentsInstalled: number;
  commandsInstalled: number;
  skillsInstalled: number;
  excluded: string[];
}

export function claudePluginDir(): string {
  return process.env.VIGOLIUM_AUDIT_HARNESS_CLAUDE_DIR ?? join(homedir(), ".config", "vigolium-audit", "harness-claude");
}

export function codexAgentsDir(): string {
  return process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_DIR ?? join(homedir(), ".codex", "agents");
}

export function codexSkillsDir(): string {
  return process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_SKILLS_DIR ?? join(homedir(), ".codex", "skills");
}

export function codexAgentsMdPath(): string {
  return process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_AGENTS_MD ?? join(homedir(), ".codex", "AGENTS.md");
}

/**
 * Stable path used by command definitions that invoke audit helper scripts.
 * The directory is a managed symlink to the content bundle, not a second
 * copied tree, so an upgraded binary cannot keep executing stale helpers.
 */
export function runtimeSkillsDir(): string {
  return process.env.VIGOLIUM_AUDIT_RUNTIME_SKILLS_DIR
    ?? join(homedir(), ".config", "vigolium-audit", "runtime-skills");
}

function legacyRuntimeSkillsDir(): string {
  return join(homedir(), ".config", "vigolium-audit", "skills");
}

function isManagedRuntimeSkillsTarget(target: string, currentSource?: string): boolean {
  if (currentSource !== undefined && target === currentSource) return true;
  const normalized = target.replaceAll("\\", "/");
  return normalized.endsWith("/archon-audit/skills")
    || normalized.includes("/.cache/vigolium-audit/content-");
}

async function removeManagedRuntimeSkillsLink(
  path: string,
  currentSource?: string,
): Promise<boolean> {
  const current = await lstat(path).catch(() => null);
  if (!current?.isSymbolicLink()) return false;
  const target = await readlink(path).catch(() => "");
  if (!isManagedRuntimeSkillsTarget(target, currentSource)) return false;
  await unlink(path);
  return true;
}

function removeManagedRuntimeSkillsLinkSync(path: string, currentSource?: string): boolean {
  let current: import("fs").Stats;
  try {
    current = lstatSync(path);
  } catch {
    return false;
  }
  if (!current.isSymbolicLink()) return false;
  let target: string;
  try {
    target = readlinkSync(path);
  } catch {
    return false;
  }
  if (!isManagedRuntimeSkillsTarget(target, currentSource)) return false;
  unlinkSync(path);
  return true;
}

async function removeLegacyManagedRuntimeSkillsLink(
  loader: ReturnType<typeof getContentLoader>,
): Promise<void> {
  // The previous TS release used the documented user-override directory as its
  // managed runtime mount. Remove only links we can prove were ours; preserve
  // real directories and custom symlinks byte-for-byte.
  if (process.env.VIGOLIUM_AUDIT_RUNTIME_SKILLS_DIR !== undefined) return;
  const source = join(loader.rootDir(), "skills");
  await removeManagedRuntimeSkillsLink(legacyRuntimeSkillsDir(), source);
}

function removeLegacyManagedRuntimeSkillsLinkSync(
  loader: ReturnType<typeof getContentLoader>,
): void {
  if (process.env.VIGOLIUM_AUDIT_RUNTIME_SKILLS_DIR !== undefined) return;
  const source = join(loader.rootDir(), "skills");
  removeManagedRuntimeSkillsLinkSync(legacyRuntimeSkillsDir(), source);
}

async function ensureRuntimeSkillsLink(loader: ReturnType<typeof getContentLoader>): Promise<void> {
  const source = join(loader.rootDir(), "skills");
  const destination = runtimeSkillsDir();
  await removeLegacyManagedRuntimeSkillsLink(loader);
  let current: import("fs").Stats | null = null;
  try {
    current = await lstat(destination);
  } catch {
    /* missing (or a dangling parent) — create it below */
  }

  if (current?.isSymbolicLink()) {
    const target = await readlink(destination).catch(() => "");
    if (target === source) return;
    // Migrate links created by the retired installation, and refresh links to
    // an older extracted content bundle after an upgrade.
    if (isManagedRuntimeSkillsTarget(target, source)) {
      await unlink(destination);
      current = null;
    } else {
      // A custom user-managed runtime link is an override. Leave it untouched.
      return;
    }
  } else if (current) {
    // A real runtime directory is also a user override; never replace it.
    return;
  }

  await mkdir(join(destination, ".."), { recursive: true });
  await symlink(source, destination, "dir");
}

/**
 * Codex skills live at `~/.codex/skills/vigolium-audit-<skill>/`. Agent bodies still
 * reference the stable runtime path (`~/.config/vigolium-audit/runtime-skills/<skill>/...`),
 * so we rewrite those references during install so the same agent body works
 * for both the Go and TS installs.
 */
function rewriteCodexSkillPaths(body: string): string {
  // `~/.config/vigolium-audit/runtime-skills/audit/foo` →
  // `~/.codex/skills/vigolium-audit-audit/foo`.
  // The trailing slash on `skills/` matters: it forces consumption of the
  // skill-name segment so we don't leave a stale path component. Keep accepting
  // the retired path for user-authored agent overrides during migration.
  return body.replace(
    /~\/\.config\/vigolium-audit\/(?:runtime-skills|skills)\/([^/\s)]+)\//g,
    "~/.codex/skills/vigolium-audit-$1/",
  );
}

const ClaudeHarnessSchema = z.object({
  format: z.literal("md"),
  defaults: z.record(z.string(), z.unknown()).default({}),
  overrides: z.record(z.string(), z.record(z.string(), z.unknown())).default({}),
});

const CodexHarnessSchema = z.object({
  format: z.literal("toml"),
  agent_name_prefix: z.string().default("vigolium-audit:"),
  dispatch_file: z.string().optional(),
  subagent_preamble_file: z.string().optional(),
  defaults: z.record(z.string(), z.unknown()).default({}),
  subagent_defaults: z.record(z.string(), z.unknown()).default({}),
  subagent_overrides: z.record(z.string(), z.record(z.string(), z.unknown())).default({}),
  exclude: z.array(z.string()).default([]),
});

export async function installHarness(platform: "claude" | "codex"): Promise<SetupResult> {
  const loader = getContentLoader();
  await ensureRuntimeSkillsLink(loader);
  if (platform === "claude") return installClaudeHarness(loader);
  return installCodexHarness(loader);
}

async function installClaudeHarness(loader: ReturnType<typeof getContentLoader>): Promise<SetupResult> {
  const harnessRaw = await loader.loadHarness("claude");
  const harness = ClaudeHarnessSchema.parse(harnessRaw);
  const dir = claudePluginDir();
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  mkdirSync(join(dir, ".claude-plugin"), { recursive: true });
  mkdirSync(join(dir, "agents"), { recursive: true });
  mkdirSync(join(dir, "commands", "vigolium-audit"), { recursive: true });
  mkdirSync(join(dir, "skills"), { recursive: true });

  // 1) plugin manifest from src/content/harnesses/claude/plugin.json
  const pluginManifestPath = join(loader.rootDir(), "harnesses", "claude", "plugin.json");
  if (existsSync(pluginManifestPath)) {
    await copyFile(pluginManifestPath, join(dir, ".claude-plugin", "plugin.json"));
  }

  // 2) agents — merge per-agent frontmatter
  const excluded: string[] = [];
  let agentsInstalled = 0;
  for (const name of await loader.listAgents()) {
    const override = harness.overrides[name];
    if (override && override["exclude"] === true) {
      excluded.push(name);
      continue;
    }
    const merged: Record<string, unknown> = {
      name,
      ...harness.defaults,
      ...(override ?? {}),
    };
    // Drop YAML keys whose value is null/undefined so the resulting frontmatter
    // doesn't carry empty fields.
    for (const key of Object.keys(merged)) {
      if (merged[key] === null || merged[key] === undefined) delete merged[key];
    }
    const agent = await loader.loadAgent(name);
    // Use canonical agent description if not overridden in harness frontmatter.
    if (!("description" in merged) && agent.description) merged.description = agent.description;
    const fmYaml = stringifyYaml(merged).trimEnd();
    const out = `---\n${fmYaml}\n---\n\n${agent.body.trim()}\n`;
    await writeFile(join(dir, "agents", `${name}.md`), out, "utf8");
    agentsInstalled++;
  }

  // 3) commands — verbatim copy under commands/vigolium-audit/
  let commandsInstalled = 0;
  for (const mode of await loader.listCommands()) {
    const src = join(loader.rootDir(), "command-defs", `${mode}.md`);
    if (!existsSync(src)) continue;
    await copyFile(src, join(dir, "commands", "vigolium-audit", `${mode}.md`));
    commandsInstalled++;
  }

  // 4) skills — verbatim recursive copy
  const skillsRoot = join(loader.rootDir(), "skills");
  let skillsInstalled = 0;
  if (existsSync(skillsRoot)) {
    for (const skill of await loader.listSkills()) {
      await copyDir(join(skillsRoot, skill), join(dir, "skills", skill));
      skillsInstalled++;
    }
  }

  return {
    platform: "claude",
    installPath: dir,
    agentsInstalled,
    commandsInstalled,
    skillsInstalled,
    excluded,
  };
}

async function installCodexHarness(loader: ReturnType<typeof getContentLoader>): Promise<SetupResult> {
  const harnessRaw = await loader.loadHarness("codex");
  const harness = CodexHarnessSchema.parse(harnessRaw);
  const dir = codexAgentsDir();
  mkdirSync(dir, { recursive: true });

  // Best-effort: clean up current and retired installs so this is idempotent.
  for (const entry of await readdir(dir).catch(() => [])) {
    if (
      (entry.startsWith("vigolium-audit-") || entry.startsWith("archon-audit-"))
      && entry.endsWith(".toml")
    ) {
      rmSync(join(dir, entry), { force: true });
    }
  }

  const preamble = harness.subagent_preamble_file
    ? await readFile(join(loader.rootDir(), "harnesses", "codex", harness.subagent_preamble_file), "utf8").catch(() => "")
    : "";

  const excluded = new Set(harness.exclude);
  let agentsInstalled = 0;
  for (const name of await loader.listAgents()) {
    if (excluded.has(name)) continue;
    const config: Record<string, unknown> = {
      ...harness.subagent_defaults,
      ...(harness.subagent_overrides[name] ?? {}),
    };
    const agent = await loader.loadAgent(name);
    const rewrittenBody = rewriteCodexSkillPaths(agent.body.trim());
    const body = preamble ? `${preamble.trim()}\n\n${rewrittenBody}\n` : rewrittenBody + "\n";
    const toml = renderCodexAgentToml({
      name: `${harness.agent_name_prefix}${name}`,
      description: agent.description,
      config,
      body,
    });
    await writeFile(join(dir, `vigolium-audit-${name}.toml`), toml, "utf8");
    agentsInstalled++;
  }

  // Skills install — codex has no plugin system to scope these to, so we
  // namespace by prefix (`vigolium-audit-<skill>`) under the global skills dir to
  // avoid colliding with user / vendor skills already present there.
  const skillsRoot = join(loader.rootDir(), "skills");
  const skillsDst = codexSkillsDir();
  mkdirSync(skillsDst, { recursive: true });
  for (const entry of await readdir(skillsDst).catch(() => [])) {
    if (entry.startsWith("vigolium-audit-") || entry.startsWith("archon-audit-")) {
      rmSync(join(skillsDst, entry), { recursive: true, force: true });
    }
  }
  let skillsInstalled = 0;
  if (existsSync(skillsRoot)) {
    for (const skill of await loader.listSkills()) {
      await copyDir(join(skillsRoot, skill), join(skillsDst, `vigolium-audit-${skill}`));
      skillsInstalled++;
    }
  }

  // Dispatch fragment install — splice agents-dispatch.md into the global
  // ~/.codex/AGENTS.md between BEGIN/END markers. Codex auto-loads AGENTS.md
  // on every `codex exec`, so this turns the fragment into the
  // slash-command-equivalent for codex: a user prompt that says "run the
  // vigolium-audit deep audit" causes codex to follow the dispatch in its
  // already-loaded AGENTS.md.
  let commandsInstalled = 0;
  if (harness.dispatch_file) {
    const dispatchPath = join(loader.rootDir(), "harnesses", "codex", harness.dispatch_file);
    const dispatch = await readFile(dispatchPath, "utf8").catch(() => "");
    if (dispatch.length > 0) {
      await spliceAgentsMd(codexAgentsMdPath(), dispatch);
      commandsInstalled = 1;
    }
  }

  return {
    platform: "codex",
    installPath: dir,
    agentsInstalled,
    commandsInstalled,
    skillsInstalled,
    excluded: [...excluded],
  };
}

/**
 * Idempotently splice an vigolium-audit-managed block into `~/.codex/AGENTS.md`
 * between `# BEGIN vigolium-audit` and `# END vigolium-audit`. Other content in
 * the file (user prose, blocks from other tools) is preserved verbatim.
 *
 * The block content (`fragment`) is expected to already include the BEGIN/END
 * markers as its first/last lines — that's how `agents-dispatch.md` is
 * authored. We trust those markers and replace within them; if the file
 * doesn't yet exist or has no markers, we append the fragment.
 */
async function spliceAgentsMd(path: string, fragment: string): Promise<void> {
  const trimmed = fragment.trim();
  await mkdir(join(path, ".."), { recursive: true });
  let existing = "";
  try {
    existing = await readFile(path, "utf8");
  } catch {
    /* file may not exist — we'll create it */
  }
  existing = removeMarkedBlock(existing, LEGACY_CODEX_AGENTS_BEGIN, LEGACY_CODEX_AGENTS_END);
  const beginIdx = existing.indexOf(CODEX_AGENTS_BEGIN);
  const endIdx = existing.indexOf(CODEX_AGENTS_END);
  let next: string;
  if (beginIdx >= 0 && endIdx > beginIdx) {
    // Replace existing block, keeping prefix/suffix exactly as the user has it.
    const after = endIdx + CODEX_AGENTS_END.length;
    next = existing.slice(0, beginIdx) + trimmed + existing.slice(after);
  } else if (existing.length === 0) {
    next = trimmed + "\n";
  } else {
    // No prior markers — append a separator and the block.
    const sep = existing.endsWith("\n") ? "" : "\n";
    next = existing + sep + "\n" + trimmed + "\n";
  }
  await writeFile(path, next, "utf8");
}

function removeMarkedBlock(existing: string, begin: string, end: string): string {
  let next = existing;
  while (true) {
    const beginIdx = next.indexOf(begin);
    const endIdx = next.indexOf(end);
    if (beginIdx < 0 || endIdx <= beginIdx) return next;
    const after = endIdx + end.length;
    // Preserve all bytes outside the managed range. In particular, do not
    // normalize blank-line runs in unrelated user-authored AGENTS.md content.
    next = next.slice(0, beginIdx) + next.slice(after);
  }
}

/**
 * Inverse of `spliceAgentsMd`: remove the vigolium-audit-managed block and clean up
 * trailing whitespace. Called on uninstall and from the ephemeral cleanup
 * hook so a SIGINT doesn't leave a stale dispatch in the user's AGENTS.md.
 */
async function unspliceAgentsMd(path: string): Promise<boolean> {
  let existing: string;
  try {
    existing = await readFile(path, "utf8");
  } catch {
    return false;
  }
  const beginIdx = existing.indexOf(CODEX_AGENTS_BEGIN);
  const endIdx = existing.indexOf(CODEX_AGENTS_END);
  if (beginIdx < 0 || endIdx <= beginIdx) return false;
  const next = removeMarkedBlock(existing, CODEX_AGENTS_BEGIN, CODEX_AGENTS_END).trimEnd();
  if (next.length === 0) {
    await unlink(path).catch(() => {});
  } else {
    await writeFile(path, next + "\n", "utf8");
  }
  return true;
}

function unspliceAgentsMdSync(path: string): boolean {
  let existing: string;
  try {
    existing = readFileSync(path, "utf8");
  } catch {
    return false;
  }
  const beginIdx = existing.indexOf(CODEX_AGENTS_BEGIN);
  const endIdx = existing.indexOf(CODEX_AGENTS_END);
  if (beginIdx < 0 || endIdx <= beginIdx) return false;
  const next = removeMarkedBlock(existing, CODEX_AGENTS_BEGIN, CODEX_AGENTS_END).trimEnd();
  if (next.length === 0) {
    try {
      unlinkSync(path);
    } catch {
      /* best effort */
    }
  } else {
    writeFileSync(path, next + "\n", "utf8");
  }
  return true;
}

function renderCodexAgentToml(args: {
  name: string;
  description: string;
  config: Record<string, unknown>;
  body: string;
}): string {
  const lines: string[] = [];
  lines.push(`name = ${tomlString(args.name)}`);
  if (args.description) lines.push(`description = ${tomlString(args.description)}`);
  for (const [k, v] of Object.entries(args.config)) {
    if (v === null || v === undefined) continue;
    if (typeof v === "string") lines.push(`${k} = ${tomlString(v)}`);
    else if (typeof v === "number" || typeof v === "boolean") lines.push(`${k} = ${String(v)}`);
    else lines.push(`${k} = ${JSON.stringify(v)}`);
  }
  lines.push("");
  lines.push("developer_instructions = '''");
  lines.push(args.body.replace(/'''/g, "''\\'"));
  lines.push("'''");
  lines.push("");
  return lines.join("\n");
}

function tomlString(s: string): string {
  // Use a literal string when there are no single quotes; else fall back to
  // a basic string with escaping.
  if (!s.includes("'")) return `'${s}'`;
  return JSON.stringify(s);
}

async function copyDir(src: string, dst: string): Promise<void> {
  await mkdir(dst, { recursive: true });
  for (const entry of await readdir(src)) {
    const s = join(src, entry);
    const d = join(dst, entry);
    const st = await stat(s);
    if (st.isDirectory()) await copyDir(s, d);
    else await copyFile(s, d);
  }
}

async function removeRuntimeSkillsLinkIfUnused(removed: string[]): Promise<void> {
  if (harnessInstalled("claude") || harnessInstalled("codex")) return;
  const loader = getContentLoader();
  await removeLegacyManagedRuntimeSkillsLink(loader);
  const path = runtimeSkillsDir();
  const source = join(loader.rootDir(), "skills");
  if (await removeManagedRuntimeSkillsLink(path, source)) {
    removed.push(relative(homedir(), path) + " (runtime skills)");
  }
}

function removeRuntimeSkillsLinkIfUnusedSync(): void {
  if (harnessInstalled("claude") || harnessInstalled("codex")) return;
  const loader = getContentLoader();
  removeLegacyManagedRuntimeSkillsLinkSync(loader);
  const source = join(loader.rootDir(), "skills");
  removeManagedRuntimeSkillsLinkSync(runtimeSkillsDir(), source);
}

export async function uninstallHarness(platform: "claude" | "codex"): Promise<{ removed: string[] }> {
  const removed: string[] = [];
  if (platform === "claude") {
    const dir = claudePluginDir();
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true });
      removed.push(dir);
    }
  } else {
    const dir = codexAgentsDir();
    if (existsSync(dir)) {
      for (const entry of await readdir(dir)) {
        if (entry.startsWith("vigolium-audit-") && entry.endsWith(".toml")) {
          const path = join(dir, entry);
          rmSync(path, { force: true });
          removed.push(relative(homedir(), path));
        }
      }
    }

    // Skills installed alongside agents — remove the vigolium-audit-prefixed entries.
    const skillsDst = codexSkillsDir();
    if (existsSync(skillsDst)) {
      for (const entry of await readdir(skillsDst)) {
        if (entry.startsWith("vigolium-audit-")) {
          const path = join(skillsDst, entry);
          rmSync(path, { recursive: true, force: true });
          removed.push(relative(homedir(), path));
        }
      }
    }

    // Splice out the AGENTS.md dispatch fragment if we wrote one.
    const agentsMd = codexAgentsMdPath();
    if (await unspliceAgentsMd(agentsMd)) {
      removed.push(relative(homedir(), agentsMd) + " (dispatch block)");
    }
  }

  await removeRuntimeSkillsLinkIfUnused(removed);
  return { removed };
}

function uninstallHarnessSync(platform: "claude" | "codex"): void {
  if (platform === "claude") {
    const dir = claudePluginDir();
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  } else {
    const dir = codexAgentsDir();
    if (existsSync(dir)) {
      for (const entry of readdirSync(dir)) {
        if (entry.startsWith("vigolium-audit-") && entry.endsWith(".toml")) {
          rmSync(join(dir, entry), { force: true });
        }
      }
    }

    const skillsDst = codexSkillsDir();
    if (existsSync(skillsDst)) {
      for (const entry of readdirSync(skillsDst)) {
        if (entry.startsWith("vigolium-audit-")) {
          rmSync(join(skillsDst, entry), { recursive: true, force: true });
        }
      }
    }

    unspliceAgentsMdSync(codexAgentsMdPath());
  }

  removeRuntimeSkillsLinkIfUnusedSync();
}

/**
 * Cheap "is a harness already installed for this platform?" probe, used to
 * distinguish a persistent `vigolium-audit setup` install from a fresh
 * ephemeral one. Checks for the sentinel artifact each install produces:
 *   - claude: `.claude-plugin/plugin.json` under the plugin dir.
 *   - codex: any `vigolium-audit-*.toml` under the agents dir.
 */
export function harnessInstalled(platform: "claude" | "codex"): boolean {
  if (platform === "claude") {
    return existsSync(join(claudePluginDir(), ".claude-plugin", "plugin.json"));
  }
  const dir = codexAgentsDir();
  if (!existsSync(dir)) return false;
  for (const entry of readdirSync(dir)) {
    if (entry.startsWith("vigolium-audit-") && entry.endsWith(".toml")) return true;
  }
  return false;
}

export interface EphemeralHarnessHandle {
  /** Where the harness was installed for this run. */
  installResult: SetupResult;
  /** Removes the harness. Idempotent — safe to call from both `finally` and the `exit` hook. */
  cleanup(): void;
}

/**
 * Install the platform harness for the lifetime of one run, and register an
 * `exit` hook that removes it. Mirrors `applyAuthOverrides` — the `exit` event
 * fires on natural exit, `process.exit()`, and the default SIGINT handler, so
 * a single hook covers Ctrl-C and uncaught throws as well.
 *
 * Concurrent `vigolium-audit run -i` instances will fight over the same install dir
 * (one's cleanup deletes the other's plugin). Theoretical and rare enough we
 * accept it for now; document if it bites users.
 *
 * If a persistent install already exists (from `vigolium-audit setup`), we refresh
 * it in place but skip the exit cleanup so an interactive run never deletes the
 * user's standing harness — only ephemeral-created installs get torn down.
 */
export async function registerEphemeralHarness(
  platform: "claude" | "codex",
): Promise<EphemeralHarnessHandle> {
  const preExisting = harnessInstalled(platform);
  const installResult = await installHarness(platform);
  let cleaned = false;
  const cleanup = (): void => {
    if (cleaned) return;
    cleaned = true;
    process.removeListener("exit", hookExit);
    // Leave a persistent `vigolium-audit setup` install untouched.
    if (preExisting) return;
    try {
      uninstallHarnessSync(platform);
    } catch {
      /* best effort */
    }
  };
  const hookExit = (): void => cleanup();
  process.once("exit", hookExit);
  return { installResult, cleanup };
}
