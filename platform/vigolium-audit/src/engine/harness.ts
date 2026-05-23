import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, unlinkSync, writeFileSync } from "fs";
import { copyFile, mkdir, readFile, readdir, stat, unlink, writeFile } from "fs/promises";
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
 * Codex skills live at `~/.codex/skills/vigolium-audit-<skill>/`. Agent bodies still
 * reference the legacy Go-binary path (`~/.config/vigolium-audit/skills/<skill>/...`),
 * so we rewrite those references during install so the same agent body works
 * for both the Go and TS installs.
 */
function rewriteCodexSkillPaths(body: string): string {
  // `~/.config/vigolium-audit/skills/audit/foo` → `~/.codex/skills/vigolium-audit/foo`.
  // The trailing slash on `skills/` matters: it forces consumption of the
  // legacy "audit" segment so we don't leave a stale path component.
  return body.replace(/~\/\.config\/vigolium-audit\/skills\/([^/\s)]+)\//g, "~/.codex/skills/vigolium-audit-$1/");
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

  // Best-effort: clean up any prior vigolium-audit-* installs so this is idempotent.
  for (const entry of await readdir(dir).catch(() => [])) {
    if (entry.startsWith("vigolium-audit-") && entry.endsWith(".toml")) {
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
    if (entry.startsWith("vigolium-audit-")) {
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
  const after = endIdx + CODEX_AGENTS_END.length;
  const next = (existing.slice(0, beginIdx) + existing.slice(after)).replace(/\n{3,}/g, "\n\n").trimEnd();
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
  const after = endIdx + CODEX_AGENTS_END.length;
  const next = (existing.slice(0, beginIdx) + existing.slice(after)).replace(/\n{3,}/g, "\n\n").trimEnd();
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

export async function uninstallHarness(platform: "claude" | "codex"): Promise<{ removed: string[] }> {
  if (platform === "claude") {
    const dir = claudePluginDir();
    if (!existsSync(dir)) return { removed: [] };
    rmSync(dir, { recursive: true, force: true });
    return { removed: [dir] };
  }
  const dir = codexAgentsDir();
  const removed: string[] = [];
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

  return { removed };
}

function uninstallHarnessSync(platform: "claude" | "codex"): void {
  if (platform === "claude") {
    const dir = claudePluginDir();
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
    return;
  }
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
 */
export async function registerEphemeralHarness(
  platform: "claude" | "codex",
): Promise<EphemeralHarnessHandle> {
  const installResult = await installHarness(platform);
  let cleaned = false;
  const cleanup = (): void => {
    if (cleaned) return;
    cleaned = true;
    process.removeListener("exit", hookExit);
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
