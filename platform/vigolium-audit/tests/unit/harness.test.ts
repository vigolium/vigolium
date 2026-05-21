import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { parse as parseYaml } from "yaml";
import { installHarness, registerEphemeralHarness, uninstallHarness } from "../../src/engine/harness.js";

let claudeDir: string;
let codexDir: string;
let codexSkillsDir: string;
let codexAgentsMdPath: string;
let codexEnvDir: string;

beforeEach(() => {
  claudeDir = mkdtempSync(join(tmpdir(), "vigolium-audit-harness-claude-"));
  codexDir = mkdtempSync(join(tmpdir(), "vigolium-audit-harness-codex-"));
  codexSkillsDir = mkdtempSync(join(tmpdir(), "vigolium-audit-harness-codex-skills-"));
  // The AGENTS.md path is a single file inside its own tmpdir so the splice
  // tests can assert on parent-dir contents without leaking into HOME.
  codexEnvDir = mkdtempSync(join(tmpdir(), "vigolium-audit-harness-codex-env-"));
  codexAgentsMdPath = join(codexEnvDir, "AGENTS.md");
  process.env.VIGOLIUM_AUDIT_HARNESS_CLAUDE_DIR = claudeDir;
  process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_DIR = codexDir;
  process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_SKILLS_DIR = codexSkillsDir;
  process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_AGENTS_MD = codexAgentsMdPath;
});

afterEach(() => {
  if (existsSync(claudeDir)) rmSync(claudeDir, { recursive: true, force: true });
  if (existsSync(codexDir)) rmSync(codexDir, { recursive: true, force: true });
  if (existsSync(codexSkillsDir)) rmSync(codexSkillsDir, { recursive: true, force: true });
  if (existsSync(codexEnvDir)) rmSync(codexEnvDir, { recursive: true, force: true });
  delete process.env.VIGOLIUM_AUDIT_HARNESS_CLAUDE_DIR;
  delete process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_DIR;
  delete process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_SKILLS_DIR;
  delete process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_AGENTS_MD;
});

describe("installHarness(claude)", () => {
  test("produces .claude-plugin/plugin.json + agents/ + commands/vigolium-audit/ + skills/", async () => {
    const result = await installHarness("claude");
    expect(result.platform).toBe("claude");
    expect(result.installPath).toBe(claudeDir);
    expect(result.agentsInstalled).toBeGreaterThan(20);
    expect(result.commandsInstalled).toBe(10);
    expect(result.skillsInstalled).toBeGreaterThan(15);
    expect(result.excluded).toContain("deep-reviewer");

    expect(existsSync(join(claudeDir, ".claude-plugin", "plugin.json"))).toBe(true);
    expect(existsSync(join(claudeDir, "agents"))).toBe(true);
    expect(existsSync(join(claudeDir, "commands", "vigolium-audit"))).toBe(true);
    expect(existsSync(join(claudeDir, "skills"))).toBe(true);

    // Plugin manifest name drives the slash-command namespace: commands under
    // commands/vigolium-audit/ resolve to `/vigolium-audit:vigolium-audit:<cmd>`.
    const manifest = JSON.parse(readFileSync(join(claudeDir, ".claude-plugin", "plugin.json"), "utf8"));
    expect(manifest.name).toBe("vigolium-audit");
  });

  test("agent frontmatter is merged from canonical + harness defaults + per-agent overrides", async () => {
    await installHarness("claude");
    const advisory = readFileSync(join(claudeDir, "agents", "cve-scout.md"), "utf8");
    const fmMatch = advisory.match(/^---\n([\s\S]*?)\n---/);
    expect(fmMatch).toBeTruthy();
    const fm = parseYaml(fmMatch![1]!);
    // From defaults:
    expect(fm.permissionMode).toBe("bypassPermissions");
    expect(fm.effort).toBe("low");
    expect(fm.model).toBe("sonnet");
    // From per-agent override:
    expect(fm.color).toBe("cyan");
    expect(fm.tools).toContain("WebSearch");
    expect(fm.tools).toContain("WebFetch");
    // Always set:
    expect(fm.name).toBe("cve-scout");
    expect(fm.description).toBeTruthy();
  });

  test("excluded agents (e.g. deep-reviewer) are not written", async () => {
    await installHarness("claude");
    expect(existsSync(join(claudeDir, "agents", "deep-reviewer.md"))).toBe(false);
  });

  test("commands are namespaced under vigolium-audit/", async () => {
    await installHarness("claude");
    const commands = readdirSync(join(claudeDir, "commands", "vigolium-audit")).sort();
    expect(commands).toContain("deep.md");
    expect(commands).toContain("lite.md");
    expect(commands).toContain("balanced.md");
    expect(commands).toContain("longshot.md");
    expect(commands.length).toBe(10);
  });

  test("idempotent — second install replaces first cleanly", async () => {
    await installHarness("claude");
    const before = readdirSync(join(claudeDir, "agents")).length;
    await installHarness("claude");
    const after = readdirSync(join(claudeDir, "agents")).length;
    expect(after).toBe(before);
  });

  test("uninstall removes the entire plugin dir", async () => {
    await installHarness("claude");
    expect(existsSync(claudeDir)).toBe(true);
    const { removed } = await uninstallHarness("claude");
    expect(removed).toEqual([claudeDir]);
    expect(existsSync(claudeDir)).toBe(false);
  });
});

describe("installHarness(codex)", () => {
  test("produces vigolium-audit-<name>.toml files with merged config", async () => {
    const result = await installHarness("codex");
    expect(result.platform).toBe("codex");
    expect(result.agentsInstalled).toBeGreaterThan(20);
    expect(result.excluded).toContain("independent-verifier");
    expect(result.excluded).toContain("history-miner");

    const advisory = readFileSync(join(codexDir, "vigolium-audit-cve-scout.toml"), "utf8");
    expect(advisory).toContain(`name = 'vigolium-audit:cve-scout'`);
    expect(advisory).toContain(`model = 'gpt-5.4'`);
    expect(advisory).toContain(`sandbox_mode = 'workspace-write'`);
    expect(advisory).toContain("developer_instructions");
    // Body is wrapped in TOML literal-string triple quotes.
    expect(advisory).toMatch(/developer_instructions = '''[\s\S]+'''/);
  });

  test("subagent_overrides win — code-scanner gets danger-full-access", async () => {
    await installHarness("codex");
    const sa = readFileSync(join(codexDir, "vigolium-audit-code-scanner.toml"), "utf8");
    expect(sa).toContain(`sandbox_mode = 'danger-full-access'`);
  });

  test("uninstall removes only vigolium-audit-*.toml files (preserves other agents)", async () => {
    await installHarness("codex");
    // Pre-seed an unrelated codex agent file that uninstall must NOT touch.
    const unrelated = join(codexDir, "user-custom-agent.toml");
    Bun.write(unrelated, "name = 'user-custom'\n");
    await Bun.sleep(10);
    const { removed } = await uninstallHarness("codex");
    expect(removed.length).toBeGreaterThan(0);
    expect(existsSync(unrelated)).toBe(true);
  });

  test("installs skills under vigolium-audit-<skill>/ — gives codex the methodology agents reference", async () => {
    const result = await installHarness("codex");
    expect(result.skillsInstalled).toBeGreaterThan(15);

    const installed = readdirSync(codexSkillsDir).sort();
    expect(installed).toContain("vigolium-audit-audit");
    expect(installed).toContain("vigolium-audit-fp-check");
    expect(installed).toContain("vigolium-audit-codeql");
    // Every entry the install touched is namespaced — no bare skill leaks into
    // the global ~/.codex/skills/ directory.
    for (const name of installed) {
      expect(name.startsWith("vigolium-audit-")).toBe(true);
    }
    expect(existsSync(join(codexSkillsDir, "vigolium-audit-audit", "SKILL.md"))).toBe(true);
  });

  test("rewrites legacy ~/.config/vigolium-audit/skills/ paths to ~/.codex/skills/vigolium-audit- in agent bodies", async () => {
    await installHarness("codex");
    // code-scanner's body references the audit skill via the legacy path.
    // The rewrite must redirect that path so the agent's Read tool calls
    // hit the codex install rather than the (possibly missing) prior-binary dir.
    const sa = readFileSync(join(codexDir, "vigolium-audit-code-scanner.toml"), "utf8");
    expect(sa).not.toContain("~/.config/vigolium-audit/skills/");
    expect(sa).toContain("~/.codex/skills/vigolium-audit-audit/");
  });

  test("splices the dispatch fragment into AGENTS.md between BEGIN/END markers", async () => {
    const result = await installHarness("codex");
    expect(result.commandsInstalled).toBe(1);

    expect(existsSync(codexAgentsMdPath)).toBe(true);
    const md = readFileSync(codexAgentsMdPath, "utf8");
    const begins = md.match(/# BEGIN vigolium-audit/g) ?? [];
    const ends = md.match(/# END vigolium-audit/g) ?? [];
    expect(begins.length).toBe(1);
    expect(ends.length).toBe(1);
    expect(md).toContain("vigolium-audit:cve-scout");
  });

  test("AGENTS.md splice preserves user-authored content above and below the block", async () => {
    writeFileSync(codexAgentsMdPath, "# my notes\n\nuser content\n");
    await installHarness("codex");
    const md = readFileSync(codexAgentsMdPath, "utf8");
    expect(md.startsWith("# my notes\n\nuser content\n")).toBe(true);
    expect(md).toContain("# BEGIN vigolium-audit");
  });

  test("AGENTS.md splice is idempotent — second install replaces the block in place", async () => {
    writeFileSync(codexAgentsMdPath, "user prefix\n");
    await installHarness("codex");
    const first = readFileSync(codexAgentsMdPath, "utf8");
    await installHarness("codex");
    const second = readFileSync(codexAgentsMdPath, "utf8");
    // No accumulating duplicate blocks across reinstalls.
    expect((second.match(/# BEGIN vigolium-audit/g) ?? []).length).toBe(1);
    expect(second).toBe(first);
  });

  test("uninstall removes the AGENTS.md block and the vigolium-audit-*/ skills", async () => {
    writeFileSync(codexAgentsMdPath, "user prefix\n");
    await installHarness("codex");
    expect(existsSync(join(codexSkillsDir, "vigolium-audit-audit"))).toBe(true);

    const { removed } = await uninstallHarness("codex");
    expect(removed.some((p) => p.endsWith("(dispatch block)"))).toBe(true);

    expect(existsSync(join(codexSkillsDir, "vigolium-audit-audit"))).toBe(false);
    const md = readFileSync(codexAgentsMdPath, "utf8");
    expect(md).not.toContain("# BEGIN vigolium-audit");
    expect(md).toContain("user prefix");
  });
});

describe("registerEphemeralHarness", () => {
  test("installs on entry and cleans up via the returned handle", async () => {
    const before = process.listenerCount("exit");
    const handle = await registerEphemeralHarness("claude");
    expect(handle.installResult.platform).toBe("claude");
    expect(existsSync(join(claudeDir, ".claude-plugin", "plugin.json"))).toBe(true);
    expect(process.listenerCount("exit")).toBe(before + 1);

    handle.cleanup();
    expect(existsSync(claudeDir)).toBe(false);
    // Listener should be removed after cleanup so the `exit` event won't re-trigger it.
    expect(process.listenerCount("exit")).toBe(before);
  });

  test("cleanup is idempotent", async () => {
    const handle = await registerEphemeralHarness("claude");
    handle.cleanup();
    // Second call must not throw — uninstallHarness is also a no-op when dir is gone.
    expect(() => handle.cleanup()).not.toThrow();
  });
});
