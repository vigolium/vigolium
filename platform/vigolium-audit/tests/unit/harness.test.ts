import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { spawnSync } from "child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readlinkSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { homedir, tmpdir } from "os";
import { join, resolve } from "path";
import { parse as parseYaml } from "yaml";
import {
  harnessInstalled,
  installHarness,
  registerEphemeralHarness,
  runtimeSkillsDir as resolveRuntimeSkillsDir,
  uninstallHarness,
} from "../../src/engine/harness.js";

// Every test here installs a harness, which copies the entire content tree
// (30+ agents, 15+ skills with reference docs) to a fresh tmpdir. That's real
// filesystem work that comfortably exceeds bun's 5s default timeout when the
// machine is under load (e.g. the rest of the suite running in parallel in
// CI). Give these I/O-bound tests explicit headroom so they don't flake.
const INSTALL_TIMEOUT_MS = 30_000;

let claudeDir: string;
let codexDir: string;
let codexSkillsDir: string;
let codexAgentsMdPath: string;
let codexEnvDir: string;
let runtimeEnvDir: string;
let runtimeSkillsDir: string;

beforeEach(() => {
  claudeDir = mkdtempSync(join(tmpdir(), "vigolium-audit-harness-claude-"));
  codexDir = mkdtempSync(join(tmpdir(), "vigolium-audit-harness-codex-"));
  codexSkillsDir = mkdtempSync(join(tmpdir(), "vigolium-audit-harness-codex-skills-"));
  // The AGENTS.md path is a single file inside its own tmpdir so the splice
  // tests can assert on parent-dir contents without leaking into HOME.
  codexEnvDir = mkdtempSync(join(tmpdir(), "vigolium-audit-harness-codex-env-"));
  codexAgentsMdPath = join(codexEnvDir, "AGENTS.md");
  runtimeEnvDir = mkdtempSync(join(tmpdir(), "vigolium-audit-runtime-"));
  runtimeSkillsDir = join(runtimeEnvDir, "skills");
  process.env.VIGOLIUM_AUDIT_HARNESS_CLAUDE_DIR = claudeDir;
  process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_DIR = codexDir;
  process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_SKILLS_DIR = codexSkillsDir;
  process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_AGENTS_MD = codexAgentsMdPath;
  process.env.VIGOLIUM_AUDIT_RUNTIME_SKILLS_DIR = runtimeSkillsDir;
});

afterEach(() => {
  if (existsSync(claudeDir)) rmSync(claudeDir, { recursive: true, force: true });
  if (existsSync(codexDir)) rmSync(codexDir, { recursive: true, force: true });
  if (existsSync(codexSkillsDir)) rmSync(codexSkillsDir, { recursive: true, force: true });
  if (existsSync(codexEnvDir)) rmSync(codexEnvDir, { recursive: true, force: true });
  if (existsSync(runtimeEnvDir)) rmSync(runtimeEnvDir, { recursive: true, force: true });
  delete process.env.VIGOLIUM_AUDIT_HARNESS_CLAUDE_DIR;
  delete process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_DIR;
  delete process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_SKILLS_DIR;
  delete process.env.VIGOLIUM_AUDIT_HARNESS_CODEX_AGENTS_MD;
  delete process.env.VIGOLIUM_AUDIT_RUNTIME_SKILLS_DIR;
});

test("managed runtime skills do not occupy the documented user-override directory", () => {
  const configured = process.env.VIGOLIUM_AUDIT_RUNTIME_SKILLS_DIR;
  delete process.env.VIGOLIUM_AUDIT_RUNTIME_SKILLS_DIR;
  try {
    expect(resolveRuntimeSkillsDir()).toBe(
      join(homedir(), ".config", "vigolium-audit", "runtime-skills"),
    );
    expect(resolveRuntimeSkillsDir()).not.toBe(
      join(homedir(), ".config", "vigolium-audit", "skills"),
    );
  } finally {
    if (configured !== undefined) process.env.VIGOLIUM_AUDIT_RUNTIME_SKILLS_DIR = configured;
  }
});

test("migrates the old managed link and preserves a later user override across refresh and uninstall", () => {
  const home = mkdtempSync(join(tmpdir(), "vigolium-audit-override-lifecycle-"));
  const cliEntry = resolve(import.meta.dir, "../../src/index.ts");
  const bundledSkills = resolve(import.meta.dir, "../../src/content/skills");
  const overrideSkills = join(home, ".config", "vigolium-audit", "skills");
  const managedRuntime = join(home, ".config", "vigolium-audit", "runtime-skills");
  const childEnv: NodeJS.ProcessEnv = { ...process.env, HOME: home };
  for (const name of [
    "VIGOLIUM_AUDIT_CONFIG_DIR",
    "VIGOLIUM_AUDIT_HARNESS_CLAUDE_DIR",
    "VIGOLIUM_AUDIT_HARNESS_CODEX_DIR",
    "VIGOLIUM_AUDIT_HARNESS_CODEX_SKILLS_DIR",
    "VIGOLIUM_AUDIT_HARNESS_CODEX_AGENTS_MD",
    "VIGOLIUM_AUDIT_RUNTIME_SKILLS_DIR",
  ]) {
    delete childEnv[name];
  }
  const runCli = (command: "setup" | "uninstall"): void => {
    const result = spawnSync("bun", ["run", cliEntry, command, "claude", "--json"], {
      env: childEnv,
      encoding: "utf8",
    });
    if (result.status !== 0) {
      throw new Error(`${command} failed: ${result.stderr || result.stdout}`);
    }
  };

  try {
    // Reproduce the retired layout: the user-override root itself was a
    // managed link into bundled content. A current setup must remove only this
    // provably managed link and create the separate runtime mount.
    mkdirSync(join(overrideSkills, ".."), { recursive: true });
    symlinkSync(bundledSkills, overrideSkills, "dir");
    runCli("setup");
    expect(existsSync(overrideSkills)).toBe(false);
    expect(readlinkSync(managedRuntime)).toBe(bundledSkills);

    // A user can now follow CUSTOMIZATION.md safely. Simulate a later bundle
    // refresh and verify both refresh and uninstall leave the override intact.
    const customSkill = join(overrideSkills, "audit", "SKILL.md");
    mkdirSync(join(customSkill, ".."), { recursive: true });
    writeFileSync(customSkill, "custom-user-skill\n");
    unlinkSync(managedRuntime);
    const staleBundle = join(home, ".cache", "vigolium-audit", "content-stale", "skills");
    mkdirSync(staleBundle, { recursive: true });
    symlinkSync(staleBundle, managedRuntime, "dir");

    runCli("setup");
    expect(readFileSync(customSkill, "utf8")).toBe("custom-user-skill\n");
    expect(readlinkSync(managedRuntime)).toBe(bundledSkills);

    runCli("uninstall");
    expect(readFileSync(customSkill, "utf8")).toBe("custom-user-skill\n");
    expect(existsSync(managedRuntime)).toBe(false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}, INSTALL_TIMEOUT_MS);

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
    expect(readlinkSync(runtimeSkillsDir)).toContain("src/content/skills");
    const consolidator = readFileSync(join(runtimeSkillsDir, "audit", "scripts", "consolidate_drafts.py"), "utf8");
    expect(consolidator).toContain('Path("vigolium-results")');
    expect(consolidator).not.toContain('Path("archon")');
    const deepCommand = readFileSync(
      join(claudeDir, "commands", "vigolium-audit", "deep.md"),
      "utf8",
    );
    expect(deepCommand).toContain("~/.config/vigolium-audit/runtime-skills/");
    expect(deepCommand).not.toContain("~/.config/vigolium-audit/skills/");

    // Plugin manifest name drives the slash-command namespace: commands under
    // commands/vigolium-audit/ resolve to `/vigolium-audit:vigolium-audit:<cmd>`.
    const manifest = JSON.parse(readFileSync(join(claudeDir, ".claude-plugin", "plugin.json"), "utf8"));
    expect(manifest.name).toBe("vigolium-audit");
  }, INSTALL_TIMEOUT_MS);

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
  }, INSTALL_TIMEOUT_MS);

  test("excluded agents (e.g. deep-reviewer) are not written", async () => {
    await installHarness("claude");
    expect(existsSync(join(claudeDir, "agents", "deep-reviewer.md"))).toBe(false);
  }, INSTALL_TIMEOUT_MS);

  test("commands are namespaced under vigolium-audit/", async () => {
    await installHarness("claude");
    const commands = readdirSync(join(claudeDir, "commands", "vigolium-audit")).sort();
    expect(commands).toContain("deep.md");
    expect(commands).toContain("lite.md");
    expect(commands).toContain("balanced.md");
    expect(commands).toContain("longshot.md");
    expect(commands.length).toBe(10);
  }, INSTALL_TIMEOUT_MS);

  test("idempotent — second install replaces first cleanly", async () => {
    await installHarness("claude");
    const before = readdirSync(join(claudeDir, "agents")).length;
    await installHarness("claude");
    const after = readdirSync(join(claudeDir, "agents")).length;
    expect(after).toBe(before);
  }, INSTALL_TIMEOUT_MS);

  test("replaces a retired runtime-skills symlink with current bundled content", async () => {
    const retiredSkills = join(runtimeEnvDir, "archon-audit", "skills");
    mkdirSync(join(retiredSkills, "audit", "scripts"), { recursive: true });
    writeFileSync(join(retiredSkills, "audit", "scripts", "consolidate_drafts.py"), 'Path("archon")\n');
    symlinkSync(retiredSkills, runtimeSkillsDir, "dir");

    await installHarness("claude");

    expect(readlinkSync(runtimeSkillsDir)).not.toBe(retiredSkills);
    const consolidator = readFileSync(join(runtimeSkillsDir, "audit", "scripts", "consolidate_drafts.py"), "utf8");
    expect(consolidator).toContain('Path("vigolium-results")');
    expect(consolidator).not.toContain('Path("archon")');
  }, INSTALL_TIMEOUT_MS);

  test("uninstall removes the entire plugin dir", async () => {
    await installHarness("claude");
    expect(existsSync(claudeDir)).toBe(true);
    const { removed } = await uninstallHarness("claude");
    expect(removed).toContain(claudeDir);
    expect(existsSync(claudeDir)).toBe(false);
    expect(existsSync(runtimeSkillsDir)).toBe(false);
  }, INSTALL_TIMEOUT_MS);
});

describe("installHarness(codex)", () => {
  test("produces vigolium-audit-<name>.toml files with merged config", async () => {
    const result = await installHarness("codex");
    expect(result.platform).toBe("codex");
    expect(result.agentsInstalled).toBeGreaterThan(20);
    expect(result.excluded).not.toContain("history-miner");
    expect(result.excluded).not.toContain("independent-verifier");
    expect(result.excluded).not.toContain("assumption-breaker");

    expect(existsSync(join(codexDir, "vigolium-audit-independent-verifier.toml"))).toBe(true);
    expect(existsSync(join(codexDir, "vigolium-audit-assumption-breaker.toml"))).toBe(true);
    expect(existsSync(join(codexDir, "vigolium-audit-history-miner.toml"))).toBe(true);

    const advisory = readFileSync(join(codexDir, "vigolium-audit-cve-scout.toml"), "utf8");
    expect(advisory).toContain(`name = 'vigolium-audit:cve-scout'`);
    expect(advisory).toContain(`model = 'gpt-5.4'`);
    expect(advisory).toContain(`sandbox_mode = 'workspace-write'`);
    expect(advisory).toContain("developer_instructions");
    // Body is wrapped in TOML literal-string triple quotes.
    expect(advisory).toMatch(/developer_instructions = '''[\s\S]+'''/);
  }, INSTALL_TIMEOUT_MS);

  test("subagent_overrides win — code-scanner gets danger-full-access", async () => {
    await installHarness("codex");
    const sa = readFileSync(join(codexDir, "vigolium-audit-code-scanner.toml"), "utf8");
    expect(sa).toContain(`sandbox_mode = 'danger-full-access'`);
  }, INSTALL_TIMEOUT_MS);

  test("uninstall removes only vigolium-audit-*.toml files (preserves other agents)", async () => {
    await installHarness("codex");
    // Pre-seed an unrelated codex agent file that uninstall must NOT touch.
    const unrelated = join(codexDir, "user-custom-agent.toml");
    Bun.write(unrelated, "name = 'user-custom'\n");
    await Bun.sleep(10);
    const { removed } = await uninstallHarness("codex");
    expect(removed.length).toBeGreaterThan(0);
    expect(existsSync(unrelated)).toBe(true);
  }, INSTALL_TIMEOUT_MS);

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
  }, INSTALL_TIMEOUT_MS);

  test("rewrites runtime and legacy skill paths to ~/.codex/skills/vigolium-audit- in agent bodies", async () => {
    await installHarness("codex");
    // code-scanner's body references the audit skill via the stable runtime path.
    // The rewrite must redirect that path so the agent's Read tool calls
    // hit the codex install rather than the (possibly missing) prior-binary dir.
    const sa = readFileSync(join(codexDir, "vigolium-audit-code-scanner.toml"), "utf8");
    expect(sa).not.toContain("~/.config/vigolium-audit/skills/");
    expect(sa).not.toContain("~/.config/vigolium-audit/runtime-skills/");
    expect(sa).toContain("~/.codex/skills/vigolium-audit-audit/");
  }, INSTALL_TIMEOUT_MS);

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
  }, INSTALL_TIMEOUT_MS);

  test("AGENTS.md splice preserves user-authored content above and below the block", async () => {
    writeFileSync(codexAgentsMdPath, "# my notes\n\nuser content\n");
    await installHarness("codex");
    const md = readFileSync(codexAgentsMdPath, "utf8");
    expect(md.startsWith("# my notes\n\nuser content\n")).toBe(true);
    expect(md).toContain("# BEGIN vigolium-audit");
  }, INSTALL_TIMEOUT_MS);

  test("AGENTS.md splice is idempotent — second install replaces the block in place", async () => {
    writeFileSync(codexAgentsMdPath, "user prefix\n");
    await installHarness("codex");
    const first = readFileSync(codexAgentsMdPath, "utf8");
    await installHarness("codex");
    const second = readFileSync(codexAgentsMdPath, "utf8");
    // No accumulating duplicate blocks across reinstalls.
    expect((second.match(/# BEGIN vigolium-audit/g) ?? []).length).toBe(1);
    expect(second).toBe(first);
  }, INSTALL_TIMEOUT_MS);

  test("removes the retired dispatch block while preserving user content", async () => {
    const before = "user-a\n\n\n\nuser-b\n\n# BEGIN archon-audit\nold audit instructions\n# END archon-audit\n\nuser suffix\n";
    const outsideLegacyBlock = "user-a\n\n\n\nuser-b\n\n\n\nuser suffix\n";
    writeFileSync(
      codexAgentsMdPath,
      before,
    );

    await installHarness("codex");

    const md = readFileSync(codexAgentsMdPath, "utf8");
    expect(md).not.toContain("# BEGIN archon-audit");
    expect(md).not.toContain("old audit instructions");
    expect(md).toContain("# BEGIN vigolium-audit");
    expect(md.slice(0, md.indexOf("# BEGIN vigolium-audit"))).toBe(
      outsideLegacyBlock + "\n",
    );
  }, INSTALL_TIMEOUT_MS);

  test("uninstall removes the AGENTS.md block and the vigolium-audit-*/ skills", async () => {
    writeFileSync(codexAgentsMdPath, "user-a\n\n\n\nuser-b\n");
    await installHarness("codex");
    expect(existsSync(join(codexSkillsDir, "vigolium-audit-audit"))).toBe(true);

    const { removed } = await uninstallHarness("codex");
    expect(removed.some((p) => p.endsWith("(dispatch block)"))).toBe(true);

    expect(existsSync(join(codexSkillsDir, "vigolium-audit-audit"))).toBe(false);
    expect(existsSync(runtimeSkillsDir)).toBe(false);
    const md = readFileSync(codexAgentsMdPath, "utf8");
    expect(md).not.toContain("# BEGIN vigolium-audit");
    expect(md).toBe("user-a\n\n\n\nuser-b\n");
  }, INSTALL_TIMEOUT_MS);
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
    expect(existsSync(runtimeSkillsDir)).toBe(false);
    // Listener should be removed after cleanup so the `exit` event won't re-trigger it.
    expect(process.listenerCount("exit")).toBe(before);
  }, INSTALL_TIMEOUT_MS);

  test("cleanup is idempotent", async () => {
    const handle = await registerEphemeralHarness("claude");
    handle.cleanup();
    // Second call must not throw — uninstallHarness is also a no-op when dir is gone.
    expect(() => handle.cleanup()).not.toThrow();
  }, INSTALL_TIMEOUT_MS);

  test("preserves a pre-existing persistent install on cleanup (claude)", async () => {
    // Simulate a persistent `vigolium-audit setup claude`.
    await installHarness("claude");
    expect(harnessInstalled("claude")).toBe(true);

    // An interactive run over the top must NOT delete it on exit.
    const handle = await registerEphemeralHarness("claude");
    handle.cleanup();
    expect(existsSync(join(claudeDir, ".claude-plugin", "plugin.json"))).toBe(true);
    expect(existsSync(runtimeSkillsDir)).toBe(true);
  }, INSTALL_TIMEOUT_MS);

  test("preserves a pre-existing persistent install on cleanup (codex)", async () => {
    await installHarness("codex");
    expect(harnessInstalled("codex")).toBe(true);

    const handle = await registerEphemeralHarness("codex");
    handle.cleanup();
    expect(existsSync(join(codexDir, "vigolium-audit-cve-scout.toml"))).toBe(true);
    expect(existsSync(runtimeSkillsDir)).toBe(true);
  }, INSTALL_TIMEOUT_MS);
});

describe("harnessInstalled", () => {
  test("false before install, true after, false again after uninstall", async () => {
    expect(harnessInstalled("claude")).toBe(false);
    expect(harnessInstalled("codex")).toBe(false);

    await installHarness("claude");
    await installHarness("codex");
    expect(harnessInstalled("claude")).toBe(true);
    expect(harnessInstalled("codex")).toBe(true);

    await uninstallHarness("claude");
    expect(existsSync(runtimeSkillsDir)).toBe(true);
    await uninstallHarness("codex");
    expect(harnessInstalled("claude")).toBe(false);
    expect(harnessInstalled("codex")).toBe(false);
    expect(existsSync(runtimeSkillsDir)).toBe(false);
  }, INSTALL_TIMEOUT_MS);

  test("codex cleanup synchronously removes agents, skills, and AGENTS.md block", async () => {
    writeFileSync(codexAgentsMdPath, "user prefix\n");
    const handle = await registerEphemeralHarness("codex");
    expect(existsSync(join(codexDir, "vigolium-audit-cve-scout.toml"))).toBe(true);
    expect(existsSync(join(codexSkillsDir, "vigolium-audit-audit"))).toBe(true);
    expect(readFileSync(codexAgentsMdPath, "utf8")).toContain("# BEGIN vigolium-audit");

    handle.cleanup();

    expect(existsSync(join(codexDir, "vigolium-audit-cve-scout.toml"))).toBe(false);
    expect(existsSync(join(codexSkillsDir, "vigolium-audit-audit"))).toBe(false);
    expect(existsSync(runtimeSkillsDir)).toBe(false);
    expect(readFileSync(codexAgentsMdPath, "utf8")).not.toContain("# BEGIN vigolium-audit");
    expect(readFileSync(codexAgentsMdPath, "utf8")).toContain("user prefix");
  }, INSTALL_TIMEOUT_MS);
});
