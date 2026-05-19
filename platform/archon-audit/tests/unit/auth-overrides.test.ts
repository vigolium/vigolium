import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir, homedir } from "os";
import { join } from "path";
import { applyAuthOverrides, platformApiKeyEnv, platformCredFilePath } from "../../src/engine/auth-overrides.js";

const ENV_KEYS = ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"];
const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

describe("auth-overrides: env mutations", () => {
  test("--oauth-token sets CLAUDE_CODE_OAUTH_TOKEN; restore reverts", () => {
    delete process.env["CLAUDE_CODE_OAUTH_TOKEN"];
    const h = applyAuthOverrides({ platform: "claude", oauthToken: "sk-ant-oat01-fake" });
    expect(process.env["CLAUDE_CODE_OAUTH_TOKEN"]).toBe("sk-ant-oat01-fake");
    h.restore();
    expect(process.env["CLAUDE_CODE_OAUTH_TOKEN"]).toBeUndefined();
  });

  test("--api-key on claude sets ANTHROPIC_API_KEY (not OPENAI_API_KEY)", () => {
    delete process.env["ANTHROPIC_API_KEY"];
    delete process.env["OPENAI_API_KEY"];
    const h = applyAuthOverrides({ platform: "claude", apiKey: "sk-ant-test" });
    expect(process.env["ANTHROPIC_API_KEY"]).toBe("sk-ant-test");
    expect(process.env["OPENAI_API_KEY"]).toBeUndefined();
    h.restore();
    expect(process.env["ANTHROPIC_API_KEY"]).toBeUndefined();
  });

  test("--api-key on codex sets OPENAI_API_KEY (not ANTHROPIC_API_KEY)", () => {
    delete process.env["ANTHROPIC_API_KEY"];
    delete process.env["OPENAI_API_KEY"];
    const h = applyAuthOverrides({ platform: "codex", apiKey: "sk-openai-test" });
    expect(process.env["OPENAI_API_KEY"]).toBe("sk-openai-test");
    expect(process.env["ANTHROPIC_API_KEY"]).toBeUndefined();
    h.restore();
    expect(process.env["OPENAI_API_KEY"]).toBeUndefined();
  });

  test("restore preserves a pre-existing env value (does not delete it)", () => {
    process.env["ANTHROPIC_API_KEY"] = "pre-existing-key";
    const h = applyAuthOverrides({ platform: "claude", apiKey: "override-key" });
    expect(process.env["ANTHROPIC_API_KEY"]).toBe("override-key");
    h.restore();
    expect(process.env["ANTHROPIC_API_KEY"]).toBe("pre-existing-key");
  });

  test("restore is idempotent", () => {
    const h = applyAuthOverrides({ platform: "claude", oauthToken: "tok" });
    h.restore();
    expect(() => h.restore()).not.toThrow();
  });

  test("summary redacts secrets", () => {
    const h = applyAuthOverrides({
      platform: "claude",
      oauthToken: "sk-ant-oat01-1RrtrzWa3C6w12Yabepy",
      apiKey: "sk-ant-test-1234567890abcdef",
    });
    const s = h.summary();
    expect(s).not.toContain("1RrtrzWa3C6w12Yabepy");
    expect(s).not.toContain("1234567890abcdef");
    expect(s).toContain("CLAUDE_CODE_OAUTH_TOKEN=");
    expect(s).toContain("ANTHROPIC_API_KEY=");
    h.restore();
  });
});

describe("auth-overrides: cred file swap", () => {
  let tmpHome: string;
  let codexCredsTarget: string;
  let claudeCredsTarget: string;
  // Files this test created — cleaned up unconditionally on afterEach so a
  // failed assertion can't leak fake creds into the real ~/.claude or ~/.codex.
  const ownedPaths = new Set<string>();

  const trackForCleanup = (path: string): string => {
    ownedPaths.add(path);
    ownedPaths.add(`${path}.archon-backup`);
    return path;
  };

  beforeEach(() => {
    tmpHome = mkdtempSync(join(tmpdir(), "archon-auth-"));
    codexCredsTarget = platformCredFilePath("codex");
    claudeCredsTarget = platformCredFilePath("claude");
  });

  afterEach(() => {
    if (existsSync(tmpHome)) rmSync(tmpHome, { recursive: true, force: true });
    for (const p of ownedPaths) rmSync(p, { force: true });
    ownedPaths.clear();
  });

  test("swap-and-restore: backs up existing target, replaces with override, restores on .restore()", () => {
    // Use a sandboxed target by temporarily overriding HOME via process.env? No
    // — applyAuthOverrides imports homedir() once. Instead we build a tiny
    // simulator by writing into a fake target path and asserting the function
    // operates on that path. Since the production helper uses platform-fixed
    // paths, we simulate via the documented platform path. To avoid real-creds
    // collision, skip this test when the user's actual claude creds file exists.
    if (existsSync(claudeCredsTarget)) return; // skip when real creds are installed
    mkdirSync(join(homedir(), ".claude"), { recursive: true });
    trackForCleanup(claudeCredsTarget);
    writeFileSync(claudeCredsTarget, JSON.stringify({ original: true }));

    const overridePath = join(tmpHome, "override.json");
    writeFileSync(overridePath, JSON.stringify({ override: true }));

    const h = applyAuthOverrides({ platform: "claude", oauthCredFile: overridePath });
    try {
      const swapped = JSON.parse(readFileSync(claudeCredsTarget, "utf8"));
      expect(swapped.override).toBe(true);
      expect(existsSync(`${claudeCredsTarget}.archon-backup`)).toBe(true);
    } finally {
      h.restore();
    }
    const restored = JSON.parse(readFileSync(claudeCredsTarget, "utf8"));
    expect(restored.original).toBe(true);
    expect(existsSync(`${claudeCredsTarget}.archon-backup`)).toBe(false);
  });

  test("swap when no prior target: removes override file on restore (no backup to restore)", () => {
    if (existsSync(codexCredsTarget)) return;
    mkdirSync(join(homedir(), ".codex"), { recursive: true });
    trackForCleanup(codexCredsTarget);

    const overridePath = join(tmpHome, "codex-override.json");
    writeFileSync(overridePath, JSON.stringify({ token: "fake" }));

    const h = applyAuthOverrides({ platform: "codex", oauthCredFile: overridePath });
    try {
      expect(existsSync(codexCredsTarget)).toBe(true);
    } finally {
      h.restore();
    }
    expect(existsSync(codexCredsTarget)).toBe(false);
  });

  test("missing source file throws and leaves target untouched", () => {
    expect(() =>
      applyAuthOverrides({ platform: "codex", oauthCredFile: "/tmp/does-not-exist-xyz.json" }),
    ).toThrow(/file not found/);
  });

  test("src === target is a no-op: file is preserved, no backup created", () => {
    if (existsSync(codexCredsTarget)) return;
    mkdirSync(join(homedir(), ".codex"), { recursive: true });
    trackForCleanup(codexCredsTarget);
    writeFileSync(codexCredsTarget, JSON.stringify({ original: true }));

    // Pass the platform's own cred path as the override — common when the
    // user types `--oauth-cred-file ~/.codex/auth.json`.
    const h = applyAuthOverrides({ platform: "codex", oauthCredFile: codexCredsTarget });
    try {
      expect(existsSync(codexCredsTarget)).toBe(true);
      expect(existsSync(`${codexCredsTarget}.archon-backup`)).toBe(false);
      const contents = JSON.parse(readFileSync(codexCredsTarget, "utf8"));
      expect(contents.original).toBe(true);
      expect(h.summary()).toContain("already in place");
    } finally {
      h.restore();
    }
    // After restore the file is still there, untouched.
    expect(existsSync(codexCredsTarget)).toBe(true);
    const after = JSON.parse(readFileSync(codexCredsTarget, "utf8"));
    expect(after.original).toBe(true);
  });

  test("stale backup blocks new override (signals prior crash)", () => {
    if (existsSync(claudeCredsTarget)) return;
    mkdirSync(join(homedir(), ".claude"), { recursive: true });
    trackForCleanup(claudeCredsTarget);
    writeFileSync(`${claudeCredsTarget}.archon-backup`, "{}");

    const overridePath = join(tmpHome, "override.json");
    writeFileSync(overridePath, "{}");

    expect(() =>
      applyAuthOverrides({ platform: "claude", oauthCredFile: overridePath }),
    ).toThrow(/stale backup/);
  });
});

describe("platform helpers", () => {
  test("platformApiKeyEnv maps correctly", () => {
    expect(platformApiKeyEnv("claude")).toBe("ANTHROPIC_API_KEY");
    expect(platformApiKeyEnv("codex")).toBe("OPENAI_API_KEY");
  });

  test("platformCredFilePath points at the right file per platform", () => {
    expect(platformCredFilePath("claude")).toContain(".claude/.credentials.json");
    expect(platformCredFilePath("codex")).toContain(".codex/auth.json");
  });
});
