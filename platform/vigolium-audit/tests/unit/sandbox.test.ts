import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync, chmodSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { runSandboxedScript } from "../../src/engine/sandbox.js";

function makeScript(contents: string): { path: string; cwd: string } {
  const cwd = mkdtempSync(join(tmpdir(), "vigolium-audit-sandbox-"));
  const path = join(cwd, "script.sh");
  writeFileSync(path, contents);
  chmodSync(path, 0o755);
  return { path, cwd };
}

describe("runSandboxedScript", () => {
  test("runs a basic script and captures stdout/stderr", async () => {
    const { path, cwd } = makeScript('echo "hello"\necho "warn" >&2\nexit 0\n');
    const result = await runSandboxedScript({ script: path, cwd });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("hello");
    expect(result.stderr).toContain("warn");
    expect(result.timedOut).toBe(false);
  });

  test("returns non-zero exit code on script failure", async () => {
    const { path, cwd } = makeScript("exit 42\n");
    const result = await runSandboxedScript({ script: path, cwd });
    expect(result.exitCode).toBe(42);
  });

  test("env allowlist drops untrusted vars by default", async () => {
    const { path, cwd } = makeScript('echo "secret=$ANTHROPIC_API_KEY"\necho "path=$PATH"\n');
    const result = await runSandboxedScript({
      script: path,
      cwd,
      extraEnv: { ANTHROPIC_API_KEY: "sk-should-not-leak-but-also-overridden" },
    });
    // extraEnv is allowed even if the key isn't in the allowlist by default.
    expect(result.stdout).toContain("secret=sk-should-not-leak-but-also-overridden");
    // PATH inherited via the default allowlist.
    expect(result.stdout).toContain("path=");
  });

  test("env allowlist excludes parent vars not on the list", async () => {
    process.env.VIGOLIUM_AUDIT_TEST_LEAK = "should-not-be-visible";
    const { path, cwd } = makeScript('echo "leak=${VIGOLIUM_AUDIT_TEST_LEAK:-empty}"\n');
    const result = await runSandboxedScript({ script: path, cwd });
    expect(result.stdout).toContain("leak=empty");
    delete process.env.VIGOLIUM_AUDIT_TEST_LEAK;
  });

  test("VIGOLIUM_AUDIT_SANDBOX=1 is set so PoCs can detect the sandbox", async () => {
    const { path, cwd } = makeScript('echo "sandbox=$VIGOLIUM_AUDIT_SANDBOX"\n');
    const result = await runSandboxedScript({ script: path, cwd });
    expect(result.stdout).toContain("sandbox=1");
  });

  test("timeout kills a long-running script", async () => {
    const { path, cwd } = makeScript("sleep 5\n");
    const result = await runSandboxedScript({ script: path, cwd, timeoutMs: 200 });
    expect(result.timedOut).toBe(true);
    expect(result.signal).toBe("SIGKILL");
  });

  test("AbortSignal terminates the script", async () => {
    const { path, cwd } = makeScript("sleep 5\n");
    const ac = new AbortController();
    const promise = runSandboxedScript({ script: path, cwd, abortSignal: ac.signal });
    setTimeout(() => ac.abort(), 50);
    const result = await promise;
    expect(result.signal).toBe("SIGTERM");
  });
});
