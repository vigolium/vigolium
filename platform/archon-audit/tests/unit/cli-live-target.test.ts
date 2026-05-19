import { describe, expect, test } from "bun:test";
import { resolve } from "path";

const CLI_ENTRY = resolve(import.meta.dir, "../../src/index.ts");

async function runCli(args: string[]): Promise<{ exitCode: number; stderr: string }> {
  const proc = Bun.spawn(["bun", "run", CLI_ENTRY, ...args], {
    stdout: "pipe",
    stderr: "pipe",
    // Strip ARCHON_* envs so the test doesn't trip on auth-override / binary-path
    // configuration from the developer's shell. Validation we're testing fires
    // before any of that, but keeping the env minimal makes failures unambiguous.
    env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "" },
  });
  const exitCode = await proc.exited;
  const stderr = await new Response(proc.stderr).text();
  return { exitCode, stderr };
}

describe("--live-target CLI validation", () => {
  test("rejects --live-target on a non-confirm mode", async () => {
    const { exitCode, stderr } = await runCli([
      "run",
      "--mode",
      "lite",
      "--live-target",
      "https://staging.example.com",
    ]);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("--live-target is only supported with --mode confirm");
  });

  test("rejects a non-http(s) scheme", async () => {
    const { exitCode, stderr } = await runCli([
      "run",
      "--mode",
      "confirm",
      "--live-target",
      "ftp://staging.example.com",
    ]);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("must be an http:// or https:// URL");
  });
});
