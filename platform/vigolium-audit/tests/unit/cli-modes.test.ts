import { describe, expect, test } from "bun:test";
import { resolve } from "path";
import { isResumeAlias, resolveRequestedModes } from "../../src/cli/run.js";
import type { RunOptions } from "../../src/engine/types.js";

const CLI_ENTRY = resolve(import.meta.dir, "../../src/index.ts");

function opts(o: Partial<RunOptions>): RunOptions {
  return { target: ".", ...o };
}

describe("resolveRequestedModes", () => {
  test("defaults to ['lite'] when neither flag is set", () => {
    expect(resolveRequestedModes(opts({}))).toEqual(["lite"]);
  });

  test("returns single mode from --mode", () => {
    expect(resolveRequestedModes(opts({ mode: "deep" }))).toEqual(["deep"]);
  });

  test("splits --modes on commas and trims whitespace", () => {
    expect(resolveRequestedModes(opts({ modes: "deep, refresh ,confirm" }))).toEqual([
      "deep",
      "refresh",
      "confirm",
    ]);
  });

  test("rejects --mode + --modes together", () => {
    expect(() => resolveRequestedModes(opts({ mode: "deep", modes: "refresh,confirm" }))).toThrow(
      /mutually exclusive/,
    );
  });

  test("rejects an empty --modes value", () => {
    expect(() => resolveRequestedModes(opts({ modes: " , ," }))).toThrow(/empty/);
  });

  test("rejects an unknown mode in --modes", () => {
    expect(() => resolveRequestedModes(opts({ modes: "deep,nope,confirm" }))).toThrow(
      /invalid mode "nope"/,
    );
  });

  test("rejects an unknown --mode", () => {
    expect(() => resolveRequestedModes(opts({ mode: "bogus" as never }))).toThrow(
      /--mode must be one of/,
    );
  });

  test("allows duplicate modes (caller's intent)", () => {
    expect(resolveRequestedModes(opts({ modes: "deep,deep" }))).toEqual(["deep", "deep"]);
  });
});

describe("isResumeAlias", () => {
  test("true for --mode resume", () => {
    expect(isResumeAlias(opts({ mode: "resume" as never }))).toBe(true);
  });

  test("true for --modes resume (single, whitespace-tolerant)", () => {
    expect(isResumeAlias(opts({ modes: "  resume " }))).toBe(true);
  });

  test("false for a real mode", () => {
    expect(isResumeAlias(opts({ mode: "deep" }))).toBe(false);
  });

  test("false when resume is mixed into a multi-mode chain", () => {
    expect(isResumeAlias(opts({ modes: "deep,resume" }))).toBe(false);
  });

  test("false when neither flag is set", () => {
    expect(isResumeAlias(opts({}))).toBe(false);
  });
});

async function runCli(args: string[]): Promise<{ exitCode: number; stderr: string }> {
  const proc = Bun.spawn(["bun", "run", CLI_ENTRY, ...args], {
    stdout: "pipe",
    stderr: "pipe",
    env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "" },
  });
  const exitCode = await proc.exited;
  const stderr = await new Response(proc.stderr).text();
  return { exitCode, stderr };
}

describe("--modes CLI validation", () => {
  test("rejects SDK transport with native interactive mode", async () => {
    const { exitCode, stderr } = await runCli([
      "run",
      "--mode",
      "deep",
      "--agent",
      "codex",
      "--transport",
      "sdk",
      "-i",
    ]);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("interactive mode uses the native agent CLI");
  });

  test("rejects Codex interactive modes that have no AGENTS.md dispatch", async () => {
    const { exitCode, stderr } = await runCli([
      "run",
      "--mode",
      "merge",
      "--agent",
      "codex",
      "-i",
    ]);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("has no Codex interactive dispatch");
    expect(stderr).toContain("Run without -i");
  });

  test("rejects -i with --modes (chain is headless-only)", async () => {
    const { exitCode, stderr } = await runCli(["run", "-i", "--modes", "deep,refresh,confirm"]);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("headless-only");
  });

  test("rejects --live-target with a chain (only --mode confirm)", async () => {
    const { exitCode, stderr } = await runCli([
      "run",
      "--modes",
      "deep,confirm",
      "--live-target",
      "https://staging.example.com",
    ]);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("--live-target is only supported with --mode confirm");
  });

  test("rejects --mode + --modes together", async () => {
    const { exitCode, stderr } = await runCli(["run", "--mode", "deep", "--modes", "refresh,confirm"]);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("mutually exclusive");
  });

  test("rejects an unknown mode in --modes", async () => {
    const { exitCode, stderr } = await runCli(["run", "--modes", "deep,bogus"]);
    expect(exitCode).toBe(2);
    expect(stderr).toContain('invalid mode "bogus"');
  });
});
