import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";
import type { ThreadEvent, ThreadOptions } from "@openai/codex-sdk";
import {
  CodexSdkAdapter,
  resolveCodexClientOptions,
  type CodexSdkClient,
} from "../../src/adapters/codex-sdk.js";
import { chooseAdapter, resolveAgentTransport } from "../../src/adapters/detect.js";
import type { AdapterEvent } from "../../src/adapters/adapter.js";
import { buildCodexInteractiveInvocation } from "../../src/cli/run-interactive.js";
import { buildCodexTriggerPrompt } from "../../src/engine/codex-handoff.js";

const CLI_ENTRY = resolve(import.meta.dir, "../../src/index.ts");
let codexHome: string;
let originalApiKey: string | undefined;

beforeEach(() => {
  codexHome = mkdtempSync(join(tmpdir(), "vigolium-audit-codex-home-"));
  process.env.CODEX_HOME = codexHome;
  originalApiKey = process.env.OPENAI_API_KEY;
  delete process.env.OPENAI_API_KEY;
});

afterEach(() => {
  rmSync(codexHome, { recursive: true, force: true });
  delete process.env.CODEX_HOME;
  if (originalApiKey === undefined) delete process.env.OPENAI_API_KEY;
  else process.env.OPENAI_API_KEY = originalApiKey;
});

describe("Codex transport selection", () => {
  test("auto prefers the Codex Agent SDK with ambient CLI auth", () => {
    expect(chooseAdapter("codex", "auto").flavor).toBe("sdk");
    expect(chooseAdapter("codex", "cli").flavor).toBe("cli");
    expect(chooseAdapter("codex", "sdk").flavor).toBe("sdk");
  });

  test("validates transport values", () => {
    expect(resolveAgentTransport(undefined)).toBe("auto");
    expect(() => resolveAgentTransport("both")).toThrow(/auto.*sdk.*cli/);
  });
});

describe("Codex canonical interactive prompt", () => {
  test("every dispatch-backed mode receives its canonical trigger", () => {
    const cases = [
      ["lite", "Lite mode: L1-L3"],
      ["balanced", "Balanced mode: B1-B9"],
      ["deep", "Full deep mode"],
      ["revisit", "Revisit mode"],
      ["confirm", "Confirm mode"],
    ] as const;
    for (const [mode, trigger] of cases) {
      const invocation = buildCodexInteractiveInvocation({ mode, targetDir: "/tmp/repo" });
      expect(invocation.prompt).toStartWith(`${trigger}.\n`);
      expect(invocation.args.at(-1)).toBe(invocation.prompt);
    }
  });

  test("deep -i passes Full deep mode as a positional startup prompt", () => {
    const invocation = buildCodexInteractiveInvocation({
      mode: "deep",
      targetDir: "/tmp/target repo",
      model: "gpt-5.4",
    });
    expect(invocation.prompt).toStartWith("Full deep mode.\n");
    expect(invocation.prompt).toContain("Dispatch authority: `~/.codex/AGENTS.md`");
    expect(invocation.args).toEqual(["--model", "gpt-5.4", invocation.prompt]);
    expect(invocation.prompt).toBe(
      buildCodexTriggerPrompt({ mode: "deep", targetDir: "/tmp/target repo" }),
    );
  });

  test("confirm prompt carries the live target", () => {
    const invocation = buildCodexInteractiveInvocation({
      mode: "confirm",
      targetDir: "/tmp/repo",
      liveTarget: "https://staging.example.com",
    });
    expect(invocation.prompt).toStartWith("Confirm mode.\n");
    expect(invocation.prompt).toContain("Live target: https://staging.example.com");
  });

  test("rejects modes that are not represented in the Codex AGENTS.md dispatch", () => {
    for (const mode of ["diff", "merge", "reinvest", "longshot", "refresh"] as const) {
      expect(() => buildCodexInteractiveInvocation({ mode, targetDir: "/tmp/repo" }))
        .toThrow(/no AGENTS\.md dispatch/);
      expect(() => buildCodexTriggerPrompt({ mode, targetDir: "/tmp/repo" }))
        .toThrow(/does not support mode/);
    }
  });
});

describe("Codex SDK adapter", () => {
  test("forwards an explicit key and falls back to OPENAI_API_KEY", () => {
    process.env.OPENAI_API_KEY = "env-key";
    expect(resolveCodexClientOptions({}).apiKey).toBe("env-key");
    expect(resolveCodexClientOptions({ apiKey: "one-shot-key" }).apiKey).toBe("one-shot-key");
  });

  test("uses resumeThread and does not replay historical subagent events", async () => {
    const threadId = "thread-resume-123";
    const sessionDir = join(codexHome, "sessions", "2026", "07", "11");
    mkdirSync(sessionDir, { recursive: true });
    const sessionFile = join(sessionDir, `rollout-${threadId}.jsonl`);
    writeFileSync(sessionFile, sessionCall("old-call", "spawn_agent") + "\n");

    let startCalls = 0;
    let resumeCalls = 0;
    let resumedOptions: ThreadOptions | undefined;
    const fakeThread = {
      runStreamed: async () => ({
        events: (async function* (): AsyncGenerator<ThreadEvent> {
          appendFileSync(sessionFile, sessionCall("new-call", "wait_agent") + "\n");
          await Bun.sleep(550);
          yield { type: "turn.completed", usage: emptyUsage() };
        })(),
      }),
    };
    const client = {
      startThread: () => {
        startCalls++;
        return fakeThread;
      },
      resumeThread: (id: string, options?: ThreadOptions) => {
        expect(id).toBe(threadId);
        resumeCalls++;
        resumedOptions = options;
        return fakeThread;
      },
    } as unknown as CodexSdkClient;

    const adapter = new CodexSdkAdapter({}, client);
    const events = await collect(adapter.run({
      userPrompt: "continue",
      cwd: "/tmp/repo",
      resume: threadId,
      bypassPermissions: true,
    }));

    expect(startCalls).toBe(0);
    expect(resumeCalls).toBe(1);
    expect(resumedOptions?.sandboxMode).toBe("danger-full-access");
    expect(events.some((event) => event.kind === "toolCall" && event.id === "old-call")).toBe(false);
    expect(events.some((event) => event.kind === "toolCall" && event.id === "new-call")).toBe(true);
    expect(events.at(-1)?.kind).toBe("finish");
  });

  test("keeps a successful turn successful when the optional session log becomes unreadable", async () => {
    const threadId = "thread-tail-io-failure";
    const sessionDir = join(codexHome, "sessions", "2026", "07", "11");
    mkdirSync(sessionDir, { recursive: true });
    const sessionFile = join(sessionDir, `rollout-${threadId}.jsonl`);
    writeFileSync(sessionFile, "{}\n");

    const fakeThread = {
      runStreamed: async () => ({
        events: (async function* (): AsyncGenerator<ThreadEvent> {
          yield { type: "thread.started", thread_id: threadId };
          // Let the tail discover the regular file, then replace it with a
          // directory so its next read deterministically fails with EISDIR.
          await Bun.sleep(50);
          rmSync(sessionFile);
          mkdirSync(sessionFile);
          yield { type: "turn.completed", usage: emptyUsage() };
        })(),
      }),
    };
    const client = {
      startThread: () => fakeThread,
      resumeThread: () => fakeThread,
    } as unknown as CodexSdkClient;

    const events = await collect(new CodexSdkAdapter({}, client).run({
      userPrompt: "continue",
      cwd: "/tmp/repo",
    }));

    expect(events.some((event) => event.kind === "error")).toBe(false);
    expect(events.at(-1)?.kind).toBe("finish");
  });
});

describe("Codex dry-run contract", () => {
  test("deep resolves to one AGENTS.md handoff", async () => {
    const proc = Bun.spawn([
      "bun",
      "run",
      CLI_ENTRY,
      "run",
      "--mode",
      "deep",
      "--agent",
      "codex",
      "--transport",
      "sdk",
      "--dry-run",
      "--json",
    ], { stdout: "pipe", stderr: "pipe" });
    expect(await proc.exited).toBe(0);
    const payload = JSON.parse(await new Response(proc.stdout).text());
    expect(payload.transport).toBe("sdk");
    expect(payload.plans[0].execution).toBe("codex-handoff");
    expect(payload.plans[0].phases).toHaveLength(1);
    expect(payload.plans[0].phases[0].id).toBe("handoff");
    expect(payload.plans[0].commandSourcePath).toEndWith("harnesses/codex/agents-dispatch.md");
  });
});

async function collect(events: AsyncIterable<AdapterEvent>): Promise<AdapterEvent[]> {
  const result: AdapterEvent[] = [];
  for await (const event of events) result.push(event);
  return result;
}

function sessionCall(callId: string, name: string): string {
  return JSON.stringify({
    type: "response_item",
    payload: { type: "function_call", name, call_id: callId, arguments: "{}" },
  });
}

function emptyUsage(): {
  input_tokens: number;
  cached_input_tokens: number;
  output_tokens: number;
  reasoning_output_tokens: number;
} {
  return {
    input_tokens: 0,
    cached_input_tokens: 0,
    output_tokens: 0,
    reasoning_output_tokens: 0,
  };
}
