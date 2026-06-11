import { describe, expect, test } from "bun:test";
import { spawnAndStream, type CliStreamItem } from "../../src/adapters/cli-process.js";

async function collect<T>(stream: AsyncGenerator<CliStreamItem<T>>): Promise<CliStreamItem<T>[]> {
  const out: CliStreamItem<T>[] = [];
  for await (const item of stream) out.push(item);
  return out;
}

const CWD = process.cwd();

describe("spawnAndStream", () => {
  test("yields one item per non-empty stdout line, then exit", async () => {
    const { stream } = spawnAndStream({
      command: "sh",
      args: ["-c", "printf 'a\\nb\\n\\nc\\n'"],
      cwd: CWD,
      stdin: "",
    });
    const items = await collect(stream);
    const lines = items.filter((i) => i.kind === "line").map((i) => (i as { line: string }).line);
    expect(lines).toEqual(["a", "b", "c"]);
    const exit = items.at(-1);
    expect(exit?.kind).toBe("exit");
    expect((exit as { exitCode: number }).exitCode).toBe(0);
  });

  test("captures non-zero exit code and stderr", async () => {
    const { stream } = spawnAndStream({
      command: "sh",
      args: ["-c", "echo boom 1>&2; exit 7"],
      cwd: CWD,
      stdin: "",
    });
    const items = await collect(stream);
    const exit = items.at(-1) as { kind: string; exitCode: number; stderr: string; crashed: Error | null };
    expect(exit.kind).toBe("exit");
    expect(exit.exitCode).toBe(7);
    expect(exit.stderr).toContain("boom");
    expect(exit.crashed).toBeNull();
  });

  test("forwards stdin to the child", async () => {
    const { stream } = spawnAndStream({
      command: "cat",
      args: [],
      cwd: CWD,
      stdin: "from-stdin\n",
    });
    const items = await collect(stream);
    const lines = items.filter((i) => i.kind === "line").map((i) => (i as { line: string }).line);
    expect(lines).toEqual(["from-stdin"]);
  });

  test("reports a spawn failure as crashed (not a thrown exception)", async () => {
    const { stream } = spawnAndStream({
      command: "this-binary-does-not-exist-vigolium",
      args: [],
      cwd: CWD,
      stdin: "",
    });
    const items = await collect(stream);
    const exit = items.at(-1) as { kind: string; crashed: Error | null };
    expect(exit.kind).toBe("exit");
    expect(exit.crashed).toBeInstanceOf(Error);
  });

  test("interleaves injected extras and flushes them in onBeforeExit", async () => {
    let injectFn: ((v: string) => void) | null = null;
    const { stream, inject } = spawnAndStream<string>({
      command: "sh",
      args: ["-c", "printf 'line\\n'"],
      cwd: CWD,
      stdin: "",
      onBeforeExit: () => {
        injectFn?.("trailing");
      },
    });
    injectFn = inject;
    const items = await collect(stream);
    const extras = items.filter((i) => i.kind === "extra").map((i) => (i as { value: string }).value);
    expect(extras).toContain("trailing");
    // The trailing extra must arrive before the terminal exit item.
    const exitIdx = items.findIndex((i) => i.kind === "exit");
    const extraIdx = items.findIndex((i) => i.kind === "extra" && (i as { value: string }).value === "trailing");
    expect(extraIdx).toBeLessThan(exitIdx);
  });

  test("aborts the child when the abort signal fires", async () => {
    const ac = new AbortController();
    const { stream } = spawnAndStream({
      command: "sh",
      args: ["-c", "sleep 30"],
      cwd: CWD,
      stdin: "",
      abortSignal: ac.signal,
    });
    setTimeout(() => ac.abort(), 50);
    const items = await collect(stream);
    // The child is killed; we still terminate with an exit item rather than hang.
    expect(items.at(-1)?.kind).toBe("exit");
  });
});
