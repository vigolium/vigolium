import { spawn } from "child_process";

export interface SandboxRunInput {
  /** Path to the script to execute. Must exist on disk. */
  script: string;
  /** Working directory. The script cannot access files outside this dir
   *  unless the OS-level FS permission allows it; we don't enforce that. */
  cwd: string;
  /** Hard timeout in ms. */
  timeoutMs?: number;
  /** Extra env vars to set on top of the allowlist. */
  extraEnv?: Record<string, string>;
  /** Override the env allowlist; default is a small safe set. */
  envAllowlist?: string[];
  /** Optional shell to invoke; defaults to `/bin/sh`. */
  shell?: string;
  /** AbortSignal to cancel a running script. */
  abortSignal?: AbortSignal;
}

export interface SandboxRunResult {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

const DEFAULT_ENV_ALLOWLIST = ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ"];

/**
 * Run a script under a constrained child process. Used by `confirm` mode for
 * PoC execution. Constraints applied:
 *
 * 1. **Env allowlist** — by default, inherits only PATH/HOME/TMPDIR/LANG/LC_ALL/TZ
 *    from the parent. No API keys, no SSH agents, no GitHub tokens.
 * 2. **CWD lock** — the child runs with `cwd` as its working directory. We
 *    do *not* enforce filesystem isolation; the script can still read/write
 *    paths outside cwd if the OS allows it. Documented threat model:
 *    *not* a security boundary against malicious PoCs — review before running.
 * 3. **Timeout** — hard kill after `timeoutMs`.
 * 4. **No stdin** — closed immediately to avoid blocking on user input.
 */
export async function runSandboxedScript(input: SandboxRunInput): Promise<SandboxRunResult> {
  const startedAt = Date.now();
  const timeoutMs = input.timeoutMs ?? 60_000;
  const allowlist = input.envAllowlist ?? DEFAULT_ENV_ALLOWLIST;

  const env: Record<string, string> = {};
  for (const key of allowlist) {
    const v = process.env[key];
    if (v !== undefined) env[key] = v;
  }
  Object.assign(env, input.extraEnv ?? {});
  // Mark sandboxed runs so PoCs can detect they're under vigolium-audit.
  env.VIGOLIUM_AUDIT_SANDBOX = "1";

  const child = spawn(input.shell ?? "/bin/sh", [input.script], {
    cwd: input.cwd,
    env,
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });

  const killGroup = (signal: NodeJS.Signals): void => {
    if (child.pid !== undefined) {
      try {
        process.kill(-child.pid, signal);
      } catch {
        try {
          child.kill(signal);
        } catch {
          /* already dead */
        }
      }
    }
  };

  let timedOut = false;
  const killTimer = setTimeout(() => {
    timedOut = true;
    killGroup("SIGKILL");
  }, timeoutMs);

  if (input.abortSignal) {
    const onAbort = (): void => {
      killGroup("SIGTERM");
    };
    if (input.abortSignal.aborted) onAbort();
    else input.abortSignal.addEventListener("abort", onAbort, { once: true });
  }

  const stdoutBuf: Buffer[] = [];
  const stderrBuf: Buffer[] = [];
  const stdoutLimit = 1024 * 1024;
  const stderrLimit = 1024 * 1024;
  let stdoutSize = 0;
  let stderrSize = 0;

  child.stdout?.on("data", (chunk: Buffer) => {
    if (stdoutSize < stdoutLimit) {
      stdoutBuf.push(chunk);
      stdoutSize += chunk.length;
    }
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    if (stderrSize < stderrLimit) {
      stderrBuf.push(chunk);
      stderrSize += chunk.length;
    }
  });

  const result = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code, signal) => resolve({ code, signal }));
  });

  clearTimeout(killTimer);

  return {
    exitCode: result.code,
    signal: result.signal,
    stdout: Buffer.concat(stdoutBuf).toString("utf8"),
    stderr: Buffer.concat(stderrBuf).toString("utf8"),
    durationMs: Date.now() - startedAt,
    timedOut,
  };
}
