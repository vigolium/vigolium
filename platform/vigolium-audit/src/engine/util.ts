/**
 * Drop properties whose value is `undefined` from an object literal.
 *
 * The codebase uses `exactOptionalPropertyTypes`, which forbids setting an
 * optional field to `undefined`. The verbose workaround was `...(x !== undefined
 * ? { field: x } : {})` for each field. Use `compact()` to keep call sites
 * legible while still typechecking under exact-optional:
 *
 *   new Orchestrator({
 *     adapter, loader, targetDir, mode,
 *     ...compact({ maxCost, focus, expectedBehaviors, debug: opts.debug || undefined }),
 *   });
 *
 * Output type makes every property optional with `undefined` excluded, so it
 * spreads cleanly into a target shape with exact-optional fields.
 */
export function compact<T extends Record<string, unknown>>(
  obj: T,
): { [K in keyof T]?: Exclude<T[K], undefined> } {
  const out: Record<string, unknown> = {};
  for (const k in obj) {
    const v = obj[k];
    if (v !== undefined) out[k] = v;
  }
  return out as { [K in keyof T]?: Exclude<T[K], undefined> };
}

/** Round to two decimal places — the canonical USD precision for cost displays. */
export function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

/**
 * Atomic write: stage to `<path>.tmp.<pid>` then rename. Survives a crash
 * mid-write — partial files never appear at the final path. Caller is
 * responsible for ensuring the directory exists.
 */
export async function atomicWrite(path: string, contents: string): Promise<void> {
  const { writeFile, rename, mkdir } = await import("fs/promises");
  const { dirname } = await import("path");
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp.${process.pid}`;
  await writeFile(tmp, contents, "utf8");
  await rename(tmp, path);
}

/**
 * Parse a non-negative integer from an env var, falling back when unset,
 * non-numeric, or negative. Used for the quota-retry knobs
 * (`VIGOLIUM_AUDIT_QUOTA_MAX_RETRIES`, `VIGOLIUM_AUDIT_QUOTA_BACKOFF_MS`).
 */
export function parseIntEnv(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

/**
 * Sleep for `ms` milliseconds, but wake immediately if the abort signal fires.
 * Used for quota-limit waits (default 1h) so SIGINT during the sleep tears down
 * the audit promptly instead of leaving the user staring at a frozen log.
 */
export function sleepInterruptible(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      resolve();
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/** SHA256 of a file's contents, hex-encoded. Returns null when unreadable. */
export async function sha256OfFile(path: string): Promise<string | null> {
  const { readFile } = await import("fs/promises");
  const { createHash } = await import("crypto");
  try {
    const buf = await readFile(path);
    return createHash("sha256").update(buf).digest("hex");
  } catch {
    return null;
  }
}
