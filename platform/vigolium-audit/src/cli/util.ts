import chalk from "chalk";

/**
 * Exit with a user-facing error message. In JSON mode emits a single object on
 * stdout so consumers can parse it; in human mode prints to stderr in red.
 *
 * `kind` is the NDJSON kind tag (e.g. "status", "explain", "fatal") — present
 * only on the JSON shape; ignored by the human path.
 */
export function failCli(opts: { json?: boolean }, kind: string, msg: string, exit = 2): never {
  if (opts.json) {
    process.stdout.write(JSON.stringify({ kind, ok: false, error: msg }) + "\n");
  } else {
    process.stderr.write(chalk.red(`error: ${msg}`) + "\n");
  }
  process.exit(exit);
}

/**
 * Parse a `--max-cost` USD cap. `cac` delivers option values as strings, but
 * `RunOptions.maxCost` is typed `number`, so callers may hand us either. Returns
 * the parsed value when it's a finite positive number, or `null` for anything
 * non-numeric, non-finite, or `<= 0`. Callers turn `null` into a user-facing
 * error rather than silently dropping the cap — a mistyped `--max-cost` must
 * never leave an audit running uncapped.
 */
export function parsePositiveUsd(raw: number | string): number | null {
  const n = typeof raw === "number" ? raw : Number(raw);
  return Number.isFinite(n) && n > 0 ? n : null;
}

const STATUS_ARROW_COLORS: Record<string, (s: string) => string> = {
  Platform: chalk.cyan,
  Adapter: chalk.magenta,
  Mode: chalk.green,
  Target: chalk.blue,
  Git: chalk.yellow,
  Model: chalk.magenta,
  Resume: chalk.green,
  Session: chalk.cyan,
  Audit: chalk.cyan,
  Loaded: chalk.blue,
};

/** Status-section row prefix. Each known label gets its own arrow color so the
 *  header block reads at a glance; unknown labels fall back to blue. Accepts
 *  the label with or without a trailing colon. */
export function statusArrow(label: string): string {
  const key = label.replace(/:.*$/, "").trim();
  return (STATUS_ARROW_COLORS[key] ?? chalk.blue)("▶");
}

const SEVERITY_COLORS: Record<string, (s: string) => string> = {
  Critical: chalk.red.bold,
  High: chalk.red,
  Medium: chalk.yellow,
  Low: chalk.cyan,
  Info: chalk.gray,
};

/** Return the chalk styler for a severity bucket. Unknown buckets fall back
 *  to dim so the rare `Unknown` count doesn't outshout real severities. */
export function severityColor(severity: string): (s: string) => string {
  return SEVERITY_COLORS[severity] ?? chalk.dim;
}
