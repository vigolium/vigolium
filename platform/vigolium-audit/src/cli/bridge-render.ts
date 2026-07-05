import chalk from "chalk";
import type { AdapterEvent } from "../adapters/adapter.js";

/**
 * Terse human-log renderer for the one-shot `bridge` command (the daemon and
 * `--json` paths emit NDJSON instead). Event serialization for the wire format
 * is shared with `run` via `run-render.ts` `serializeAdapterEvent`.
 */

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + "…";
}

function oneLine(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

function toolHeadline(input: unknown): string {
  if (input && typeof input === "object") {
    const o = input as Record<string, unknown>;
    for (const key of ["command", "file_path", "path", "pattern", "url", "query", "prompt", "description"]) {
      if (typeof o[key] === "string") return o[key] as string;
    }
  }
  if (typeof input === "string") return input;
  return "";
}

export interface BridgeHumanRenderer {
  onEvent: (e: AdapterEvent) => void;
  /** Flush any buffered partial line. Call before printing the summary. */
  flush: () => void;
}

/**
 * A minimal human renderer: streams assistant text as `●` lines, tool calls as
 * `ƒ`, tool results as `←`. Writes straight to stdout (no typewriter delay —
 * the bridge is script-facing, so latency matters more than animation).
 */
export function makeBridgeHumanRenderer(opts: { debug?: boolean } = {}): BridgeHumanRenderer {
  const debug = !!opts.debug;
  const inputCap = debug ? 800 : 200;
  const outputCap = debug ? 2000 : 400;
  let textBuf = "";

  const writeAgentLines = (chunk: string): void => {
    const body = chunk.endsWith("\n") ? chunk.slice(0, -1) : chunk;
    for (const line of body.split("\n")) {
      process.stdout.write(`  ${chalk.magenta("●")} ${line}\n`);
    }
  };
  const flush = (): void => {
    if (textBuf.length === 0) return;
    // writeAgentLines strips a trailing newline itself, so no need to add one.
    writeAgentLines(textBuf);
    textBuf = "";
  };

  const onEvent = (e: AdapterEvent): void => {
    if (e.kind !== "textDelta") flush();
    switch (e.kind) {
      case "session": {
        process.stdout.write(`${chalk.dim("session")} ${chalk.cyan(e.sessionId)}`);
        const parts: string[] = [];
        if (e.plugins?.length) parts.push(`plugin=${e.plugins.map((p) => p.name).join(",")}`);
        if (e.skills) parts.push(`skills=${e.skills.length}`);
        if (e.model) parts.push(`model=${e.model}`);
        process.stdout.write(parts.length ? chalk.dim(` (${parts.join(" · ")})\n`) : "\n");
        break;
      }
      case "textDelta": {
        const buf = textBuf + e.text;
        const lastNl = buf.lastIndexOf("\n");
        if (lastNl >= 0) {
          writeAgentLines(buf.slice(0, lastNl + 1));
          textBuf = buf.slice(lastNl + 1);
        } else {
          textBuf = buf;
        }
        break;
      }
      case "thinking":
        if (debug) process.stdout.write(chalk.dim(`  · ${truncate(oneLine(e.text), outputCap)}\n`));
        break;
      case "toolCall": {
        const head = debug ? JSON.stringify(e.input) : toolHeadline(e.input);
        const param = truncate(oneLine(head), inputCap);
        process.stdout.write(
          `  ${chalk.green(`ƒ ${e.tool}`)}${param ? chalk.dim(" · ") + chalk.cyan(param) : ""}\n`,
        );
        break;
      }
      case "toolResult": {
        const out = typeof e.output === "string" ? e.output : JSON.stringify(e.output);
        const preview = truncate(oneLine(out), outputCap);
        if (preview) {
          const arrow = e.isError ? chalk.red("✗") : chalk.dim("←");
          process.stdout.write(`    ${arrow} ${e.isError ? chalk.red(preview) : chalk.gray(preview)}\n`);
        }
        break;
      }
      default:
        break;
    }
  };

  return { onEvent, flush };
}
