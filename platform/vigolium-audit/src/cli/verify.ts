import { existsSync } from "fs";
import { spawnSync } from "child_process";
import chalk from "chalk";
import type { Adapter } from "../adapters/adapter.js";
import { ClaudeCliAdapter } from "../adapters/claude-cli.js";
import { ClaudeSdkAdapter } from "../adapters/claude-sdk.js";
import { CodexCliAdapter } from "../adapters/codex-cli.js";
import { CodexSdkAdapter } from "../adapters/codex-sdk.js";
import { chooseAdapter } from "../adapters/detect.js";
import { getContentLoader } from "../content-loader.js";
import type { AgentPlatform, AgentTransport } from "../engine/types.js";

type VerifyTransport = AgentTransport | "both";

interface CheckResult {
  ok: boolean;
  /** One-line detail rendered next to the check label. */
  detail?: string;
  /** Remediation message shown on failure. */
  hint?: string;
}

interface Check {
  label: string;
  run: () => Promise<CheckResult> | CheckResult;
}

export async function verifyCommand(
  platform: string,
  opts: { json?: boolean; transport?: string } = {},
): Promise<void> {
  if (platform !== "claude" && platform !== "codex") {
    if (opts.json) {
      process.stdout.write(
        JSON.stringify({ ok: false, error: `platform must be "claude" or "codex"`, platform }) + "\n",
      );
    } else {
      console.error(chalk.red(`error: platform must be "claude" or "codex"`));
    }
    process.exit(2);
  }
  const p = platform as AgentPlatform;
  let requestedTransport: VerifyTransport;
  try {
    requestedTransport = resolveVerifyTransport(opts.transport);
  } catch (err) {
    const message = (err as Error).message;
    if (opts.json) {
      process.stdout.write(JSON.stringify({ ok: false, platform: p, error: message }) + "\n");
    } else {
      console.error(chalk.red(`error: ${message}`));
    }
    process.exit(2);
  }

  const transports: AgentTransport[] =
    requestedTransport === "both" ? ["sdk", "cli"] : [requestedTransport];

  if (!opts.json) {
    const label = requestedTransport === "both" ? "sdk + cli" : requestedTransport;
    console.log(`[vigolium-audit] verifying ${p} (${label})…\n`);
  }

  const isTty = !!process.stdout.isTTY && !opts.json;
  const runs: Array<{
    transport: AgentTransport;
    adapter: "sdk" | "cli";
    checks: Array<{ label: string; ok: boolean; detail?: string; hint?: string }>;
  }> = [];
  let failed = false;

  for (const transport of transports) {
    const choice = chooseAdapter(p, transport);
    const checks = await buildChecks(p, transport);
    const results: Array<{ label: string; ok: boolean; detail?: string; hint?: string }> = [];
    let runFailed = false;
    if (!opts.json && transports.length > 1) {
      console.log(chalk.cyan(`  [${transport}]`));
    }
    for (const check of checks) {
      if (isTty) process.stdout.write(`  …  ${check.label}`);
      const result = await Promise.resolve(check.run());
      if (isTty) process.stdout.write("\r" + " ".repeat(check.label.length + 6) + "\r");
      results.push({
        label: check.label,
        ok: result.ok,
        ...(result.detail !== undefined ? { detail: result.detail } : {}),
        ...(result.hint !== undefined ? { hint: result.hint } : {}),
      });
      if (!opts.json) {
        if (result.ok) {
          console.log(`  ${chalk.green("✓")} ${check.label.padEnd(22)} ${result.detail ?? ""}`);
        } else {
          console.log(`  ${chalk.red("✗")} ${check.label.padEnd(22)} ${result.detail ?? "failed"}`);
          if (result.hint) console.log(`     ${result.hint}`);
        }
      }
      if (!result.ok) {
        failed = true;
        runFailed = true;
        break;
      }
    }
    runs.push({ transport, adapter: choice.flavor, checks: results });
    if (!opts.json && transports.length > 1 && !runFailed) console.log("");
  }

  if (opts.json) {
    const payload =
      runs.length === 1
        ? { ok: !failed, platform: p, transport: runs[0]!.transport, adapter: runs[0]!.adapter, checks: runs[0]!.checks }
        : { ok: !failed, platform: p, transport: "both", runs };
    process.stdout.write(JSON.stringify(payload) + "\n");
  } else {
    console.log("");
    if (failed) {
      console.error(chalk.red(`[vigolium-audit] verify failed — fix the issue above and re-run.`));
    } else {
      console.log(chalk.green(`[vigolium-audit] all checks passed — ${p} is ready.`));
    }
  }
  process.exit(failed ? 1 : 0);
}

function resolveVerifyTransport(value: unknown): VerifyTransport {
  const resolved = value ?? "auto";
  if (resolved !== "auto" && resolved !== "sdk" && resolved !== "cli" && resolved !== "both") {
    throw new Error(
      `--transport must be "auto", "sdk", "cli", or "both" for verify (got ${JSON.stringify(value)})`,
    );
  }
  return resolved;
}

async function buildChecks(platform: AgentPlatform, transport: AgentTransport): Promise<Check[]> {
  const loader = getContentLoader();
  const choice = chooseAdapter(platform, transport);

  // Pre-resolved values shared between checks.
  let adapter: Adapter | null = null;

  return [
    {
      label: "binary found",
      run: () => {
        if (!choice.binaryPath) {
          const installHint =
            platform === "claude"
              ? "install via `npm i -g @anthropic-ai/claude-code`, or set VIGOLIUM_AUDIT_CLAUDE_PATH"
              : "install via `npm i -g @openai/codex`, or set VIGOLIUM_AUDIT_CODEX_PATH";
          return { ok: false, detail: `no \`${platform}\` binary on PATH`, hint: installHint };
        }
        if (!existsSync(choice.binaryPath)) {
          return { ok: false, detail: `${choice.binaryPath} does not exist` };
        }
        return { ok: true, detail: `${choice.binaryPath} (${choice.binarySource})` };
      },
    },
    {
      label: "binary executable",
      run: () => {
        if (!choice.binaryPath) return { ok: false, detail: "no binary to invoke" };
        const result = spawnSync(choice.binaryPath, ["--version"], {
          encoding: "utf8",
          timeout: 10_000,
          stdio: ["ignore", "pipe", "pipe"],
        });
        if (result.error) {
          return { ok: false, detail: result.error.message, hint: "binary is not executable or not runnable on this platform" };
        }
        if (result.status !== 0) {
          return {
            ok: false,
            detail: `--version exited ${result.status}`,
            hint: `stderr: ${(result.stderr ?? "").toString().trim().slice(0, 200)}`,
          };
        }
        const v = ((result.stdout ?? "") + (result.stderr ?? "")).trim().split(/\r?\n/)[0] ?? "(no version reported)";
        return { ok: true, detail: v };
      },
    },
    {
      label: "auth source",
      run: () => {
        if (choice.authSource === "unknown") {
          const envVar = platform === "claude" ? "ANTHROPIC_API_KEY" : "OPENAI_API_KEY";
          return {
            ok: false,
            detail: "no API key and no installed binary detected",
            hint: `set ${envVar}=… or install the ${platform} CLI to use ambient subscription auth`,
          };
        }
        return {
          ok: true,
          detail: `${choice.authSource} (adapter: ${choice.flavor})`,
        };
      },
    },
    {
      label: "content available",
      run: async () => {
        const cmds = await loader.listCommands();
        const agents = await loader.listAgents();
        const skills = await loader.listSkills();
        if (cmds.length === 0 || agents.length === 0) {
          return {
            ok: false,
            detail: "content directory is empty",
            hint: "reinstall vigolium-audit (curl -fsSL …/install.sh | bash)",
          };
        }
        return {
          ok: true,
          detail: `${cmds.length} commands, ${agents.length} agents, ${skills.length} skills`,
        };
      },
    },
    {
      label: "message round-trip",
      run: async () => {
        if (!choice.binaryPath) return { ok: false, detail: "skipped — no binary" };
        adapter =
          platform === "claude"
            ? choice.flavor === "cli"
              ? new ClaudeCliAdapter({ pathToClaudeCodeExecutable: choice.binaryPath })
              : new ClaudeSdkAdapter({ pathToClaudeCodeExecutable: choice.binaryPath })
            : choice.flavor === "cli"
              ? new CodexCliAdapter({ pathToCodexExecutable: choice.binaryPath })
              : new CodexSdkAdapter({ codexPathOverride: choice.binaryPath });
        const startedAt = Date.now();
        try {
          await adapter.probe();
          const ms = Date.now() - startedAt;
          return { ok: true, detail: `"ping" → "pong" in ${(ms / 1000).toFixed(1)}s` };
        } catch (err) {
          const msg = (err as Error).message;
          let hint = "";
          if (/auth/i.test(msg) || /api[_ ]?key/i.test(msg)) {
            hint =
              platform === "claude"
                ? "check ANTHROPIC_API_KEY or run `claude login`"
                : "check OPENAI_API_KEY or run `codex login`";
          } else if (/quota|billing|out_of_credits|usage limit|credits/i.test(msg)) {
            hint = "API quota / billing — check your provider dashboard";
          } else if (/rate[_ ]?limit/i.test(msg)) {
            hint = "rate-limited — wait a moment and re-run";
          }
          return { ok: false, detail: msg.slice(0, 200), ...(hint ? { hint } : {}) };
        }
      },
    },
  ];
}
