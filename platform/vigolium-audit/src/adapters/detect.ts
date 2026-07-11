import { existsSync } from "fs";
import { spawnSync } from "child_process";
import { homedir } from "os";
import { join } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";
import type { AgentPlatform, AgentTransport } from "../engine/types.js";

export interface BinaryProbe {
  /** Absolute path to the resolved binary, or null if none found. */
  path: string | null;
  /** Where the binary was found: "PATH", "bundled-dev", "env-override", "common-path", or null. */
  source: string | null;
}

/**
 * Find the user's `claude` binary. Search order:
 *   1. VIGOLIUM_AUDIT_CLAUDE_PATH env override
 *   2. `which claude` on PATH
 *   3. Common manual-install locations (~/.npm/bin, ~/.bun/bin, etc.)
 *   4. Bundled native dep at node_modules/@anthropic-ai/claude-agent-sdk-<platform>/claude
 *      (development mode only; doesn't survive `bun build --compile`)
 */
export function probeClaudeBinary(): BinaryProbe {
  return probeBinary("claude", "VIGOLIUM_AUDIT_CLAUDE_PATH", [
    "@anthropic-ai/claude-agent-sdk-darwin-arm64",
    "@anthropic-ai/claude-agent-sdk-darwin-x64",
    "@anthropic-ai/claude-agent-sdk-linux-arm64",
    "@anthropic-ai/claude-agent-sdk-linux-x64",
    "@anthropic-ai/claude-agent-sdk-linux-x64-musl",
    "@anthropic-ai/claude-agent-sdk-linux-arm64-musl",
  ]);
}

export function probeCodexBinary(): BinaryProbe {
  return probeBinary("codex", "VIGOLIUM_AUDIT_CODEX_PATH", [
    "@openai/codex-darwin-arm64",
    "@openai/codex-darwin-x64",
    "@openai/codex-linux-arm64",
    "@openai/codex-linux-x64",
  ]);
}

function probeBinary(name: string, envOverride: string, bundledPackages: string[]): BinaryProbe {
  const fromEnv = process.env[envOverride];
  if (fromEnv && existsSync(fromEnv)) {
    return { path: fromEnv, source: "env-override" };
  }
  const fromPath = whichBinary(name);
  if (fromPath) {
    return { path: fromPath, source: "PATH" };
  }
  const commonLocations = [
    join(homedir(), ".npm", "bin", name),
    join(homedir(), ".bun", "install", "global", "bin", name),
    join(homedir(), ".local", "bin", name),
    "/opt/homebrew/bin/" + name,
    "/usr/local/bin/" + name,
  ];
  for (const candidate of commonLocations) {
    if (existsSync(candidate)) return { path: candidate, source: "common-path" };
  }
  // Bundled dev fallback: walk up from this module to find node_modules/.
  const moduleDir = dirname(fileURLToPath(import.meta.url));
  let dir: string | null = moduleDir;
  for (let i = 0; i < 6; i++) {
    if (!dir) break;
    const nm = join(dir, "node_modules");
    if (existsSync(nm)) {
      for (const pkg of bundledPackages) {
        const candidate = join(nm, pkg, name);
        if (existsSync(candidate)) return { path: candidate, source: "bundled-dev" };
        const candidateBin = join(nm, pkg, "bin", name);
        if (existsSync(candidateBin)) return { path: candidateBin, source: "bundled-dev" };
      }
      break;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return { path: null, source: null };
}

function whichBinary(name: string): string | null {
  const result = spawnSync("which", [name], { stdio: ["ignore", "pipe", "ignore"], encoding: "utf8" });
  if (result.status !== 0) return null;
  const out = (result.stdout ?? "").trim();
  return out.length > 0 ? out : null;
}

export interface ResolvedAdapterChoice {
  platform: AgentPlatform;
  /** Which adapter family to use: "sdk" or "cli". */
  flavor: "sdk" | "cli";
  binaryPath: string | null;
  binarySource: string | null;
  authSource: "api-key" | "subscription" | "unknown";
}

/**
 * Env var name that holds the platform's API key.
 *   claude → ANTHROPIC_API_KEY
 *   codex  → OPENAI_API_KEY
 */
export function platformApiKeyEnv(platform: AgentPlatform): string {
  return platform === "claude" ? "ANTHROPIC_API_KEY" : "OPENAI_API_KEY";
}

/**
 * Pick an adapter for a platform based on the requested transport, installed
 * binary, and available auth. Codex SDK can reuse the CLI's ambient ChatGPT
 * authentication, so Codex `auto` prefers SDK even without OPENAI_API_KEY.
 * Claude retains the established API-key-to-SDK / subscription-to-CLI policy.
 */
export function chooseAdapter(
  platform: AgentPlatform,
  transport: AgentTransport = "auto",
): ResolvedAdapterChoice {
  const probe = platform === "claude" ? probeClaudeBinary() : probeCodexBinary();
  const hasKey = !!process.env[platformApiKeyEnv(platform)];
  const flavor: "sdk" | "cli" =
    transport === "sdk"
      ? "sdk"
      : transport === "cli"
        ? "cli"
        : platform === "codex"
          ? "sdk"
          : hasKey
            ? "sdk"
            : "cli";
  const authSource: ResolvedAdapterChoice["authSource"] = hasKey
    ? "api-key"
    : probe.path
      ? "subscription"
      : "unknown";
  return {
    platform,
    flavor,
    binaryPath: probe.path,
    binarySource: probe.source,
    authSource,
  };
}

/** Validate a value received from the CLI and normalize an omitted flag. */
export function resolveAgentTransport(value: unknown): AgentTransport {
  const resolved = value ?? "auto";
  if (resolved !== "auto" && resolved !== "sdk" && resolved !== "cli") {
    throw new Error(`--transport must be "auto", "sdk", or "cli" (got ${JSON.stringify(value)})`);
  }
  return resolved;
}
