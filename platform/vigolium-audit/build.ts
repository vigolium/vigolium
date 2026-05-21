#!/usr/bin/env bun
/**
 * Multi-target build for vigolium-audit. Runs the content transform, regenerates the
 * embedded content bundle, then invokes `bun build --compile` for each target
 * triple. Output goes to dist/vigolium-audit-<target>.
 *
 * Usage:
 *   bun run build                 # current platform only
 *   bun run build --all           # all supported targets
 *   bun run build --target=bun-linux-x64
 */
import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync } from "fs";
import { homedir } from "os";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { spawnSync } from "child_process";

const ROOT = dirname(fileURLToPath(import.meta.url));
const DIST = join(ROOT, "build", "dist");
const LOCAL_BIN = process.env.VIGOLIUM_AUDIT_BIN_DIR ?? join(homedir(), ".local", "bin");

const ALL_TARGETS = [
  "bun-darwin-arm64",
  "bun-darwin-x64",
  "bun-linux-arm64",
  "bun-linux-x64",
];

function detectCurrentTarget(): string {
  const arch = process.arch === "arm64" ? "arm64" : "x64";
  const platform = process.platform === "darwin" ? "darwin" : process.platform === "linux" ? "linux" : null;
  if (!platform) {
    throw new Error(`unsupported host platform: ${process.platform}`);
  }
  return `bun-${platform}-${arch}`;
}

function runStep(label: string, cmd: string, args: string[]): void {
  console.log(`[build] ${label}`);
  const result = spawnSync(cmd, args, { cwd: ROOT, stdio: "inherit" });
  if (result.status !== 0) {
    throw new Error(`${label} failed (exit ${result.status})`);
  }
}

function main(): void {
  const argv = process.argv.slice(2);
  const all = argv.includes("--all");
  const targetArg = argv.find((a) => a.startsWith("--target="));
  const targets = all
    ? ALL_TARGETS
    : targetArg
      ? [targetArg.slice("--target=".length)]
      : [detectCurrentTarget()];

  if (existsSync(DIST)) rmSync(DIST, { recursive: true, force: true });
  mkdirSync(DIST, { recursive: true });

  runStep("transform content", "bun", ["run", "scripts/transform-content.ts"]);
  runStep("bundle content", "bun", ["run", "scripts/bundle-content.ts"]);

  const buildDate = new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const commit = (() => {
    const r = spawnSync("git", ["rev-parse", "--short", "HEAD"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return r.status === 0 ? r.stdout.trim() : "unknown";
  })();

  let hostBinary: string | null = null;
  const hostTarget = (() => {
    try {
      return detectCurrentTarget();
    } catch {
      return null;
    }
  })();

  for (const target of targets) {
    const out = join(DIST, `vigolium-audit-${target.replace(/^bun-/, "")}`);
    runStep(`compile ${target}`, "bun", [
      "build",
      "--compile",
      `--target=${target}`,
      "src/index.ts",
      `--outfile=${out}`,
      `--define`,
      `process.env.VIGOLIUM_AUDIT_BUILD_DATE="${buildDate}"`,
      `--define`,
      `process.env.VIGOLIUM_AUDIT_COMMIT="${commit}"`,
    ]);
    if (target === hostTarget) hostBinary = out;
  }

  if (hostBinary && process.env.VIGOLIUM_AUDIT_BUILD_NO_INSTALL !== "1") {
    installToLocalBin(hostBinary);
  } else if (!hostBinary && targets.length > 0) {
    console.log(
      `[build] note: no host-platform binary built (host=${hostTarget ?? "?"}); skipping local install.`,
    );
  }
}

function installToLocalBin(hostBinary: string): void {
  try {
    mkdirSync(LOCAL_BIN, { recursive: true });
    const dst = join(LOCAL_BIN, "vigolium-audit");
    copyFileSync(hostBinary, dst);
    chmodSync(dst, 0o755);
    console.log(`[build] installed → ${dst}`);
    if (!isOnPath(LOCAL_BIN)) {
      console.log(`[build] note: ${LOCAL_BIN} is not on PATH yet; add:`);
      console.log(`         export PATH="${LOCAL_BIN}:$PATH"`);
    }
  } catch (err) {
    console.warn(`[build] warn: failed to install to ${LOCAL_BIN}: ${(err as Error).message}`);
    console.warn(`[build] (set VIGOLIUM_AUDIT_BUILD_NO_INSTALL=1 to silence; VIGOLIUM_AUDIT_BIN_DIR=… to override)`);
  }
}

function isOnPath(dir: string): boolean {
  const p = process.env.PATH ?? "";
  return p.split(":").includes(dir);
}

main();
