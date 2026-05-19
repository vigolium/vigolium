#!/usr/bin/env bun
/**
 * npm publish orchestrator — single self-contained package.
 *
 * Publishes ONE package:
 *
 *   @vigolium/archon-audit — a tiny Node CJS shim (bin/cli.cjs) plus every
 *                            platform's `bun --compile` binary, each
 *                            brotli-compressed to keep the install small
 *                            (~95 MB for all four vs ~330 MB raw).
 *
 * The shim picks the binary matching the host, decompresses it once into a
 * cache dir with Node's built-in zlib, then execs it. The end user needs
 * neither Bun nor Node to run archon — Node only runs the shim, with zero
 * runtime dependencies (no optionalDependencies, no postinstall, no network).
 *
 * Flow: build (via build.ts --all) → brotli-compress the 4 binaries → stage
 * one package under build/npm/ → dry-run validate → publish (skipping if the
 * version is already on the registry) → move the `latest` dist-tag onto it so
 * both `npm i -g @vigolium/archon-audit` and `@alpha` resolve.
 *
 * Env vars:
 *   ARCHON_VERSION              — version to publish (default: package.json)
 *   ARCHON_RELEASE_SKIP_BUILD=1 — reuse existing build/dist/ from a prior build
 *   ARCHON_NPM_DRY_RUN=1        — stage + dry-run validate only; no registry writes
 *   NPM_TOKEN                   — if set, written to a staged-dir .npmrc for auth
 *                                 (npm excludes .npmrc from published tarballs)
 */
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, copyFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { spawnSync } from "child_process";
import { brotliCompressSync, constants as zlibConstants } from "zlib";

const ROOT = dirname(fileURLToPath(import.meta.url)) + "/..";
const DIST = join(ROOT, "build", "dist");
const STAGE = join(ROOT, "build", "npm");
const SHIM_SRC = join(ROOT, "bin", "cli.cjs");
const SCOPE = "@vigolium";
const MAIN_PKG = `${SCOPE}/archon-audit`;
const DRY_RUN = process.env.ARCHON_NPM_DRY_RUN === "1";

/** `binarySuffix` matches what build.ts emits (`dist/archon-<binarySuffix>`). */
const TARGETS: string[] = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"];

const PREFIX = "\x1b[36m[*]\x1b[0m";

function step(msg: string): void {
  console.log(`${PREFIX} ${msg}`);
}

function run(cmd: string, args: string[], opts: { cwd?: string; check?: boolean } = {}): number {
  const result = spawnSync(cmd, args, { cwd: opts.cwd ?? ROOT, stdio: "inherit" });
  if ((opts.check ?? true) && result.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} failed (exit ${result.status})`);
  }
  return result.status ?? 0;
}

function readPkg(): { version: string; description: string } {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
    version?: string;
    description?: string;
  };
  return {
    version: process.env.ARCHON_VERSION ?? String(pkg.version ?? "0.0.0"),
    description: String(pkg.description ?? "Archon — autonomous agent that performs thorough security audits on your codebase, part of Vigolium"),
  };
}

function build(): void {
  if (process.env.ARCHON_RELEASE_SKIP_BUILD === "1") {
    step("skipping build (ARCHON_RELEASE_SKIP_BUILD=1) — reusing existing build/dist/");
    return;
  }
  step("building all targets via build.ts --all");
  run("bun", ["run", "build.ts", "--all"]);
}

/** Write a staged-dir .npmrc from NPM_TOKEN. npm omits .npmrc from tarballs. */
function writeNpmrc(dir: string): void {
  const token = process.env.NPM_TOKEN;
  if (!token) return;
  writeFileSync(
    join(dir, ".npmrc"),
    `registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${token}\n`,
    { mode: 0o600 },
  );
}

/** Brotli-compress every platform binary into <dir>/bin/archon-<version>-<suffix>.br. */
function compressBinaries(binDir: string, version: string): void {
  for (const suffix of TARGETS) {
    const binary = join(DIST, `archon-${suffix}`);
    if (!existsSync(binary)) {
      throw new Error(`expected compiled binary not found: ${binary} (run build.ts --all)`);
    }
    const raw = readFileSync(binary);
    const compressed = brotliCompressSync(raw, {
      params: {
        [zlibConstants.BROTLI_PARAM_QUALITY]: 9,
        [zlibConstants.BROTLI_PARAM_SIZE_HINT]: raw.length,
      },
    });
    const out = join(binDir, `archon-${version}-${suffix}.br`);
    writeFileSync(out, compressed);
    const pct = ((compressed.length / raw.length) * 100).toFixed(0);
    step(`compressed ${suffix}: ${(raw.length / 1e6).toFixed(0)}MB → ${(compressed.length / 1e6).toFixed(0)}MB (${pct}%)`);
  }
}

function stageMain(version: string, description: string): string {
  if (!existsSync(SHIM_SRC)) throw new Error(`missing shim: ${SHIM_SRC}`);
  const dir = join(STAGE, "main");
  const binDir = join(dir, "bin");
  mkdirSync(binDir, { recursive: true });
  copyFileSync(SHIM_SRC, join(binDir, "cli.cjs"));
  compressBinaries(binDir, version);
  const readme = join(ROOT, "README.md");
  if (existsSync(readme)) copyFileSync(readme, join(dir, "README.md"));
  const license = join(ROOT, "LICENSE");
  if (existsSync(license)) copyFileSync(license, join(dir, "LICENSE"));
  const manifest = {
    name: MAIN_PKG,
    version,
    description,
    license: "MIT",
    bin: { "archon-audit": "bin/cli.cjs" },
    files: ["bin/", "README.md", "LICENSE"],
    engines: { node: ">=18" },
    publishConfig: { access: "public" },
  };
  writeFileSync(join(dir, "package.json"), JSON.stringify(manifest, null, 2) + "\n");
  writeNpmrc(dir);
  step(`staged ${MAIN_PKG}`);
  return dir;
}

/** True if <pkg>@<version> already exists on the registry. */
function isPublished(pkg: string, version: string): boolean {
  const r = spawnSync("npm", ["view", `${pkg}@${version}`, "version"], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  return r.status === 0 && (r.stdout ?? "").trim() === version;
}

function npmAuthCheck(): void {
  const r = spawnSync("npm", ["whoami"], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (r.status === 0) {
    step(`npm authenticated as ${(r.stdout ?? "").trim()}`);
    return;
  }
  if (process.env.NPM_TOKEN) {
    step("npm whoami failed but NPM_TOKEN is set — relying on staged-dir .npmrc");
    return;
  }
  const msg =
    "not authenticated to npm. Run `npm login`, or set NPM_TOKEN (an Automation token, which also bypasses 2FA/OTP).";
  if (DRY_RUN) {
    step(`warning: ${msg}`);
    return;
  }
  throw new Error(msg);
}

function publishOrSkip(dir: string, pkg: string, version: string): void {
  if (isPublished(pkg, version)) {
    step(`skip ${pkg}@${version} — already on registry`);
    return;
  }
  // Publish with `--tag latest` (not `alpha`). The registry only rewrites the
  // packument's root-level `description` (what npmjs.com renders) when the
  // publish itself sets the `latest` dist-tag — a later `npm dist-tag add`
  // never touches root metadata. Publishing a prerelease as `latest` is fine
  // as long as the tag is explicit.
  step(`publishing ${pkg}@${version} (--tag latest)`);
  run("npm", ["publish", "--tag", "latest", "--access", "public"], { cwd: dir });
}

function ensureAlphaTag(version: string): void {
  // `latest` is already set by the publish above; also point `alpha` here so
  // `npm i -g @vigolium/archon-audit@alpha` keeps resolving. Idempotent.
  step(`pointing alpha → ${MAIN_PKG}@${version}`);
  run("npm", ["dist-tag", "add", `${MAIN_PKG}@${version}`, "alpha"]);
}

function main(): void {
  const { version, description } = readPkg();
  step(`npm release ${MAIN_PKG}@${version}  (tags: alpha + latest)${DRY_RUN ? "  [DRY RUN]" : ""}`);

  npmAuthCheck();
  build();

  if (existsSync(STAGE)) rmSync(STAGE, { recursive: true, force: true });
  mkdirSync(STAGE, { recursive: true });

  const mainDir = stageMain(version, description);

  // Preflight: dry-run validate the tarball before any write. An explicit
  // `--tag` is required because the version is a prerelease (npm refuses to
  // publish a prerelease, even --dry-run, without one).
  step("validating tarball (npm publish --dry-run)");
  run("npm", ["publish", "--dry-run", "--tag", "latest", "--access", "public"], { cwd: mainDir });

  if (DRY_RUN) {
    step("DRY RUN — staged + validated only; no registry writes performed");
    console.log("");
    console.log(`  staged under: ${STAGE}`);
    console.log(`  would publish: ${MAIN_PKG}@${version} (--tag latest)`);
    console.log(`  would then: npm dist-tag add ${MAIN_PKG}@${version} alpha`);
    return;
  }

  publishOrSkip(mainDir, MAIN_PKG, version);
  ensureAlphaTag(version);

  step("npm release published successfully!");
  console.log("");
  console.log(`  npm install -g ${MAIN_PKG}            # latest`);
  console.log(`  npm install -g ${MAIN_PKG}@alpha      # alpha tag`);
}

main();
