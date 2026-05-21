#!/usr/bin/env bun
/**
 * Release orchestrator. Mirrors the prior Go binary's `make release`:
 *
 *   1. Build all 4 targets via build.ts (transform + bundle + bun --compile)
 *   2. Package each binary into vigolium-audit_<version>_<os>_<arch>.tar.gz
 *   3. Generate checksums.txt (SHA256, GNU coreutils format: "<hash>  <file>")
 *   4. Generate metadata.json with version + commit + date pointer
 *   5. mc rm --recursive --force the prior contents under R2_PREFIX
 *   6. mc cp tarballs + checksums.txt + metadata.json + install.sh
 *
 * Env vars:
 *   VIGOLIUM_AUDIT_VERSION         — release version (default: package.json version)
 *   VIGOLIUM_AUDIT_R2_BUCKET       — mc bucket alias (default: r2/vigolium-dist)
 *   VIGOLIUM_AUDIT_R2_PREFIX       — R2 path prefix (default: vigolium-audit)
 *   VIGOLIUM_AUDIT_RELEASE_DRY_RUN=1 — do everything except mc upload
 *   VIGOLIUM_AUDIT_RELEASE_SKIP_BUILD=1 — reuse existing dist/ from a prior build
 */
import { createHash } from "crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { dirname, join, basename } from "path";
import { fileURLToPath } from "url";
import { spawnSync } from "child_process";

const ROOT = dirname(fileURLToPath(import.meta.url)) + "/..";
const DIST = join(ROOT, "build", "dist");
const BUILD_SCRIPTS = join(ROOT, "build", "scripts");

/**
 * `binarySuffix` matches what build.ts produces (`dist/vigolium-audit-<suffix>`).
 * `tarballSuffix` is the canonical install-script-friendly form using
 * underscores, matching detect_platform()'s output in install.sh.
 */
const TARGETS: Array<{ binarySuffix: string; tarballSuffix: string }> = [
  { binarySuffix: "darwin-arm64", tarballSuffix: "darwin_arm64" },
  { binarySuffix: "darwin-x64", tarballSuffix: "darwin_x64" },
  { binarySuffix: "linux-arm64", tarballSuffix: "linux_arm64" },
  { binarySuffix: "linux-x64", tarballSuffix: "linux_x64" },
];

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

function readVersion(): string {
  if (process.env.VIGOLIUM_AUDIT_VERSION) return process.env.VIGOLIUM_AUDIT_VERSION;
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  return String(pkg.version ?? "0.0.0");
}

function shortCommit(): string {
  const r = spawnSync("git", ["rev-parse", "--short", "HEAD"], { cwd: ROOT, encoding: "utf8" });
  return r.status === 0 ? (r.stdout ?? "").trim() : "unknown";
}

function sha256(path: string): string {
  const h = createHash("sha256");
  h.update(readFileSync(path));
  return h.digest("hex");
}

function tarGz(args: { binary: string; outfile: string }): void {
  // We package a single file (the renamed `vigolium-audit` binary) at the tarball root.
  // Use BSD tar's `-s` option style? GNU/BSD differ — easiest is to stage the
  // binary in a clean dir then tar that dir's contents.
  const stageDir = `${args.outfile}.stage`;
  if (existsSync(stageDir)) rmSync(stageDir, { recursive: true, force: true });
  mkdirSync(stageDir);
  const stagedBinary = join(stageDir, "vigolium-audit");
  // Copy + chmod 755.
  const buf = readFileSync(args.binary);
  writeFileSync(stagedBinary, buf, { mode: 0o755 });
  // Use `gtar` if available (Linux GNU tar deterministic flags), else `tar`.
  const tarBin = spawnSync("gtar", ["--version"]).status === 0 ? "gtar" : "tar";
  const tarArgs = ["-czf", args.outfile, "-C", stageDir, "vigolium-audit"];
  const r = spawnSync(tarBin, tarArgs, { stdio: "inherit" });
  if (r.status !== 0) throw new Error(`${tarBin} failed (exit ${r.status})`);
  rmSync(stageDir, { recursive: true, force: true });
}

interface ReleaseManifest {
  version: string;
  commit: string;
  date: string;
  artifacts: Array<{
    target: string;
    file: string;
    sha256: string;
    bytes: number;
  }>;
}

function build(): void {
  if (process.env.VIGOLIUM_AUDIT_RELEASE_SKIP_BUILD === "1") {
    step("skipping build (VIGOLIUM_AUDIT_RELEASE_SKIP_BUILD=1) — reusing existing dist/");
    return;
  }
  step("building all targets via build.ts --all");
  run("bun", ["run", "build.ts", "--all"]);
}

function packageTarballs(version: string): ReleaseManifest {
  const versionNoV = version.replace(/^v/, "");
  const manifest: ReleaseManifest = {
    version: versionNoV,
    commit: shortCommit(),
    date: new Date().toISOString(),
    artifacts: [],
  };

  for (const t of TARGETS) {
    const binary = join(DIST, `vigolium-audit-${t.binarySuffix}`);
    if (!existsSync(binary)) {
      throw new Error(`expected compiled binary not found: ${binary}`);
    }
    const tarballName = `vigolium-audit_${versionNoV}_${t.tarballSuffix}.tar.gz`;
    const tarballPath = join(DIST, tarballName);
    step(`packaging ${tarballName}`);
    tarGz({ binary, outfile: tarballPath });
    const hash = sha256(tarballPath);
    const bytes = readFileSync(tarballPath).length;
    manifest.artifacts.push({ target: t.tarballSuffix, file: tarballName, sha256: hash, bytes });
  }
  return manifest;
}

function writeChecksums(manifest: ReleaseManifest): string {
  const lines = manifest.artifacts.map((a) => `${a.sha256}  ${a.file}`);
  const out = lines.join("\n") + "\n";
  const path = join(DIST, "checksums.txt");
  writeFileSync(path, out);
  step(`wrote ${basename(path)} (${manifest.artifacts.length} entries)`);
  return path;
}

function writeMetadata(manifest: ReleaseManifest): string {
  const meta = {
    project_name: "vigolium-audit",
    version: manifest.version,
    commit: manifest.commit,
    date: manifest.date,
    artifacts: manifest.artifacts.map((a) => ({ target: a.target, file: a.file, bytes: a.bytes })),
  };
  const path = join(DIST, "metadata.json");
  writeFileSync(path, JSON.stringify(meta) + "\n");
  step(`wrote ${basename(path)} (version=${manifest.version})`);
  return path;
}

function copyInstaller(): string {
  const src = join(BUILD_SCRIPTS, "install.sh");
  const dst = join(DIST, "install.sh");
  if (!existsSync(src)) throw new Error(`missing build/scripts/install.sh`);
  writeFileSync(dst, readFileSync(src), { mode: 0o755 });
  step(`copied install.sh → build/dist/`);
  return dst;
}

function uploadToR2(args: { bucket: string; prefix: string; files: string[] }): void {
  if (process.env.VIGOLIUM_AUDIT_RELEASE_DRY_RUN === "1") {
    step("DRY RUN — skipping mc upload");
    for (const f of args.files) {
      console.log(`  would upload ${basename(f)} → ${args.bucket}/${args.prefix}/`);
    }
    return;
  }
  // Verify mc is installed.
  if (spawnSync("mc", ["--version"]).status !== 0) {
    throw new Error(
      `\`mc\` (MinIO Client) not found on PATH. Install via \`brew install minio/stable/mc\` or see https://min.io/docs/minio/linux/reference/minio-mc.html`,
    );
  }

  const target = `${args.bucket}/${args.prefix}/`;

  step(`cleaning old files at ${target}`);
  // mc rm --recursive --force may fail with "object not found" on first release;
  // tolerate that.
  spawnSync("mc", ["rm", "--recursive", "--force", target], { stdio: "inherit" });

  step(`uploading ${args.files.length} artifact(s) to ${target}`);
  for (const f of args.files) {
    run("mc", ["cp", f, target]);
  }
}

function main(): void {
  const version = readVersion();
  const r2Bucket = process.env.VIGOLIUM_AUDIT_R2_BUCKET ?? "r2/vigolium-dist";
  const r2Prefix = process.env.VIGOLIUM_AUDIT_R2_PREFIX ?? "vigolium-audit";

  step(`release v${version}  →  ${r2Bucket}/${r2Prefix}/`);

  build();
  const manifest = packageTarballs(version);
  const checksums = writeChecksums(manifest);
  const metadata = writeMetadata(manifest);
  const installer = copyInstaller();

  const filesToUpload = [
    ...manifest.artifacts.map((a) => join(DIST, a.file)),
    checksums,
    metadata,
    installer,
  ];

  uploadToR2({ bucket: r2Bucket, prefix: r2Prefix, files: filesToUpload });

  step("release uploaded successfully!");
  console.log("");
  console.log(`  installer: https://cdn.vigolium.com/${r2Prefix}/install.sh`);
  console.log(`  metadata:  https://cdn.vigolium.com/${r2Prefix}/metadata.json`);
  console.log("");
  console.log(`  curl -fsSL https://cdn.vigolium.com/${r2Prefix}/install.sh | bash`);
}

main();
