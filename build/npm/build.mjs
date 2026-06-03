#!/usr/bin/env node
// Stage the @vigolium/vigolium npm packages.
//
// Produces, under build/dist-npm/:
//   - vigolium/              the thin launcher package (@vigolium/vigolium@<v>)
//   - vigolium-<tag>/        4 platform packages (@vigolium/vigolium@<v>-<tag>)
//                            each carrying the gzipped binary in vendor/<tag>/
//
// The binary is gzipped so each platform package's *unpacked* size stays at
// ~70-110MB instead of 200-310MB, keeping it under npm's per-version ceiling.
// bin/vigolium.js decompresses it once on first run.
//
// Source binaries come from goreleaser output in build/dist/
// (vigolium_<goos>_<goarch>_<variant>/vigolium). Run `make snapshot` first.
//
// Usage:
//   node build/npm/build.mjs [--pack] [--allow-missing=<tag,tag>]
//   VIGOLIUM_VERSION=0.1.2-alpha node build/npm/build.mjs

import { spawnSync } from "node:child_process";
import {
  createWriteStream,
  existsSync,
  readdirSync,
  readFileSync,
  rmSync,
  mkdirSync,
  copyFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGzip } from "node:zlib";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..", "..");
const DIST_DIR = path.join(REPO_ROOT, "build", "dist");
const OUT_DIR = path.join(REPO_ROOT, "build", "dist-npm");
const LAUNCHER_SRC = path.join(__dirname, "bin", "vigolium.js");
// Bundle the full project README onto the npm package page.
const README_SRC = path.join(REPO_ROOT, "README.md");
const LICENSE_SRC = path.join(REPO_ROOT, "LICENSE");
const VERSION_GO = path.join(REPO_ROOT, "pkg", "cli", "version.go");

const NPM_NAME = "@vigolium/vigolium";
const LICENSE_ID = "AGPL-3.0-only";
const HOMEPAGE = "https://vigolium.com";
const DESCRIPTION = "Vigolium - High-fidelity vulnerability scanner fusing agentic AI with native speed, modularity, and precision";
const KEYWORDS = [
  "vigolium",
  "security",
  "security-scanner",
  "vulnerability",
  "vulnerability-scanner",
  "dast",
  "ai-powered-scanner",
];
const REPOSITORY = {
  type: "git",
  url: "git+https://github.com/vigolium/vigolium.git",
};
const ENGINES = { node: ">=16" };

const PLATFORMS = [
  { tag: "linux-x64", goos: "linux", goarch: "amd64", os: "linux", cpu: "x64" },
  { tag: "linux-arm64", goos: "linux", goarch: "arm64", os: "linux", cpu: "arm64" },
  { tag: "darwin-x64", goos: "darwin", goarch: "amd64", os: "darwin", cpu: "x64" },
  { tag: "darwin-arm64", goos: "darwin", goarch: "arm64", os: "darwin", cpu: "arm64" },
];

const args = process.argv.slice(2);
const doPack = args.includes("--pack");
const allowMissing = new Set(
  (args.find((a) => a.startsWith("--allow-missing=")) || "")
    .split("=")[1]
    ?.split(",")
    .map((s) => s.trim())
    .filter(Boolean) || [],
);

function fail(msg) {
  console.error(`\x1b[31m[!] ${msg}\x1b[0m`);
  process.exit(1);
}

function info(msg) {
  console.log(`\x1b[36m[*]\x1b[0m ${msg}`);
}

// --- version --------------------------------------------------------------

function deriveBaseVersion() {
  if (process.env.VIGOLIUM_VERSION) {
    return process.env.VIGOLIUM_VERSION.replace(/^v/, "");
  }
  const src = readFileSync(VERSION_GO, "utf8");
  const m = src.match(/^\s*Version\s*=\s*"v?([^"]+)"/m);
  if (!m) fail(`Could not parse Version from ${VERSION_GO}`);
  return m[1];
}

const baseVersion = deriveBaseVersion();
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(baseVersion)) {
  console.warn(
    `\x1b[33m[warn] "${baseVersion}" does not look like a semver string; npm may reject it.\x1b[0m`,
  );
}
const platformVersion = (tag) => `${baseVersion}-${tag}`;

// --- locate goreleaser binaries -------------------------------------------

function findSourceBinary(goos, goarch) {
  if (!existsSync(DIST_DIR)) {
    fail(
      `${DIST_DIR} not found. Build cross-platform binaries first ` +
        `(e.g. \`make snapshot\`).`,
    );
  }
  const re = new RegExp(`^vigolium_${goos}_${goarch}(?:_.+)?$`);
  const dirs = readdirSync(DIST_DIR)
    .filter((d) => re.test(d))
    .filter((d) => existsSync(path.join(DIST_DIR, d, "vigolium")))
    .sort();
  if (dirs.length === 0) return null;
  if (dirs.length > 1) {
    console.warn(
      `\x1b[33m[warn] multiple goreleaser dirs for ${goos}/${goarch}: ` +
        `${dirs.join(", ")} — using ${dirs[0]}\x1b[0m`,
    );
  }
  return path.join(DIST_DIR, dirs[0], "vigolium");
}

// --- embedded audit blob verification -------------------------------------

// Loader strings that uniquely fingerprint an embedded executable's OS. The
// vigolium-audit blob and the jsscan blob are dynamically-linked native
// binaries that carry their platform's loader path. jsscan is embedded with
// per-platform go:build tags (internal/resources/deparos/embed_jsscan_*.go),
// so for any cross-compile only the matching-OS jsscan is present — the audit
// blob is the only other native binary. Verified empirically: a correct-OS
// vigolium build carries ZERO foreign-OS loader markers, so a foreign marker
// can only come from a mis-staged audit blob.
//
// Note: Linux ELF interpreter strings are NOT used as arch discriminators —
// the Go runtime itself bakes in "/lib64/ld-linux-x86-64.so.2" on every Linux
// build regardless of GOARCH, so it is not a reliable signal. Same-OS arch
// swaps (linux x64<->arm64, darwin x64<->arm64) are left to the runtime guard
// in pkg/audit/bin and the staging script's own format assertion.
const MACHO_MARKERS = ["/usr/lib/libSystem.B.dylib", "/usr/lib/dyld"];
const ELF_INTERP_MARKERS = [
  "/lib64/ld-linux-x86-64.so.2",
  "/lib/ld-linux-aarch64.so.1",
];

// verifyEmbeddedAudit is the release backstop for the per-target go:embed
// staging. It fails the npm build if a packaged binary embeds an audit blob
// for the wrong OS — the v0.1.15-beta bug, where a macOS arm64 audit binary
// was baked into the linux-x64 package.
function verifyEmbeddedAudit(buf, p) {
  const has = (s) => buf.indexOf(Buffer.from(s, "latin1")) !== -1;

  let foreign = [];
  if (p.os === "linux") foreign = MACHO_MARKERS.filter(has);
  else if (p.os === "darwin") foreign = ELF_INTERP_MARKERS.filter(has);

  if (foreign.length) {
    fail(
      `${p.tag}: WRONG-OS vigolium-audit blob embedded — found foreign loader ` +
        `marker(s) [${foreign.join(", ")}] in the ${p.tag} binary. A non-${p.os} ` +
        `audit blob was baked in at build time (cross-compile packaging bug — ` +
        `check the goreleaser audit staging hook in .goreleaser.yaml).`,
    );
  }
  info(`verified ${p.tag} embeds no foreign-OS vigolium-audit blob`);
}

// --- staging --------------------------------------------------------------

function writeJson(file, obj) {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(obj, null, 2) + "\n");
}

function humanSize(bytes) {
  return `${(bytes / 1048576).toFixed(0)} MB`;
}

async function gzipBuffer(buf, dest) {
  mkdirSync(path.dirname(dest), { recursive: true });
  await pipeline(
    Readable.from([buf]),
    createGzip({ level: 9 }),
    createWriteStream(dest),
  );
}

async function stagePlatformPackage(p) {
  const src = findSourceBinary(p.goos, p.goarch);
  if (!src) {
    if (allowMissing.has(p.tag)) {
      console.warn(
        `\x1b[33m[warn] skipping ${p.tag}: no binary for ${p.goos}/${p.goarch}\x1b[0m`,
      );
      return false;
    }
    fail(
      `Missing binary for ${p.goos}/${p.goarch} (tag ${p.tag}). ` +
        `Run \`make snapshot\` or pass --allow-missing=${p.tag}.`,
    );
  }

  const binBuf = readFileSync(src);
  verifyEmbeddedAudit(binBuf, p);

  const pkgDir = path.join(OUT_DIR, `vigolium-${p.tag}`);
  const gzPath = path.join(pkgDir, "vendor", p.tag, "vigolium.gz");

  info(`packaging ${p.tag} (${humanSize(binBuf.length)} -> gzip)`);
  await gzipBuffer(binBuf, gzPath);

  writeJson(path.join(pkgDir, "package.json"), {
    name: NPM_NAME,
    version: platformVersion(p.tag),
    description: `${DESCRIPTION} (${p.tag} prebuilt binary)`,
    license: LICENSE_ID,
    homepage: HOMEPAGE,
    repository: REPOSITORY,
    os: [p.os],
    cpu: [p.cpu],
    engines: ENGINES,
    files: ["vendor"],
  });
  if (existsSync(README_SRC)) copyFileSync(README_SRC, path.join(pkgDir, "README.md"));
  if (existsSync(LICENSE_SRC)) copyFileSync(LICENSE_SRC, path.join(pkgDir, "LICENSE"));

  console.log(
    `    -> ${pkgDir}  (vendor unpacked ${humanSize(statSync(gzPath).size)})`,
  );
  return true;
}

function stageMainPackage(stagedTags) {
  const pkgDir = path.join(OUT_DIR, "vigolium");
  const binDir = path.join(pkgDir, "bin");
  mkdirSync(binDir, { recursive: true });
  copyFileSync(LAUNCHER_SRC, path.join(binDir, "vigolium.js"));
  if (existsSync(README_SRC)) copyFileSync(README_SRC, path.join(pkgDir, "README.md"));
  if (existsSync(LICENSE_SRC)) copyFileSync(LICENSE_SRC, path.join(pkgDir, "LICENSE"));

  const optionalDependencies = {};
  for (const p of PLATFORMS) {
    if (!stagedTags.has(p.tag)) continue;
    optionalDependencies[`${NPM_NAME}-${p.tag}`] =
      `npm:${NPM_NAME}@${platformVersion(p.tag)}`;
  }

  writeJson(path.join(pkgDir, "package.json"), {
    name: NPM_NAME,
    version: baseVersion,
    description: DESCRIPTION,
    keywords: KEYWORDS,
    license: LICENSE_ID,
    homepage: HOMEPAGE,
    repository: REPOSITORY,
    type: "module",
    bin: { vigolium: "bin/vigolium.js" },
    engines: ENGINES,
    files: ["bin"],
    optionalDependencies,
  });
  info(`staged main package -> ${pkgDir}`);
}

function npmPack(pkgDir) {
  const res = spawnSync(
    "npm",
    ["pack", "--json", "--pack-destination", OUT_DIR],
    { cwd: pkgDir, encoding: "utf8" },
  );
  if (res.status !== 0) {
    fail(`npm pack failed in ${pkgDir}:\n${res.stderr || res.stdout}`);
  }
  try {
    const out = JSON.parse(res.stdout);
    const name = out[0]?.filename;
    if (name) console.log(`    -> ${path.join(OUT_DIR, name)}`);
  } catch {
    /* non-fatal: tarball is still written */
  }
}

// --- main -----------------------------------------------------------------

info(`vigolium npm build — version ${baseVersion}`);
if (existsSync(OUT_DIR)) rmSync(OUT_DIR, { recursive: true, force: true });
mkdirSync(OUT_DIR, { recursive: true });

const stagedTags = new Set();
for (const p of PLATFORMS) {
  if (await stagePlatformPackage(p)) stagedTags.add(p.tag);
}
if (stagedTags.size === 0) fail("No platform packages were staged.");
stageMainPackage(stagedTags);

if (doPack) {
  info("running npm pack on each staged package...");
  npmPack(path.join(OUT_DIR, "vigolium"));
  for (const tag of stagedTags) npmPack(path.join(OUT_DIR, `vigolium-${tag}`));
}

info("done.");
console.log(`\nStaged in ${OUT_DIR}:`);
console.log(`  ${NPM_NAME}@${baseVersion}  (main)`);
for (const tag of stagedTags) {
  console.log(`  ${NPM_NAME}@${platformVersion(tag)}  (${tag})`);
}
console.log(
  `\nVerify:  node ${path.join(OUT_DIR, "vigolium", "bin", "vigolium.js")} version`,
);
