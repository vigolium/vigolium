#!/usr/bin/env bun
/**
 * npm publish orchestrator for the standalone `@vigolium/jstangle` CLI.
 *
 * Publishes ONE package: the normal `dist/` build (compiled JS + `.d.ts` types)
 * with `bin.jstangle -> dist/cli.js`. Runtime deps (babel, webcrack, graphql,
 * commander) are declared in `dependencies` and resolved by npm on install, so
 * `npm i -g @vigolium/jstangle` puts a working `jstangle` command on PATH.
 *
 * Flow: resolve version -> auto patch-bump only if the version is already on the
 * registry (so a first publish of 1.1.0 stays 1.1.0) -> `bun publish`. The build
 * itself is produced by the `prepublishOnly` lifecycle script (`bun run build`)
 * that bun runs before packing, so dist/ is always fresh.
 *
 * `bun publish` (not `npm publish`) is used deliberately: npm rejects this
 * manifest's `overrides` (which pin babel to exact versions that are also direct
 * deps) with EOVERRIDE, while bun — this project's package manager — honors them.
 * `access: public` comes from `publishConfig` in package.json.
 *
 * Env vars:
 *   JSTANGLE_VERSION      — pin the version to publish; disables auto-bump
 *   JSTANGLE_NPM_DRY_RUN=1 — validate + `bun publish --dry-run` only; no bump
 *                            write, no registry writes
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PKG_PATH = join(ROOT, 'package.json');
const PKG_NAME = '@vigolium/jstangle';
const DRY_RUN = process.env.JSTANGLE_NPM_DRY_RUN === '1';
const PINNED = process.env.JSTANGLE_VERSION;

const PREFIX = '\x1b[36m[*]\x1b[0m';

function step(msg: string): void {
  console.log(`${PREFIX} ${msg}`);
}

function run(cmd: string, args: string[]): void {
  const result = spawnSync(cmd, args, { cwd: ROOT, stdio: 'inherit' });
  if (result.status !== 0) {
    throw new Error(`${cmd} ${args.join(' ')} failed (exit ${result.status ?? 'signal'})`);
  }
}

function readVersion(): string {
  return String((JSON.parse(readFileSync(PKG_PATH, 'utf8')) as { version?: string }).version ?? '0.0.0');
}

/** True when `<PKG_NAME>@<version>` already exists on the registry. */
function isPublished(version: string): boolean {
  const result = spawnSync('npm', ['view', `${PKG_NAME}@${version}`, 'version'], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  // Non-empty stdout => that exact version exists. E404 (package/version missing)
  // yields empty stdout with a non-zero status, which we treat as "not published".
  return result.status === 0 && result.stdout.trim().length > 0;
}

/** Patch-bump, preserving any prerelease suffix (1.1.0 -> 1.1.1, 1.1.0-rc.1 -> 1.1.1-rc.1). */
function nextPatch(version: string): string {
  const m = /^(\d+)\.(\d+)\.(\d+)(-.+)?$/.exec(version);
  if (!m) throw new Error(`cannot parse version "${version}" (expected MAJOR.MINOR.PATCH[-prerelease])`);
  return `${m[1]}.${m[2]}.${Number(m[3]) + 1}${m[4] ?? ''}`;
}

/** Rewrite only the `"version":` line so the hand-maintained manifest formatting is untouched. */
function writeVersion(version: string): void {
  const raw = readFileSync(PKG_PATH, 'utf8');
  const next = raw.replace(/("version":\s*")[^"]+(")/, `$1${version}$2`);
  if (next === raw) throw new Error('failed to rewrite "version" field in package.json');
  writeFileSync(PKG_PATH, next);
}

function main(): void {
  let version = PINNED ?? readVersion();
  step(`package ${PKG_NAME}`);
  step(`requested version ${version}${PINNED ? ' (pinned via JSTANGLE_VERSION)' : ''}`);

  if (isPublished(version)) {
    if (PINNED) {
      throw new Error(`${PKG_NAME}@${version} is already published — cannot republish a pinned version`);
    }
    const bumped = nextPatch(version);
    step(`${version} already on registry; auto-bumping to ${bumped}`);
    version = bumped;
    if (isPublished(version)) {
      throw new Error(`${PKG_NAME}@${version} is also already published — bump manually`);
    }
  }

  if (DRY_RUN) {
    step(`dry run — would publish ${PKG_NAME}@${version} (package.json not modified)`);
    run('bun', ['publish', '--dry-run']);
    step('dry run complete');
    return;
  }

  if (version !== readVersion()) {
    step(`writing version ${version} to package.json`);
    writeVersion(version);
  }

  step(`publishing ${PKG_NAME}@${version} (prepublishOnly runs the build)`);
  run('bun', ['publish']);
  step(`published ${PKG_NAME}@${version}`);
}

try {
  main();
} catch (error) {
  console.error(`\x1b[31m[!]\x1b[0m ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
