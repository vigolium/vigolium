import { spawnSync } from "child_process";

/**
 * Build metadata surfaced by `archon --version`.
 *
 * In compiled binaries, BUILD_DATE and COMMIT_HASH are baked in by `build.ts`
 * via Bun's `--define` flag. In dev mode the env vars are absent — fall back
 * to the current ISO timestamp for the date and a runtime `git rev-parse`
 * for the commit.
 */
export const BUILD_DATE: string =
  process.env["ARCHON_BUILD_DATE"] ?? new Date().toISOString().replace(/\.\d+Z$/, "Z");

export const COMMIT_HASH: string = process.env["ARCHON_COMMIT"] ?? devGitShort();

export const AUTHOR = "@j3ssie";
export const LICENSE = "self-hosted";
export const WEBSITE = "https://www.vigolium.com";
export const DOCS = "https://docs.vigolium.com";

function devGitShort(): string {
  const r = spawnSync("git", ["rev-parse", "--short", "HEAD"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (r.status !== 0) return "dev";
  return r.stdout.trim() || "dev";
}
