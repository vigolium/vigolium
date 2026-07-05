#!/usr/bin/env bun
/**
 * Refresh the vendored `vigolium-scanner` skill from the Go `vigolium` repo.
 *
 * The bridge (`vigolium-audit bridge …`) always loads this skill so the driven
 * agent knows how to operate the `vigolium` CLI. The canonical source lives in
 * the scanner repo at `public/skills/vigolium-scanner/`; we vendor a copy under
 * `src/content/skills/` so the compiled audit binary is self-contained (the
 * skill ships inside `content-bundle.json`).
 *
 * This script re-copies the canonical tree over the vendored one so the copy
 * doesn't silently drift. Point it at the scanner checkout via
 * `VIGOLIUM_REPO` (defaults to a sibling `../vigolium`).
 *
 *   bun run scripts/sync-scanner-skill.ts
 *   VIGOLIUM_REPO=/path/to/vigolium bun run scripts/sync-scanner-skill.ts
 */
import { cpSync, existsSync, rmSync } from "fs";
import { dirname, join, resolve } from "path";
import { fileURLToPath } from "url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DEST = join(ROOT, "src", "content", "skills", "vigolium-scanner");

function main(): void {
  const repo = resolve(process.env.VIGOLIUM_REPO ?? join(ROOT, "..", "vigolium"));
  const src = join(repo, "public", "skills", "vigolium-scanner");
  if (!existsSync(join(src, "SKILL.md"))) {
    console.error(
      `[sync-scanner-skill] scanner skill not found at ${src}\n` +
        `  Set VIGOLIUM_REPO to your vigolium checkout (currently: ${repo}).`,
    );
    process.exit(1);
  }
  rmSync(DEST, { recursive: true, force: true });
  cpSync(src, DEST, { recursive: true });
  console.log(`[sync-scanner-skill] vendored ${src} → ${DEST.replace(ROOT + "/", "")}`);
}

if (import.meta.main) main();
