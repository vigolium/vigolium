import { createHash } from "crypto";
import { cpSync, existsSync, mkdirSync, statSync, writeFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { getContentLoader } from "../content-loader.js";

/**
 * The skill that is ALWAYS loaded into a bridge session so the driven agent
 * knows how to operate the `vigolium` CLI (scan, scan-request, replay, oast,
 * traffic, agent modes, extensions). Vendored under `src/content/skills/` and
 * refreshed from the scanner repo via `scripts/sync-scanner-skill.ts`.
 */
export const ALWAYS_ON_SKILL = "vigolium-scanner";

export interface BridgePlugin {
  /** Absolute path to a Claude Code plugin dir (pass as AdapterRunInput.pluginDir). */
  dir: string;
  /** Skills that were resolved and copied in. */
  loadedSkills: string[];
  /** Requested skills that could not be resolved (skipped, not fatal). */
  missing: string[];
}

/**
 * Assemble an ephemeral Claude Code plugin containing the requested skills plus
 * the always-on `vigolium-scanner` skill, and return its path for the SDK's
 * `plugins:` option. The result is cached under
 * `~/.cache/vigolium-audit/bridge-plugins/plugin-<hash>/`, keyed on the skill
 * set and each skill's on-disk mtime — so a rebuilt binary or an edited skill
 * produces a fresh dir while repeat invocations (and a long-lived daemon) reuse
 * the same one.
 */
// Per-process cache: within a daemon the vendored skills and binary don't
// change, so an identical skill set resolves to the same plugin without
// re-stat/re-hash/re-copy. The on-disk `.ready`/hash guard below still handles
// cross-process invalidation (rebuilt binary, edited skill).
const pluginCache = new Map<string, BridgePlugin>();

export async function buildBridgePlugin(skills: string[]): Promise<BridgePlugin> {
  const loader = getContentLoader();
  const requested = [...new Set([ALWAYS_ON_SKILL, ...skills])].sort();

  const cacheKey = requested.join("\n");
  const cached = pluginCache.get(cacheKey);
  if (cached) return cached;

  const resolved: Array<{ name: string; srcDir: string; mtimeMs: number }> = [];
  const missing: string[] = [];
  for (const name of requested) {
    try {
      const srcDir = await loader.resolveSkillDir(name);
      resolved.push({ name, srcDir, mtimeMs: statSync(join(srcDir, "SKILL.md")).mtimeMs });
    } catch {
      missing.push(name);
    }
  }

  const key = createHash("sha256");
  for (const s of resolved) key.update(`${s.name}:${s.srcDir}:${s.mtimeMs}\0`);
  const hash = key.digest("hex").slice(0, 16);

  const cacheRoot = join(homedir(), ".cache", "vigolium-audit", "bridge-plugins");
  const dir = join(cacheRoot, `plugin-${hash}`);

  // `.ready` marks a fully-materialized dir; guards against reusing a partial
  // tree left by a crash mid-copy.
  if (!existsSync(join(dir, ".ready"))) {
    mkdirSync(join(dir, ".claude-plugin"), { recursive: true });
    mkdirSync(join(dir, "skills"), { recursive: true });
    writeFileSync(
      join(dir, ".claude-plugin", "plugin.json"),
      JSON.stringify(
        {
          name: "vigolium-bridge",
          description: "Vigolium bridge — skills for driving the vigolium CLI during triage/exploit/plan.",
          version: "1.0.0",
        },
        null,
        2,
      ),
    );
    for (const s of resolved) {
      cpSync(s.srcDir, join(dir, "skills", s.name), { recursive: true });
    }
    writeFileSync(join(dir, ".ready"), ""); // presence-only sentinel; the dir name already carries the hash
  }

  const plugin: BridgePlugin = { dir, loadedSkills: resolved.map((s) => s.name), missing };
  pluginCache.set(cacheKey, plugin);
  return plugin;
}
