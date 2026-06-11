#!/usr/bin/env bun
/**
 * Walks src/content/ and writes src/content-bundle.json — a single JSON blob
 * keyed by relative path. The bundle is imported by content-loader at compile
 * time so the standalone binary doesn't need a sibling content tree at run
 * time.
 *
 * Run before `bun build --compile`. Idempotent; safe to run repeatedly in dev.
 */
import { readdirSync, readFileSync, statSync, writeFileSync } from "fs";
import { dirname, join, relative } from "path";
import { fileURLToPath } from "url";
// Single source of truth for the hash — the loader reads the same field at
// runtime to name its extraction cache dir, so the algorithm must not drift.
import { bundleContentHash } from "../src/content-loader.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(ROOT, "src", "content");
const OUT = join(ROOT, "src", "content-bundle.json");

interface Bundle {
  /** ISO timestamp at bundle time. Informational only — NOT used for caching. */
  generated_at: string;
  /**
   * SHA-256 over the (sorted) files map. Drives the extraction cache dir name
   * so identical content reuses the same `~/.cache/.../content-<hash>/` across
   * rebuilds instead of orphaning a fresh dir per timestamp.
   */
  content_hash: string;
  /** Map of relative-from-src/content path → file contents (UTF-8 text). */
  files: Record<string, string>;
}

function walk(dir: string, out: Record<string, string>): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      // Skip generated sdk-variants from the bundle iff we want to regenerate
      // them at install time — but since transform is build-time we include them.
      walk(path, out);
      continue;
    }
    if (!entry.isFile()) continue;
    // Only bundle text content the loader will read.
    const rel = relative(SRC, path);
    const ext = path.split(".").pop() ?? "";
    if (!["md", "yaml", "yml", "json", "sh", "py"].includes(ext)) continue;
    const stat = statSync(path);
    if (stat.size > 1024 * 1024) {
      console.warn(`[bundle] skipping large file: ${rel} (${stat.size} bytes)`);
      continue;
    }
    out[rel] = readFileSync(path, "utf8");
  }
}

function main(): void {
  const files: Record<string, string> = {};
  walk(SRC, files);
  const bundle: Bundle = {
    generated_at: new Date().toISOString(),
    content_hash: bundleContentHash(files),
    files,
  };
  writeFileSync(OUT, JSON.stringify(bundle));
  const count = Object.keys(files).length;
  const size = JSON.stringify(bundle).length;
  console.log(
    `[bundle] wrote ${count} files to ${relative(ROOT, OUT)} (${(size / 1024).toFixed(1)} KB, hash ${bundle.content_hash})`,
  );
}

if (import.meta.main) main();
