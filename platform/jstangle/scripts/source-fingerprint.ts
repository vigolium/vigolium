#!/usr/bin/env bun

import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

async function walk(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

export async function sourceFingerprint(): Promise<string> {
  const inputs = [
    ...await walk(join(root, 'src')),
    ...await walk(join(root, 'scripts')),
    join(root, 'package.json'),
    join(root, 'bun.lock'),
    join(root, 'tsconfig.json'),
    join(root, 'tsconfig.build.json'),
    join(root, 'vitest.config.ts'),
  ].sort((a, b) => relative(root, a).localeCompare(relative(root, b)));

  const hash = createHash('sha256');
  for (const input of inputs) {
    const rel = relative(root, input).replaceAll('\\', '/');
    hash.update(rel);
    hash.update('\0');
    hash.update(await readFile(input));
    hash.update('\0');
  }
  return `sha256:${hash.digest('hex')}`;
}

if (import.meta.main) process.stdout.write(`${await sourceFingerprint()}\n`);
