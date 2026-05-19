import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const findingDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(findingDir, '../../..');
const evidenceDir = join(findingDir, 'evidence');
const sessionShort = (process.env.PIGOLIUM_SESSION_UUID || 'c44d2b43').slice(0, 8);
const testName = `test_confirm_unbounded_git_local_frontmatter_parse_${sessionShort}`;

describe('Confirm p12 unbounded SKILL.md frontmatter parsing from local sources', () => {
  it(testName, async () => {
    await mkdir(evidenceDir, { recursive: true });
    const root = await mkdtemp(join(tmpdir(), 'skills-confirm-p12-frontmatter-'));
    const source = join(root, 'malicious-skill');
    const detailLog = join(evidenceDir, 'confirm-test-evidence.log');
    const cli = join(repoRoot, 'bin', 'cli.mjs');

    try {
      await mkdir(source, { recursive: true });
      const keyCount = 500_000;
      const chunks: string[] = ['---\nname: oom-local-skill\ndescription: oversized frontmatter\n'];
      for (let i = 0; i < keyCount; i += 1) {
        chunks.push(`k${i}: ${i}\n`);
      }
      chunks.push('---\nBody\n');
      const payload = chunks.join('');
      await writeFile(join(source, 'SKILL.md'), payload, 'utf-8');

      const args = [cli, 'add', source, '--list'];
      const result = spawnSync(process.execPath, args, {
        cwd: root,
        env: {
          ...process.env,
          NODE_OPTIONS: '--max-old-space-size=32',
          CI: '1',
          NO_COLOR: '1',
          DISABLE_TELEMETRY: '1',
        },
        encoding: 'utf-8',
        timeout: 55_000,
        maxBuffer: 20 * 1024 * 1024,
      });
      const combined = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
      await writeFile(
        detailLog,
        [
          `finding=p12-unbounded-git-local-frontmatter-parse`,
          `test_name=${testName}`,
          `payload_bytes=${Buffer.byteLength(payload)}`,
          `key_count=${keyCount}`,
          `cwd=${root}`,
          `command=NODE_OPTIONS=--max-old-space-size=32 ${process.execPath} ${args.map((a) => JSON.stringify(a)).join(' ')}`,
          `exit_status=${result.status}`,
          `signal=${result.signal ?? ''}`,
          `spawn_error=${result.error ? String(result.error) : ''}`,
          '--- stdout ---',
          result.stdout ?? '',
          '--- stderr ---',
          result.stderr ?? '',
        ].join('\n'),
        'utf-8'
      );

      expect(result.status).not.toBe(0);
      expect(combined).toMatch(/FATAL ERROR|JavaScript heap out of memory|Allocation failed/i);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);
});
