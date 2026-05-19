import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, readlink } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const findingDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(findingDir, '../../..');
const evidenceDir = join(findingDir, 'evidence');
const sessionShort = (process.env.PIGOLIUM_SESSION_UUID || 'c44d2b43').slice(0, 8);
const testName = `test_confirm_project_scope_remove_symlinked_agent_base_escape_${sessionShort}`;

describe('Confirm p12 project-scoped remove follows symlinked .agents outside project', () => {
  it(testName, async () => {
    await mkdir(evidenceDir, { recursive: true });
    const root = await mkdtemp(join(tmpdir(), 'skills-confirm-p12-remove-'));
    const project = join(root, 'project');
    const outside = join(root, 'outside');
    const outsideSkill = join(outside, 'skills', 'victim-skill');
    const detailLog = join(evidenceDir, 'confirm-test-evidence.log');
    const cli = join(repoRoot, 'bin', 'cli.mjs');

    try {
      await mkdir(outsideSkill, { recursive: true });
      await mkdir(project, { recursive: true });
      await writeFile(join(outsideSkill, 'SKILL.md'), 'P12_SYMLINK_ESCAPE_SENTINEL\n', 'utf-8');
      await symlink(outside, join(project, '.agents'), 'dir');
      const before = existsSync(outsideSkill);
      const symlinkTarget = await readlink(join(project, '.agents'));
      const args = [cli, 'remove', 'victim-skill', '-y'];
      const result = spawnSync(process.execPath, args, {
        cwd: project,
        env: { ...process.env, CI: '1', NO_COLOR: '1', DISABLE_TELEMETRY: '1' },
        encoding: 'utf-8',
        timeout: 55_000,
        maxBuffer: 10 * 1024 * 1024,
      });
      const after = existsSync(outsideSkill);
      await writeFile(
        detailLog,
        [
          `finding=p12-project-scope-remove-symlinked-agent-base-escape`,
          `test_name=${testName}`,
          `cwd=${project}`,
          `project_.agents_symlink=${symlinkTarget}`,
          `outside_skill=${outsideSkill}`,
          `outside_exists_before=${before}`,
          `command=${process.execPath} ${args.map((a) => JSON.stringify(a)).join(' ')}`,
          `exit_status=${result.status}`,
          `signal=${result.signal ?? ''}`,
          `outside_exists_after=${after}`,
          '--- stdout ---',
          result.stdout ?? '',
          '--- stderr ---',
          result.stderr ?? '',
        ].join('\n'),
        'utf-8'
      );

      expect(before).toBe(true);
      expect(result.status).toBe(0);
      expect(after).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);
});
