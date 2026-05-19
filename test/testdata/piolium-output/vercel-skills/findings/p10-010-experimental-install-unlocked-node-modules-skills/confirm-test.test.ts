import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const findingDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(findingDir, '../../..');
const evidenceDir = join(findingDir, 'evidence');
const sessionShort = (process.env.PIGOLIUM_SESSION_UUID || 'c44d2b43').slice(0, 8);
const testName = `test_confirm_experimental_install_unlocked_node_modules_skills_${sessionShort}`;

describe('Confirm p10-010 experimental_install installs unlisted node_modules skills', () => {
  it(testName, async () => {
    await mkdir(evidenceDir, { recursive: true });
    const project = await mkdtemp(join(tmpdir(), 'skills-confirm-p10-010-'));
    const safePkg = join(project, 'node_modules', 'benign-skill-package');
    const evilPkg = join(project, 'node_modules', 'transitive-evil-package');
    const installedEvil = join(project, '.agents', 'skills', 'malicious-lock-bypass', 'SKILL.md');
    const detailLog = join(evidenceDir, 'confirm-test-evidence.log');
    const cli = join(repoRoot, 'bin', 'cli.mjs');

    try {
      await mkdir(safePkg, { recursive: true });
      await mkdir(evilPkg, { recursive: true });
      await writeFile(
        join(safePkg, 'SKILL.md'),
        '---\nname: safe-locked-skill\ndescription: locked benign skill\n---\nSAFE_LOCKED_SKILL\n',
        'utf-8'
      );
      await writeFile(
        join(evilPkg, 'SKILL.md'),
        '---\nname: malicious-lock-bypass\ndescription: unlisted malicious skill\n---\nATTACKER_CONTROLLED_MARKER: unlisted-node-modules-skill-installed\n',
        'utf-8'
      );
      const initialLock = {
        version: 1,
        skills: {
          'safe-locked-skill': {
            source: 'benign-skill-package',
            sourceType: 'node_modules',
            computedHash: '0'.repeat(64),
          },
        },
      };
      await writeFile(join(project, 'skills-lock.json'), JSON.stringify(initialLock, null, 2), 'utf-8');

      const args = [cli, 'experimental_install'];
      const result = spawnSync(process.execPath, args, {
        cwd: project,
        env: { ...process.env, CI: '1', NO_COLOR: '1', DISABLE_TELEMETRY: '1' },
        encoding: 'utf-8',
        timeout: 55_000,
        maxBuffer: 10 * 1024 * 1024,
      });
      const installed = existsSync(installedEvil) ? await readFile(installedEvil, 'utf-8') : '';
      const finalLockRaw = await readFile(join(project, 'skills-lock.json'), 'utf-8');
      await writeFile(
        detailLog,
        [
          `finding=p10-010-experimental-install-unlocked-node-modules-skills`,
          `test_name=${testName}`,
          `cwd=${project}`,
          `command=${process.execPath} ${args.map((a) => JSON.stringify(a)).join(' ')}`,
          `initial_lock_contains_malicious=false`,
          `exit_status=${result.status}`,
          `signal=${result.signal ?? ''}`,
          '--- stdout ---',
          result.stdout ?? '',
          '--- stderr ---',
          result.stderr ?? '',
          `installed_evil=${installedEvil}`,
          '--- installed malicious SKILL.md ---',
          installed,
          '--- final skills-lock.json ---',
          finalLockRaw,
        ].join('\n'),
        'utf-8'
      );

      const finalLock = JSON.parse(finalLockRaw);
      expect(result.status).toBe(0);
      expect(initialLock.skills).not.toHaveProperty('malicious-lock-bypass');
      expect(installed).toContain('ATTACKER_CONTROLLED_MARKER: unlisted-node-modules-skill-installed');
      expect(finalLock.skills).toHaveProperty('malicious-lock-bypass');
    } finally {
      await rm(project, { recursive: true, force: true });
    }
  }, 60_000);
});
