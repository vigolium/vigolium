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
const testName = `test_confirm_direct_git_url_ref_reaches_simple_git_clone_${sessionShort}`;

describe('Confirm p10-001 direct git URL/ref reaches simple-git clone boundary', () => {
  it(testName, async () => {
    await mkdir(evidenceDir, { recursive: true });
    const home = await mkdtemp(join(tmpdir(), 'skills-confirm-p10-001-home-'));
    const work = await mkdtemp(join(tmpdir(), 'skills-confirm-p10-001-work-'));
    const impactPath = join(evidenceDir, 'confirm-impact.log');
    const detailLog = join(evidenceDir, 'confirm-test-evidence.log');
    await rm(impactPath, { force: true });
    await writeFile(join(home, '.gitconfig'), '[protocol "ext"]\n    allow = always\n', 'utf-8');
    await mkdir(join(home, '.config'), { recursive: true });

    const payload = `ext::sh -c id% >${impactPath}% 2>&1`;
    const cli = join(repoRoot, 'bin', 'cli.mjs');
    const args = [cli, 'add', payload, '-y'];
    const env = {
      ...process.env,
      HOME: home,
      XDG_CONFIG_HOME: join(home, '.config'),
      GIT_CONFIG_NOSYSTEM: '1',
      SKILLS_CLONE_TIMEOUT_MS: '15000',
      NO_COLOR: '1',
      CI: '1',
      DISABLE_TELEMETRY: '1',
    };

    const result = spawnSync(process.execPath, args, {
      cwd: work,
      env,
      encoding: 'utf-8',
      timeout: 55_000,
      maxBuffer: 10 * 1024 * 1024,
    });
    const impact = existsSync(impactPath) ? await readFile(impactPath, 'utf-8') : '';
    const evidence = [
      `finding=p10-001-direct-git-url-ref-reaches-simple-git-clone`,
      `test_name=${testName}`,
      `cwd=${work}`,
      `command=${process.execPath} ${args.map((a) => JSON.stringify(a)).join(' ')}`,
      `payload=${payload}`,
      `exit_status=${result.status}`,
      `signal=${result.signal ?? ''}`,
      `timed_out=${result.error?.name === 'TimeoutError'}`,
      '--- stdout ---',
      result.stdout ?? '',
      '--- stderr ---',
      result.stderr ?? '',
      '--- impact ---',
      impact,
    ].join('\n');
    await writeFile(detailLog, evidence, 'utf-8');

    await rm(home, { recursive: true, force: true });
    await rm(work, { recursive: true, force: true });

    expect(impact, 'native git ext helper should write process identity to impact log').toMatch(/^uid=/m);
  }, 60_000);
});
