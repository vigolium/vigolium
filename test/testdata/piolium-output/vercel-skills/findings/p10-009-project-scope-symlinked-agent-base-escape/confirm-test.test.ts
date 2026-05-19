import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, realpath } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { installSkillForAgent } from '../../../src/installer.ts';

const findingDir = dirname(fileURLToPath(import.meta.url));
const evidenceDir = join(findingDir, 'evidence');
const sessionShort = (process.env.PIGOLIUM_SESSION_UUID || 'c44d2b43').slice(0, 8);
const testName = `test_confirm_project_scope_symlinked_agent_base_escape_${sessionShort}`;

describe('Confirm p10-009 project-scoped install follows symlinked .agents outside project', () => {
  it(testName, async () => {
    await mkdir(evidenceDir, { recursive: true });
    const root = await mkdtemp(join(tmpdir(), 'skills-confirm-p10-009-'));
    const project = join(root, 'victim-project');
    const outsideAgents = join(root, 'victim-home', '.agents');
    const source = join(project, 'malicious-skill');
    const skillName = 'symlink-escape-payload';
    const lexicalInstalled = join(project, '.agents', 'skills', skillName, 'SKILL.md');
    const outsideInstalled = join(outsideAgents, 'skills', skillName, 'SKILL.md');
    const detailLog = join(evidenceDir, 'confirm-test-evidence.log');

    try {
      await mkdir(project, { recursive: true });
      await mkdir(outsideAgents, { recursive: true });
      await symlink(outsideAgents, join(project, '.agents'), 'dir');
      await mkdir(source, { recursive: true });
      await writeFile(
        join(source, 'SKILL.md'),
        '---\nname: symlink-escape-payload\ndescription: payload\n---\nPIOLIUM_P10_009_PROJECT_SCOPE_SYMLINK_ESCAPE\n',
        'utf-8'
      );

      const result = await installSkillForAgent(
        { name: skillName, description: 'payload', path: source },
        'codex',
        { cwd: project, mode: 'copy', global: false }
      );
      const realInstalled = await realpath(lexicalInstalled);
      const content = await readFile(outsideInstalled, 'utf-8');
      const realProject = await realpath(project);
      const realOutside = await realpath(outsideAgents);
      await writeFile(
        detailLog,
        [
          `finding=p10-009-project-scope-symlinked-agent-base-escape`,
          `test_name=${testName}`,
          `project=${project}`,
          `project_.agents_symlink_target=${outsideAgents}`,
          `install_result=${JSON.stringify(result)}`,
          `lexical_installed=${lexicalInstalled}`,
          `real_installed=${realInstalled}`,
          `outside_installed=${outsideInstalled}`,
          `real_project=${realProject}`,
          `real_outside_agents=${realOutside}`,
          '--- outside SKILL.md ---',
          content,
        ].join('\n'),
        'utf-8'
      );

      expect(result.success).toBe(true);
      expect(realInstalled.startsWith(realProject)).toBe(false);
      expect(realInstalled.startsWith(realOutside)).toBe(true);
      expect(content).toContain('PIOLIUM_P10_009_PROJECT_SCOPE_SYMLINK_ESCAPE');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);
});
