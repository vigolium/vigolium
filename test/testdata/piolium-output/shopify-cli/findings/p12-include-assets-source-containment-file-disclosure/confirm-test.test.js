import {expect, test, vi} from 'vitest'
import {mkdtemp, mkdir, readFile, writeFile} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {copyConfigKeyEntry} from '../../../packages/app/src/cli/services/build/steps/include-assets/copy-config-key-entry.js'

const findingDir = dirname(fileURLToPath(import.meta.url))
const evidenceDir = join(findingDir, 'evidence')
const observationPath = join(evidenceDir, 'confirm-test-observation.json')

const makeContext = (configuration, stdout) => ({
  extension: {configuration},
  options: {stdout},
  stepResults: new Map(),
})

test('test_confirm_p12_include_assets_source_containment_file_disclosure_nosessid', async () => {
  await mkdir(evidenceDir, {recursive: true})
  const workDir = await mkdtemp(join(tmpdir(), 'piolium-include-assets-confirm-'))
  const extensionDir = join(workDir, 'app', 'extensions', 'admin-ext')
  const outDir = join(workDir, 'deploy-bundle')
  await mkdir(extensionDir, {recursive: true})
  await mkdir(outDir, {recursive: true})
  const outsidePath = join(workDir, 'app', 'extensions', '.env')
  const marker = `PIOLIUM_INCLUDE_ASSETS_CONFIRM_${Date.now()}`
  await writeFile(outsidePath, `LOCAL_SECRET_MARKER=${marker}\n`)
  const stdout = {write: vi.fn()}
  const context = makeContext({admin: {static_root: '../.env'}}, stdout)

  const result = await copyConfigKeyEntry({
    key: 'admin.static_root',
    baseDir: extensionDir,
    outputDir: outDir,
    context,
  })

  const copiedPath = join(outDir, '.env')
  const copied = await readFile(copiedPath, 'utf8')
  await writeFile(
    observationPath,
    JSON.stringify(
      {
        finding: 'p12-include-assets-source-containment-file-disclosure',
        attackerConfig: {admin: {static_root: '../.env'}},
        extensionDir,
        outsidePath,
        outputDir: outDir,
        copiedPath,
        filesCopied: result.filesCopied,
        pathMap: Object.fromEntries(result.pathMap),
        stdout: stdout.write.mock.calls.map((call) => call[0]),
        copied,
        marker,
        confirmed: copied.includes(marker) && result.pathMap.get('../.env') === '.env',
      },
      null,
      2,
    ),
  )

  expect(result.filesCopied).toBe(1)
  expect(result.pathMap.get('../.env')).toBe('.env')
  expect(copied).toContain(marker)
  expect(stdout.write).toHaveBeenCalledWith(expect.stringContaining("Included '../.env'"))
})
