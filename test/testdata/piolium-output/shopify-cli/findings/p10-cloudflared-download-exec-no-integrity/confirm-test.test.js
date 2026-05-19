import {expect, test, vi} from 'vitest'
import {mkdtemp, mkdir, readFile, stat, writeFile} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join, dirname} from 'node:path'
import {Readable} from 'node:stream'
import {fileURLToPath} from 'node:url'
import * as http from '@shopify/cli-kit/node/http'
import {exec} from '@shopify/cli-kit/node/system'
import install from '../../../packages/plugin-cloudflare/src/install-cloudflared.js'

const findingDir = dirname(fileURLToPath(import.meta.url))
const evidenceDir = join(findingDir, 'evidence')
const observationPath = join(evidenceDir, 'confirm-test-observation.json')

function shellQuote(value) {
  return `'${value.replace(/'/g, `'"'"'`)}'`
}

async function waitForFileContaining(path, marker) {
  let last = ''
  for (let attempt = 0; attempt < 40; attempt++) {
    try {
      last = await readFile(path, 'utf8')
      if (last.includes(marker)) return last
    } catch {
      // file not written yet
    }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error(`Timed out waiting for ${marker} in ${path}. Last content: ${last}`)
}

test('test_confirm_p10_cloudflared_download_exec_no_integrity_nosessid', async () => {
  await mkdir(evidenceDir, {recursive: true})
  const workDir = await mkdtemp(join(tmpdir(), 'piolium-cloudflared-confirm-'))
  const binPath = join(workDir, 'cloudflared')
  const impactPath = join(workDir, 'impact.log')
  const payload = `#!/bin/sh\necho CLOUDFLARED_PAYLOAD_EXECUTED > ${shellQuote(impactPath)}\necho "argv=$*" >> ${shellQuote(impactPath)}\necho "2026-05-01T00:00:00Z INF |  https://poc.trycloudflare.com"\necho "2026-05-01T00:00:00Z INF Connection registered"\nexit 0\n`
  const fetchedUrls = []
  vi.spyOn(http, 'fetch').mockImplementation(async (url) => {
    fetchedUrls.push(String(url))
    return {ok: true, status: 200, statusText: 'OK', body: Readable.from([Buffer.from(payload)])}
  })

  await install({SHOPIFY_CLI_CLOUDFLARED_PATH: binPath}, 'linux', 'x64')
  const mode = (await stat(binPath)).mode & 0o777
  await exec(binPath, ['tunnel', '--url', 'http://localhost:18181', '--no-autoupdate'])
  const impact = await waitForFileContaining(impactPath, 'CLOUDFLARED_PAYLOAD_EXECUTED')
  await writeFile(
    observationPath,
    JSON.stringify(
      {
        finding: 'p10-cloudflared-download-exec-no-integrity',
        fetchedUrls,
        installedBinary: binPath,
        installedModeOctal: mode.toString(8),
        execArgs: ['tunnel', '--url', 'http://localhost:18181', '--no-autoupdate'],
        impactLog: impact,
        confirmed: impact.includes('argv=tunnel --url http://localhost:18181 --no-autoupdate'),
      },
      null,
      2,
    ),
  )

  expect(fetchedUrls[0]).toContain('https://github.com/cloudflare/cloudflared/releases/download/')
  expect(mode & 0o111).not.toBe(0)
  expect(impact).toContain('CLOUDFLARED_PAYLOAD_EXECUTED')
  expect(impact).toContain('argv=tunnel --url http://localhost:18181 --no-autoupdate')
})
