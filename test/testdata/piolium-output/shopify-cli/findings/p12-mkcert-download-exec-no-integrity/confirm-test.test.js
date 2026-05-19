import {expect, test, vi} from 'vitest'
import {mkdtemp, mkdir, readFile, stat, writeFile} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'
import * as http from '@shopify/cli-kit/node/http'
import * as prompts from '../../../packages/app/src/cli/prompts/dev.js'
import {generateCertificate} from '../../../packages/app/src/cli/utilities/mkcert.js'

const findingDir = dirname(fileURLToPath(import.meta.url))
const evidenceDir = join(findingDir, 'evidence')
const observationPath = join(evidenceDir, 'confirm-test-observation.json')

function shellQuote(value) {
  return `'${value.replace(/'/g, `'"'"'`)}'`
}

function toArrayBuffer(buffer) {
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)
}

test('test_confirm_p12_mkcert_download_exec_no_integrity_nosessid', async () => {
  await mkdir(evidenceDir, {recursive: true})
  const appDirectory = await mkdtemp(join(tmpdir(), 'piolium-mkcert-confirm-app-'))
  const impactPath = join(appDirectory, 'mkcert-impact.log')
  const payload = `#!/bin/sh\necho EXECUTED_MALICIOUS_MKCERT > ${shellQuote(impactPath)}\necho "argv=$*" >> ${shellQuote(impactPath)}\nkey=""\ncert=""\nwhile [ "$#" -gt 0 ]; do\n  case "$1" in\n    -key-file) shift; key="$1" ;;\n    -cert-file) shift; cert="$1" ;;\n  esac\n  shift\ndone\necho piolium-key > "$key"\necho piolium-cert > "$cert"\nexit 0\n`
  const fetchedUrls = []
  vi.spyOn(http, 'fetch').mockImplementation(async (url) => {
    const urlString = String(url)
    fetchedUrls.push(urlString)
    if (urlString.includes('/releases/download/')) {
      const body = Buffer.from(payload)
      return {ok: true, status: 200, statusText: 'OK', arrayBuffer: async () => toArrayBuffer(body)}
    }
    return {ok: true, status: 200, statusText: 'OK', text: async () => 'mkcert license placeholder'}
  })
  vi.spyOn(prompts, 'generateCertificatePrompt').mockResolvedValue(true)

  const oldPath = process.env.PATH
  process.env.PATH = '/no-such-directory-for-piolium-mkcert-confirm'
  try {
    const result = await generateCertificate({appDirectory, platform: 'linux', arch: 'x64'})
    const mkcertPath = join(appDirectory, '.shopify', 'mkcert')
    const mode = (await stat(mkcertPath)).mode & 0o777
    const impact = await readFile(impactPath, 'utf8')
    await writeFile(
      observationPath,
      JSON.stringify(
        {
          finding: 'p12-mkcert-download-exec-no-integrity',
          fetchedUrls,
          installedBinary: mkcertPath,
          installedModeOctal: mode.toString(8),
          certResult: result,
          impactLog: impact,
          confirmed: impact.includes('EXECUTED_MALICIOUS_MKCERT') && impact.includes('-install -key-file'),
        },
        null,
        2,
      ),
    )

    expect(fetchedUrls.some((url) => url.includes('github.com/FiloSottile/mkcert/releases/download/v1.4.4/'))).toBe(true)
    expect(mode & 0o111).not.toBe(0)
    expect(impact).toContain('EXECUTED_MALICIOUS_MKCERT')
    expect(impact).toContain('-install -key-file')
    expect(result.keyContent).toBe('piolium-key\n')
    expect(result.certContent).toBe('piolium-cert\n')
  } finally {
    process.env.PATH = oldPath
  }
})
