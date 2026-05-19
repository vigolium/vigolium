import {expect, test, vi} from 'vitest'
import {mkdtemp, mkdir, readFile, stat, writeFile} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {dirname, join} from 'node:path'
import {Readable} from 'node:stream'
import {pipeline} from 'node:stream/promises'
import {createGunzip, gzipSync} from 'node:zlib'
import {fileURLToPath} from 'node:url'
import * as http from '@shopify/cli-kit/node/http'
import {exec} from '@shopify/cli-kit/node/system'
import {downloadBinary} from '../../../packages/app/src/cli/services/function/binaries.js'

const findingDir = dirname(fileURLToPath(import.meta.url))
const evidenceDir = join(findingDir, 'evidence')
const observationPath = join(evidenceDir, 'confirm-test-observation.json')

function shellQuote(value) {
  return `'${value.replace(/'/g, `'"'"'`)}'`
}

test('test_confirm_p12_function_toolchain_download_exec_no_integrity_nosessid', async () => {
  await mkdir(evidenceDir, {recursive: true})
  const workDir = await mkdtemp(join(tmpdir(), 'piolium-function-runner-confirm-'))
  const binPath = join(workDir, 'function-runner')
  const functionDir = join(workDir, 'function-extension')
  const wasmPath = join(functionDir, 'dist', 'function.wasm')
  const impactPath = join(workDir, 'impact.log')
  await mkdir(dirname(wasmPath), {recursive: true})
  await writeFile(wasmPath, 'not real wasm; payload confirms runner execution before parsing')
  const payload = `#!/bin/sh\necho FUNCTION_RUNNER_PAYLOAD_EXECUTED > ${shellQuote(impactPath)}\necho "argv=$*" >> ${shellQuote(impactPath)}\necho "cwd=$(pwd)" >> ${shellQuote(impactPath)}\nexit 0\n`
  const gzippedPayload = gzipSync(Buffer.from(payload))
  const fetchedUrls = []
  vi.spyOn(http, 'fetch').mockImplementation(async (url) => {
    fetchedUrls.push(String(url))
    return {status: 200, ok: true, body: Readable.from([gzippedPayload])}
  })

  const bin = {
    name: 'function-runner',
    version: '9.1.2-confirm',
    path: binPath,
    downloadUrl: () => 'https://github.com/Shopify/function-runner/releases/download/v9.1.2/function-runner-x86_64-linux-v9.1.2.gz',
    processResponse: async (responseStream, outputStream) => pipeline(responseStream, createGunzip(), outputStream),
  }

  await downloadBinary(bin)
  const mode = (await stat(binPath)).mode & 0o777
  await exec(binPath, ['-f', wasmPath], {cwd: functionDir})
  const impact = await readFile(impactPath, 'utf8')
  await writeFile(
    observationPath,
    JSON.stringify(
      {
        finding: 'p12-function-toolchain-download-exec-no-integrity',
        fetchedUrls,
        installedBinary: binPath,
        installedModeOctal: mode.toString(8),
        execArgs: ['-f', wasmPath],
        impactLog: impact,
        confirmed: impact.includes('FUNCTION_RUNNER_PAYLOAD_EXECUTED') && impact.includes(`argv=-f ${wasmPath}`),
      },
      null,
      2,
    ),
  )

  expect(fetchedUrls[0]).toContain('github.com/Shopify/function-runner/releases/download')
  expect(mode & 0o111).not.toBe(0)
  expect(impact).toContain('FUNCTION_RUNNER_PAYLOAD_EXECUTED')
  expect(impact).toContain(`argv=-f ${wasmPath}`)
})
