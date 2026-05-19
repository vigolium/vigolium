import {expect, test, vi} from 'vitest'
import {mkdir, writeFile} from 'node:fs/promises'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'

const childProcessMocks = vi.hoisted(() => ({
  exec: vi.fn((command, callback) => {
    if (typeof callback === 'function') callback(undefined, '', '')
    return {pid: 4242}
  }),
  spawn: vi.fn(),
}))

vi.mock('child_process', () => ({
  exec: childProcessMocks.exec,
  spawn: childProcessMocks.spawn,
}))

import {treeKill} from '../../../packages/cli-kit/src/public/node/tree-kill.js'

const findingDir = dirname(fileURLToPath(import.meta.url))
const evidenceDir = join(findingDir, 'evidence')
const observationPath = join(evidenceDir, 'confirm-test-observation.json')

function setProcessProperty(name, value) {
  const original = Object.getOwnPropertyDescriptor(process, name)
  Object.defineProperty(process, name, {value, configurable: true, enumerable: original?.enumerable ?? true})
  return () => {
    if (original) Object.defineProperty(process, name, original)
  }
}

test('test_confirm_p10_tree_kill_windows_command_injection_nosessid', async () => {
  await mkdir(evidenceDir, {recursive: true})
  const restorePlatform = setProcessProperty('platform', 'win32')
  const payload = '2147483647 & echo PIOLIUM_TREEKILL_CONFIRM>pwned.txt & rem'
  try {
    treeKill(payload, 'SIGTERM', true, () => {})
  } finally {
    restorePlatform()
  }

  expect(childProcessMocks.exec).toHaveBeenCalledTimes(1)
  const command = childProcessMocks.exec.mock.calls[0][0]
  await writeFile(
    observationPath,
    JSON.stringify(
      {
        finding: 'p10-tree-kill-windows-command-injection',
        sink: 'child_process.exec',
        simulatedPlatform: 'win32',
        attackerControlledPid: payload,
        observedCommand: command,
        confirmed: command.includes(payload) && command.includes('& echo PIOLIUM_TREEKILL_CONFIRM'),
      },
      null,
      2,
    ),
  )

  expect(command).toContain(payload)
  expect(command).toContain('& echo PIOLIUM_TREEKILL_CONFIRM')
})
