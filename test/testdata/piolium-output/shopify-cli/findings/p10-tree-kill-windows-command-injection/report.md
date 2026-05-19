# [p10] Windows `treeKill` string PID command injection

## Summary

`@shopify/cli-kit` exposes `treeKill(pid: number | string)`. On Windows, arbitrary string PIDs are not rejected because the code applies `Number.isNaN()` to a string value, then interpolates the original `pid` into a `child_process.exec()` command. A downstream CLI, plugin, or script that forwards attacker-controlled PID text to this public helper can execute shell commands as the invoking user. Vulnerability class: OS command injection (CWE-78). PoC status: **theoretical**; the prepared exploit requires Windows `cmd.exe` and was not executed on this Darwin host.

## Details

The public helper in [`packages/cli-kit/src/public/node/tree-kill.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/cli-kit/src/public/node/tree-kill.ts#L20-L31) explicitly accepts `number | string` and forwards the value into `adaptedTreeKill`. In the same file, the validation path preserves string input, checks it with `Number.isNaN()`, and the Windows branch later passes the unescaped original value into shell-based `exec()` ([lines 47-77](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/cli-kit/src/public/node/tree-kill.ts#L47-L77)):

```ts
export function treeKill(
  pid: number | string = process.pid,
  killSignal = 'SIGTERM',
  killRoot = true,
  callback?: AfterKillCallback,
): void {
  // ...
  adaptedTreeKill(pid, killSignal, killRoot, after)
}

function adaptedTreeKill(pid: number | string, killSignal: string, killRoot: boolean, callback: (error?: Error) => void): void {
  const rootPid = typeof pid === 'number' ? pid.toString() : pid

  if (Number.isNaN(rootPid)) {
    callback(new Error('pid must be a number'))
    return
  }

  switch (process.platform) {
    case 'win32':
      exec(`taskkill /pid ${pid} /T /F`, callback)
      break
```

For a string such as `2147483647 & echo SHOPIFY_CLI_TREEKILL_POC>marker.txt & rem`, `rootPid` remains a string and `Number.isNaN(rootPid)` evaluates to `false`. On `process.platform === 'win32'`, `child_process.exec()` invokes a shell, so `cmd.exe` interprets `&` command separators inside the PID string instead of treating the value as one taskkill argument.

The known first-party Shopify CLI call sites currently pass numeric process IDs, so this report is scoped to the exported library API and downstream consumers that pass untrusted PID text. It is not a standalone remote exploit in Shopify CLI without such a caller.

## Root Cause

The implementation accepts string PIDs at a public boundary but does not canonicalize and validate them as numeric process identifiers before use. `Number.isNaN()` is the wrong validation primitive for this path because it does not coerce strings; arbitrary strings are therefore considered valid. The Windows implementation also uses `exec()` with a formatted command string instead of invoking `taskkill` with an argument vector, allowing shell metacharacters in `pid` to reach `cmd.exe`.

## Proof of Concept (PoC)

PoC status from the finding draft: **theoretical**. The vulnerable branch is Windows-only, and the evidence environment is Darwin, so runtime exploitation was not executed here. The prepared script is `piolium/findings/p10-tree-kill-windows-command-injection/poc.js` and calls the real `treeKill` export when run on Windows.

Run on a Windows Node.js environment after building `@shopify/cli-kit`:

```sh
pnpm install --frozen-lockfile
pnpm --filter @shopify/cli-kit build
node piolium/findings/p10-tree-kill-windows-command-injection/poc.js
```

The PoC payload is:

```text
2147483647 & echo SHOPIFY_CLI_TREEKILL_POC>"<finding-dir>\\evidence\\tree-kill-win32-marker.txt" & rem
```

`taskkill` may fail for the non-existent PID, but the injected `echo` command is still parsed by `cmd.exe` and writes the marker file. The expected success marker from the PoC is:

```json
{"status":"confirmed","evidence":"marker file created by injected cmd.exe command: <path>","notes":""}
```

On non-Windows hosts, the same script exits `inconclusive` and records source-level evidence rather than claiming command execution.

## Impact

If a Windows CLI, plugin, or other downstream consumer passes attacker-controlled text into `treeKill()`, the attacker can execute arbitrary shell commands with the privileges of that process. Practical consequences include writing or deleting files, launching programs, changing project state, or running further commands in the developer's environment. Exposure is conditional on Windows and an untrusted string reaching this public helper; numeric-only first-party call sites are not directly exploitable.

## Remediation

Reject non-numeric PIDs before any platform-specific process execution, and avoid shell command construction for `taskkill`. For example, parse `pid` once, require a positive safe integer, use the canonical parsed value everywhere, and replace `exec()` with `execFile()`/`spawn()` using an argument array such as `['/pid', String(parsedPid), '/T', '/F']`. If string PID support is not required, narrow the public API to `number` and fail closed for all string input.

## Confirmation (V4)
Confirm-Status: blocked
Confirm-Timestamp: 2026-05-01T09:00:22Z
Confirm-Evidence: piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirmed-20260501T090022Z.log
Confirm-Variant-Count: 0
Confirm-FpCheck: not-run
Confirm-Notes: Local-only exploit path is routed to V5 per V4 instructions; no network PoC executed
Confirm-Queued-V5: yes

## Confirmation (V5 generated test)
Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: piolium/findings/p10-tree-kill-windows-command-injection/confirm-test.test.js
Confirm-Test-Output: piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirm-test-output.log; piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirm-test-observation.json; piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirm-test-command.sh
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-01T09:10:04Z
Confirm-Notes: Vitest mocked the Win32 platform and child_process.exec sink; attacker-controlled PID text containing cmd.exe metacharacters was observed verbatim in the taskkill command string.
