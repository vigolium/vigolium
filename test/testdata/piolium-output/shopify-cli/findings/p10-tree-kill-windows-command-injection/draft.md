---
Phase: 10
Sequence: 1
Slug: tree-kill-windows-command-injection
Verdict: VALID
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: first-party-callers-numeric; public-library-api-remains-exploitable
Debate: piolium/chamber-workspace/c01-process-supply-chain/debate.md
Origin-Drafts: p4-001-tree-kill-windows-command-injection.md
id: p10
slug: tree-kill-windows-command-injection
severity: info
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
---

# Windows `treeKill` accepts string PIDs into a shell command

## Summary
`@shopify/cli-kit` exports `treeKill(pid: number | string)`. On Windows, non-numeric strings are not rejected because `Number.isNaN(rootPid)` is applied to a string, and the original `pid` is interpolated into `child_process.exec("taskkill ...")`. A downstream CLI/plugin that forwards untrusted PID text can turn this library helper into command execution on Windows.

## Location
- `packages/cli-kit/src/public/node/tree-kill.ts:20-31` — public helper accepts `number | string`.
- `packages/cli-kit/src/public/node/tree-kill.ts:53-56` — validation does not convert strings before `Number.isNaN`.
- `packages/cli-kit/src/public/node/tree-kill.ts:73-76` — Windows branch executes a shell command containing `pid`.

## Attacker Control
The exposed library API accepts caller-provided strings. First-party callers currently pass numeric `process.pid`/child PIDs, so severity is normalized from the original High to Medium; the production package still ships an unsafe public helper for downstream command/plugin code.

## Trust Boundary Crossed
Untrusted string data crosses from a public TypeScript API into Windows `cmd.exe` command parsing through `child_process.exec`.

## Impact
Command execution with the privileges of the invoking Shopify CLI consumer on Windows when attacker-controlled text reaches `treeKill()`.

## Evidence
```ts
export function treeKill(pid: number | string = process.pid, ...)
const rootPid = typeof pid === 'number' ? pid.toString() : pid
if (Number.isNaN(rootPid)) { ... } // false for arbitrary strings
exec(`taskkill /pid ${pid} /T /F`, callback)
```

## Reproduction Steps
1. On Windows, import `treeKill` from `@shopify/cli-kit/node/tree-kill`.
2. Call it with a string PID containing shell metacharacters, for example a value ending with `& <command>`.
3. Observe that the Windows branch builds a `taskkill` command line with the unescaped string instead of rejecting it as non-numeric.
