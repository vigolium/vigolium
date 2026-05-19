# Theoretical PoC: Windows `treeKill` command injection

Runtime exploitation was not executed on this host because the vulnerable branch is gated by `process.platform === 'win32'` and requires Windows `cmd.exe` parsing. The PoC script in `poc.js` is runnable against the actual `@shopify/cli-kit` public API on Windows.

## Chain

1. A downstream CLI/plugin imports `treeKill` from `@shopify/cli-kit/node/tree-kill`.
2. It forwards attacker-controlled PID text to `treeKill(pid: number | string)`.
3. The code converts only numeric inputs and checks `Number.isNaN(rootPid)`, which is false for arbitrary strings.
4. On Windows, the original `pid` string is interpolated into ``child_process.exec(`taskkill /pid ${pid} /T /F`)``, so `cmd.exe` parses shell metacharacters.
5. The PoC passes:
   `2147483647 & echo SHOPIFY_CLI_TREEKILL_POC>"<finding-dir>\\evidence\\tree-kill-win32-marker.txt" & rem`
6. `taskkill` fails on the non-existent PID, but `& echo ...` still runs. The marker file proves command execution as the invoking user.

## Run on Windows

```sh
pnpm install --frozen-lockfile
pnpm --filter @shopify/cli-kit build
node piolium/findings/p10-tree-kill-windows-command-injection/poc.js
```

Expected final stdout line:

```json
{"status":"confirmed","evidence":"marker file created by injected cmd.exe command: <path>","notes":""}
```

On non-Windows hosts the script exits `inconclusive` and records source-level evidence in `evidence/impact.log`.
