# [p12] Function toolchain downloads are executed without integrity verification

**CWE:** [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)  
**PoC Status:** executed

## Summary

Shopify CLI's app function toolchain downloads `function-runner`, `javy`, `shopify-function-trampoline`, the Javy plugin, and `wasm-opt` from GitHub releases or CDNs, caches them under the CLI package `bin` directory, and later executes them during function build/run workflows. If an attacker can replace one of those upstream artifacts before it is cached locally, the CLI accepts the bytes, marks them executable, and runs them in the developer's user context without checking a pinned digest or signature.

## Details

The native function-toolchain executable helper builds versioned GitHub release URLs for platform-specific artifacts in [`packages/app/src/cli/services/function/binaries.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/function/binaries.ts#L95-L135). The same file also fetches CDN-hosted tooling for the Javy plugin and `wasm-opt` via [`JavyPlugin.downloadUrl()`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/function/binaries.ts#L159-L165) and [`WasmOptExecutable.downloadUrl()`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/function/binaries.ts#L179-L185).

The decisive download path only checks whether the destination file already exists, fetches the remote response, processes/decompresses the stream, marks the resulting file executable, and moves it into the cached binary path. There is no checksum, signature, transparency-log, or pinned-digest validation between the network response and the executable cache:

```ts
export async function downloadBinary(bin: DownloadableBinary) {
  const isDownloaded = await fileExists(bin.path)
  if (isDownloaded) {
    return
  }

  const downloadOp = performDownload(bin)
  downloadsInProgress.set(bin.path, downloadOp)
  try {
    await downloadOp
  } finally {
    downloadsInProgress.delete(bin.path)
  }
}

async function performDownload(bin: DownloadableBinary) {
  const url = bin.downloadUrl(process.platform, process.arch)
  outputDebug(`Downloading ${bin.name} ${bin.version} from ${url} to ${bin.path}`)
  // ...
  const resp = await fetch(url, undefined, 'slow-request')
  // ...
  await inTemporaryDirectory(async (tmpDir) => {
    const tmpFile = joinPath(tmpDir, 'binary')
    const outputStream = createFileWriteStream(tmpFile)
    await bin.processResponse(responseStream, outputStream)
    await chmod(tmpFile, 0o775)
    await moveFile(tmpFile, bin.path, {overwrite: true})
  })
}
```

This snippet is from [`downloadBinary()`/`performDownload()`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/function/binaries.ts#L232-L303). After caching, the `app function run` path executes the downloaded `function-runner` path directly in [`runFunction()`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/function/runner.ts#L37-L65):

```ts
const functionRunner = await getFunctionRunnerBinary(ext)
await downloadBinary(functionRunner)

// ...

return exec(functionRunner.path, ['-f', functionPath, ...args], {
  cwd: options.functionExtension.directory,
  stdin: options.stdin,
  stdout: options.stdout ?? 'inherit',
  stderr: options.stderr ?? 'inherit',
  input: options.input,
})
```

The build workflow has the same trust boundary: [`runWasmOpt()`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/function/build.ts#L256-L281) invokes the downloaded `wasm-opt` wrapper with `node`, [`runTrampoline()`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/function/build.ts#L283-L304) executes the downloaded trampoline, and [`runJavy()`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/function/build.ts#L319-L349) executes the downloaded `javy` binary while passing the downloaded plugin path.

## Root Cause

The function tooling download model treats the artifact URL and version string as sufficient identity for executable code. `DownloadableBinary` implementations provide a `name`, `version`, `path`, and `downloadUrl()`, but no expected digest or signature metadata is enforced before the file is cached or executed. The cache also trusts file existence alone, so a previously poisoned binary is reused without later integrity validation.

## Proof of Concept (PoC)

The draft records `PoC-Status: executed`. The self-contained PoC at `piolium/findings/p12-function-toolchain-download-exec-no-integrity/poc.js` transforms the current `binaries.ts` and `runner.ts` into a local harness, stubs `fetch()` to emulate a compromised upstream `function-runner` release asset, downloads a gzipped shell payload, and calls `runFunction()`.

Run either of the following from the repository root:

```sh
node piolium/findings/p12-function-toolchain-download-exec-no-integrity/poc.js
# or
piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/exploit.sh
```

The captured evidence shows the malicious artifact was accepted from the expected GitHub release URL, installed with executable permissions, and then executed by the function runner path:

```text
fetch log: {"url":"https://github.com/Shopify/function-runner/releases/download/v9.1.2/function-runner-arm-macos-v9.1.2.gz","mode":"slow-request","artifact":".../evidence/work/function-runner.gz","bytes":172}
exec log: {"command":".../evidence/bin/function-runner-9.1.2","args":["-f",".../example-function/dist/function.wasm"],"cwd":".../evidence/work/example-function","status":0}
installed mode: 775
runner stdout: {"ok":true,"poc":"downloaded function-runner executed"}
impact log: function-runner payload executed | argv=-f .../example-function/dist/function.wasm | cwd=.../evidence/work/example-function | uid=501
{"status":"confirmed","evidence":"impact.log shows downloaded function-runner payload executed by app function runner path","notes":"downloadBinary accepted gzipped upstream bytes, chmodded/cached them, and runFunction executed the cached path without digest/signature validation"}
```

## Impact

A successful attack gives local code execution as the developer running Shopify CLI. Practical attacker positions include compromise of a GitHub release asset, compromise of the CDN-hosted tooling, a poisoned local cache before first use, or a trusted-network/TLS-breaking intermediary that can supply malicious artifact bytes. The executed payload could read project source, environment variables, Shopify credentials, access tokens, SSH keys, or other developer workstation secrets. This is a supply-chain/developer-workstation impact; it does not by itself imply unauthenticated remote compromise of a deployed Shopify app.

## Remediation

Publish and pin expected integrity metadata for every function-toolchain artifact version, and verify it before `chmod`, cache move, or execution. Prefer signed release artifacts with Sigstore/cosign or an equivalent signature scheme plus SHA-256 digests stored in the CLI source or a signed manifest. Fail closed on mismatch, delete untrusted cache entries, and consider revalidating cached executables instead of trusting file existence alone. Where possible, use package-manager integrity mechanisms or vendor immutable artifacts so CDN or release-asset compromise cannot silently become local code execution.

## Confirmation (V4)
Confirm-Status: blocked
Confirm-Timestamp: 2026-05-01T09:00:36Z
Confirm-Evidence: piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirmed-20260501T090022Z.log
Confirm-Variant-Count: 0
Confirm-FpCheck: not-run
Confirm-Notes: Local-only exploit path is routed to V5 per V4 instructions; no network PoC executed
Confirm-Queued-V5: yes

## Confirmation (V5 generated test)
Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: piolium/findings/p12-function-toolchain-download-exec-no-integrity/confirm-test.test.js
Confirm-Test-Output: piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirm-test-output.log; piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirm-test-observation.json; piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirm-test-command.sh
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-01T09:10:04Z
Confirm-Notes: Vitest mocked a gzipped function-runner release artifact; downloadBinary wrote/chmodded it and the CLI exec wrapper executed the downloaded payload with -f function.wasm.
