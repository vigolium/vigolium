# [p12] mkcert release download is executed without integrity verification

## Summary

When no configured, cached, or system `mkcert` binary is available, Shopify CLI downloads a `FiloSottile/mkcert` GitHub release asset into the app's `.shopify` directory, marks it executable, and later runs it to generate localhost certificates. The downloaded bytes are trusted solely because the HTTP request succeeded; no pinned checksum, signature, digest, or attestation is verified before execution. If the release asset or download path is compromised, attacker-controlled code runs in the developer's user context.

## Details

The localhost certificate flow first resolves the `mkcert` executable. In [`getMkcertPath`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/utilities/mkcert.ts#L25-L50), when there is no environment override, no app-local `.shopify/mkcert`, and no `mkcert` on `PATH`, the CLI downloads a new binary to the app-local path and returns that path for later execution:

```ts
const binaryName = platform === 'win32' ? 'mkcert.exe' : 'mkcert'
const defaultMkcertPath = joinPath(dotShopifyPath, binaryName)

if (await fileExists(defaultMkcertPath)) {
  return defaultMkcertPath
}

const mkcertLocation = await which('mkcert', {nothrow: true})
if (mkcertLocation) {
  outputDebug(outputContent`Found ${mkcertSnippet} at ${outputToken.path(mkcertLocation)}`)
  return mkcertLocation
}

await downloadMkcert(defaultMkcertPath, platform, arch)

return defaultMkcertPath
```

[`downloadMkcert`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/utilities/mkcert.ts#L58-L76) constructs the platform-specific asset name for `MKCERT_VERSION` and delegates the actual download to the shared GitHub release helper:

```ts
await downloadGitHubRelease(MKCERT_REPO, MKCERT_VERSION, assetName, targetPath)
```

The shared helper in [`downloadGitHubRelease`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/cli-kit/src/public/node/github.ts#L141-L170) fetches the release URL, writes the response body, makes it executable, and moves it into place. The decisive path has no integrity check between `arrayBuffer()` and `chmod`/`moveFile`:

```ts
response = await fetch(url, undefined, 'slow-request')
if (!response.ok) {
  throw new AbortError(`Failed to download ${assetName}: ${response.statusText}`)
}

const buffer = await response.arrayBuffer()
await writeFile(tempPath, Buffer.from(buffer))

await chmod(tempPath, 0o755)
await mkdir(dirname(targetPath))
await moveFile(tempPath, targetPath)
```

After resolution, [`generateCertificate`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/utilities/mkcert.ts#L185-L186) invokes the selected path directly:

```ts
await exec(mkcertPath, ['-install', '-key-file', keyPath, '-cert-file', certPath, 'localhost'])
```

## Root Cause

This is a download-and-execute supply-chain issue (CWE-494: Download of Code Without Integrity Check). The implementation treats a successful fetch from a GitHub release URL as sufficient authenticity for executable code, and the shared downloader even sets executable permissions before the caller runs the artifact. There is no pinned digest, release signature verification, trusted public key, or fail-closed integrity policy for the `mkcert` binary.

## Proof of Concept (PoC)

PoC-Status: `executed`.

The PoC at `piolium/findings/p12-mkcert-download-exec-no-integrity/poc.sh` creates a temporary Vitest spec that mocks `@shopify/cli-kit/node/http` so the expected mkcert release URL returns a benign shell payload. It then constrains `PATH` so no system `mkcert` is found, calls `generateCertificate({appDirectory, platform: 'linux', arch: 'x64'})`, and verifies that the downloaded `.shopify/mkcert` payload is executable and invoked.

```bash
cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli
piolium/findings/p12-mkcert-download-exec-no-integrity/poc.sh
```

The run completed successfully. `evidence/exploit.log` recorded the test marker:

```text
POC_MARKER downloaded mkcert executed without integrity check; mode=755
```

`evidence/impact.log` shows the controlled payload was launched from the app-local `.shopify/mkcert` path with the arguments passed by `generateCertificate`:

```text
EXECUTED_MALICIOUS_MKCERT
argv=-install -key-file /var/folders/2k/z4j3lfxj5fv7r20hswc8sj8r0000gn/T/shopify-mkcert-poc-l2C1cS/.shopify/localhost-key.pem -cert-file /var/folders/2k/z4j3lfxj5fv7r20hswc8sj8r0000gn/T/shopify-mkcert-poc-l2C1cS/.shopify/localhost.pem localhost
payload_path=/var/folders/2k/z4j3lfxj5fv7r20hswc8sj8r0000gn/T/shopify-mkcert-poc-l2C1cS/.shopify/mkcert
```

`evidence/poc-run.log` also concluded with:

```json
{"status":"confirmed","evidence":"downloaded .shopify/mkcert payload executed and wrote impact.log","notes":"controlled fetch response simulates compromised GitHub release asset"}
```

## Impact

A compromised `FiloSottile/mkcert` release asset, poisoned local cache, or trusted-network/TLS-breaking attacker that can supply the release bytes can obtain local code execution when a developer triggers localhost certificate generation and the CLI falls back to downloading `mkcert`. The payload runs with the developer's privileges, so it can read or modify project files, steal local credentials available to the user, tamper with development dependencies, or abuse the certificate-generation flow. This is not an unauthenticated remote exploit against a running service; it is a supply-chain/local developer execution risk that depends on the download fallback being reached.

## Remediation

Verify `mkcert` release assets before making them executable or invoking them. At minimum, pin expected SHA-256 digests for each supported platform/architecture and fail closed on mismatch. Prefer signature or provenance verification with a trusted key/attestation, and record the verified digest for cached `.shopify/mkcert` binaries so stale or replaced local artifacts are not silently trusted. Add a regression test that serves mismatched bytes for the mkcert release URL and asserts that certificate generation aborts before `chmod` or `exec`.

## Confirmation (V4)
Confirm-Status: blocked
Confirm-Timestamp: 2026-05-01T09:00:36Z
Confirm-Evidence: piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirmed-20260501T090022Z.log
Confirm-Variant-Count: 0
Confirm-FpCheck: not-run
Confirm-Notes: Local-only exploit path is routed to V5 per V4 instructions; no network PoC executed
Confirm-Queued-V5: yes

## Confirmation (V5 generated test)
Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: piolium/findings/p12-mkcert-download-exec-no-integrity/confirm-test.test.js
Confirm-Test-Output: piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirm-test-output.log; piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirm-test-observation.json; piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirm-test-command.sh
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-01T09:10:04Z
Confirm-Notes: Vitest mocked the mkcert GitHub release response; generateCertificate downloaded .shopify/mkcert, chmodded it, and executed the payload to create key/cert files.
