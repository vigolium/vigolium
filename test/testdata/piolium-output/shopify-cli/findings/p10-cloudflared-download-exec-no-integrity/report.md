# [p10] Cloudflared installer executes downloaded release artifacts without integrity verification

## Summary

The Cloudflare tunnel plugin downloads a platform-specific `cloudflared` executable or archive from GitHub Releases and installs it into the CLI plugin binary path without verifying a pinned checksum, signature, or digest. If an attacker can replace that release artifact through a supply-chain compromise, poisoned cache, or trusted-network/TLS-breaking position, the CLI will write attacker-controlled bytes as `cloudflared` and execute them in the developer's local user context. This is a download-of-code-without-integrity-check weakness (CWE-494).

## Details

The installer builds the release URL from the hard-coded `CURRENT_CLOUDFLARE_VERSION` and a platform/architecture filename in [`packages/plugin-cloudflare/src/install-cloudflared.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/plugin-cloudflare/src/install-cloudflared.ts#L19-L55). The install path then downloads that URL and immediately promotes the downloaded bytes to the local binary path: Linux marks the file executable, Windows writes it directly, and macOS extracts the tarball and renames `cloudflared` into place. The decisive download/write path is in [`install-cloudflared.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/plugin-cloudflare/src/install-cloudflared.ts#L123-L150):

```ts
async function installLinux(file: string, binTarget: string) {
  await downloadFile(file, binTarget)
  await chmod(binTarget, '755')
}

async function installWindows(file: string, binTarget: string) {
  await downloadFile(file, binTarget)
}

async function installMacos(file: string, binTarget: string) {
  await downloadFile(file, `${binTarget}.tgz`)
  const filename = basename(`${binTarget}.tgz`)
  execSync(`tar -xzf ${filename}`, {cwd: dirname(binTarget)})
  unlinkFileSync(`${binTarget}.tgz`)
  await renameFile(`${dirname(binTarget)}/cloudflared`, binTarget)
}

async function downloadFile(url: string, to: string) {
  if (!fileExistsSync(dirname(to))) {
    mkdirSync(dirname(to))
  }
  const streamPipeline = util.promisify(pipeline)
  const response = await fetch(url, {redirect: 'follow'}, 'slow-request')
  if (!response.ok || !response.body)
    throw new Error(`Couldn't download file ${url} (${response.status} ${response.statusText})`)
  const fileObject = createFileWriteStream(to)
  await streamPipeline(response.body, fileObject)
  return to
}
```

No digest or signature check appears between `fetch(...)` and `streamPipeline(response.body, fileObject)`, nor before `chmod`, extraction, or rename. When a tunnel starts, [`TunnelClientInstance.startTunnel()` calls `install()`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/plugin-cloudflare/src/tunnel.ts#L53-L56), and the plugin later launches the installed path with [`exec(getBinPathTarget(), args, ...)`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/plugin-cloudflare/src/tunnel.ts#L131-L132):

```ts
await install()
this.tunnel()

// ...
exec(getBinPathTarget(), args, {
  stdout: customStdout,
  stderr: customStdout,
  signal: this.abortController.signal,
```

This crosses the trust boundary from externally downloaded release bytes into local executable code without an independently validated integrity decision.

## Root Cause

The installer trusts transport success from a GitHub Release URL as sufficient authorization to execute the artifact. It does not pin expected SHA-256 hashes, verify a signed checksum/provenance statement, or otherwise bind the downloaded artifact to an authenticated release identity before storing it in the executable path.

## Proof of Concept (PoC)

**PoC Status:** `executed`.

The self-contained PoC at `piolium/findings/p10-cloudflared-download-exec-no-integrity/poc.js` safely simulates a compromised release artifact by stubbing the CLI fetch helper to return a local payload archive, setting `SHOPIFY_CLI_CLOUDFLARED_PATH` to an isolated work directory, and invoking the real transformed installer/tunnel flow. It does not require external service provisioning.

Run:

```bash
cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli
node piolium/findings/p10-cloudflared-download-exec-no-integrity/poc.js
```

The executed evidence shows the installer accepted the replacement macOS artifact from the expected release URL, wrote it to the cloudflared bin path, and then executed it as the tunnel process:

```text
installer fetch log: {"url":"https://github.com/cloudflare/cloudflared/releases/download/2024.8.2/cloudflared-darwin-arm64.tgz","redirect":"follow","mode":"slow-request","artifact":"/Users/j3ssie/Desktop/oss-to-run/shopify-cli/piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/work/cloudflared-darwin.tgz","bytes":299}
installed binary: /Users/j3ssie/Desktop/oss-to-run/shopify-cli/piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/work/bin/cloudflared
tunnel status: {"status":"connected","url":"https://poc.trycloudflare.com"}
impact log: cloudflared payload executed | argv=tunnel --url http://localhost:18181 --no-autoupdate | uid=501
{"status":"confirmed","evidence":"impact.log shows downloaded cloudflared payload executed by tunnel launcher","notes":"downloaded bytes were written to the cloudflared bin path before execution"}
```

The impact marker captured in `evidence/impact.log` confirms code execution of the downloaded payload:

```text
cloudflared payload executed
argv=tunnel --url http://localhost:18181 --no-autoupdate
uid=501
```

The PoC ran on `darwin/arm64` with Node `v25.9.0`; the same trust-boundary issue applies to the Linux and Windows install branches because they also write the fetched artifact without an integrity check.

## Impact

A successful artifact replacement results in local code execution as the developer running Shopify CLI when the Cloudflare tunnel plugin installs or updates `cloudflared`. The realistic attacker precondition is supply-chain control over the release asset path or a trusted-network/TLS-breaking/caching position capable of supplying malicious bytes for the expected GitHub Release artifact; ordinary on-path attackers are still constrained by TLS. Under those conditions, the attacker can execute arbitrary commands with the user's local privileges, read or modify project files and environment variables available to the CLI process, and persist by leaving a malicious `cloudflared` binary at the plugin binary path.

## Remediation

Verify `cloudflared` artifacts before installation and fail closed on mismatch. A practical fix is to maintain versioned, platform-specific SHA-256 digests or signed provenance for `CURRENT_CLOUDFLARE_VERSION`, compute the digest of the downloaded file before `chmod`, extraction, rename, or execution, and abort if it does not match. Prefer signatures or Sigstore/GitHub artifact attestations when available, and ensure all Linux, macOS, and Windows branches share the same verification gate before writing to the final executable path.

## Confirmation (V4)
Confirm-Status: blocked
Confirm-Timestamp: 2026-05-01T09:00:29Z
Confirm-Evidence: piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirmed-20260501T090022Z.log
Confirm-Variant-Count: 0
Confirm-FpCheck: not-run
Confirm-Notes: Local-only exploit path is routed to V5 per V4 instructions; no network PoC executed
Confirm-Queued-V5: yes

## Confirmation (V5 generated test)
Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: piolium/findings/p10-cloudflared-download-exec-no-integrity/confirm-test.test.js
Confirm-Test-Output: piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirm-test-output.log; piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirm-test-observation.json; piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirm-test-command.sh
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-01T09:10:04Z
Confirm-Notes: Vitest mocked the cloudflared release fetch with a shell payload; install() wrote it as an executable and the CLI exec wrapper ran it with tunnel arguments, producing impact.log.
