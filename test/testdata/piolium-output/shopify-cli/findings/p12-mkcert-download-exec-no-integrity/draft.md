---
id: p12
slug: mkcert-download-exec-no-integrity
severity: info
---

Phase: 12
Sequence: 002
Slug: mkcert-download-exec-no-integrity
Verdict: VALID
Rationale: The localhost certificate helper downloads `mkcert` from a GitHub release, makes it executable via the shared release downloader, and later runs it without checksum/signature verification.
Severity-Original: MEDIUM
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
Origin-Finding: piolium/findings-draft/p10-005-cloudflared-download-exec-no-integrity.md
Origin-Pattern: AP-010-005

## Summary
When no configured or system `mkcert` is available, the CLI downloads `mkcert` into the app's `.shopify` directory and executes it to generate local HTTPS certificates. The release download helper writes and chmods the artifact but does not verify a pinned checksum, signature, or digest.

## Location
- `packages/app/src/cli/utilities/mkcert.ts:23-47` — selects the app-local `.shopify/mkcert` path when no env/system binary is available.
- `packages/app/src/cli/utilities/mkcert.ts:56-76` — constructs platform release asset names and calls `downloadGitHubRelease()`.
- `packages/cli-kit/src/public/node/github.ts:141-170` — downloads release bytes, writes them, `chmod`s them, and moves them to the target path.
- `packages/app/src/cli/utilities/mkcert.ts:185-186` — executes the resulting `mkcertPath`.

## Attacker Control
A compromised `FiloSottile/mkcert` release asset, poisoned cache, or trusted-network/TLS-breaking attacker can provide the bytes downloaded by `downloadGitHubRelease()`.

## Trust Boundary Crossed
External release bytes cross into local executable trust and are launched by the CLI in the developer's user context.

## Impact
Local code execution when certificate generation downloads and runs a malicious `mkcert` artifact; the flow may also prompt for password/trust-store changes.

## Evidence
`downloadMkcert()` calls `downloadGitHubRelease(MKCERT_REPO, MKCERT_VERSION, assetName, targetPath)`. The helper fetches the URL, writes `Buffer.from(await response.arrayBuffer())`, performs `chmod(tempPath, 0o755)`, and moves it to `targetPath`. `generateCertificate()` then runs `await exec(mkcertPath, ['-install', ...])`. No integrity verification is present between download and execution.

## Reproduction Steps
1. Ensure no system `mkcert` is available and remove the app-local `.shopify/mkcert` cache.
2. In a controlled test, replace the expected GitHub release response with a benign test executable.
3. Trigger localhost certificate generation.
4. Observe the downloaded executable placed at `.shopify/mkcert` and invoked without checksum or signature validation.
