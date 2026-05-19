---
Phase: 10
Sequence: 5
Slug: cloudflared-download-exec-no-integrity
Verdict: VALID
Severity-Original: MEDIUM
PoC-Status: executed
Pre-FP-Flag: supply-chain-precondition
Debate: piolium/chamber-workspace/c01-process-supply-chain/debate.md
Origin-Drafts: p4-006-cloudflared-download-exec-no-integrity.md
id: p10
slug: cloudflared-download-exec-no-integrity
severity: info
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
---

# Cloudflared installer executes downloaded release artifacts without integrity verification

## Summary
The Cloudflare tunnel plugin downloads platform-specific `cloudflared` artifacts from GitHub releases, writes them to the plugin binary path, marks or extracts them, and later executes the resulting binary. The code does not verify a pinned checksum, signature, or digest before execution.

## Location
- `packages/plugin-cloudflare/src/install-cloudflared.ts:20-45` — versioned release URL construction.
- `packages/plugin-cloudflare/src/install-cloudflared.ts:123-151` — download, write, chmod/extract without integrity verification.
- `packages/plugin-cloudflare/src/tunnel.ts:131-132` — executes `getBinPathTarget()`.

## Attacker Control
A compromised release asset, compromised GitHub account/release process, poisoned cache, or trusted-network/TLS-breaking attacker can supply malicious bytes to the installer path.

## Trust Boundary Crossed
External downloaded bytes cross into local executable trust and are launched in the developer's user context.

## Impact
Local code execution when the CLI installs or starts a malicious `cloudflared` artifact.

## Evidence
`downloadFile()` streams `fetch(url, {redirect: 'follow'})` directly to disk; Linux `chmod`s the file, macOS extracts the archive with `tar`, and `tunnel.ts` launches the resulting path. No checksum or signature verification was found in the install path.

## Reproduction Steps
1. Interpose or replace the expected `cloudflared` release artifact with a test executable in a controlled environment.
2. Trigger Cloudflared installation/start via the plugin.
3. Observe the downloaded bytes written to the plugin `bin` path and executed without a digest/signature check.
