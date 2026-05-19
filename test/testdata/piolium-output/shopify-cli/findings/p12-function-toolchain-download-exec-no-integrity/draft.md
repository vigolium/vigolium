---
id: p12
slug: function-toolchain-download-exec-no-integrity
severity: info
---

Phase: 12
Sequence: 001
Slug: function-toolchain-download-exec-no-integrity
Verdict: VALID
Rationale: The function build/run toolchain downloads versioned executables or JS/WASM tooling from GitHub/CDNs, chmods/caches them, and later executes them without an independent checksum/signature check.
Severity-Original: MEDIUM
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
Origin-Finding: piolium/findings-draft/p10-005-cloudflared-download-exec-no-integrity.md
Origin-Pattern: AP-010-005

## Summary
The app function toolchain repeats the Cloudflared pattern for `function-runner`, `javy`, `shopify-function-trampoline`, and `wasm-opt`: remote artifacts are fetched into the CLI package `bin` directory, marked executable, and used by function build/run commands without verifying a pinned digest or signature.

## Location
- `packages/app/src/cli/services/function/binaries.ts:63-134` — GitHub release URL construction for native `javy`, `function-runner`, and trampoline executables.
- `packages/app/src/cli/services/function/binaries.ts:147-183` — CDN URLs for the Javy plugin and `wasm-opt.cjs`.
- `packages/app/src/cli/services/function/binaries.ts:232-302` — `downloadBinary()` fetches, writes, `chmod`s, and moves artifacts without integrity verification.
- `packages/app/src/cli/services/function/build.ts:257-303` and `:325-344` — downloaded `wasm-opt`, trampoline, and `javy` are executed.
- `packages/app/src/cli/services/function/runner.ts:39-60` — downloaded `function-runner` is executed for `app function run`.

## Attacker Control
A compromised upstream release/CDN asset, poisoned cache, or trusted-network/TLS-breaking attacker can supply the artifact bytes before they are cached locally.

## Trust Boundary Crossed
External downloaded bytes cross into the local OS process boundary and are executed in the developer's user context.

## Impact
Local code execution when a developer builds or runs Shopify Functions after a malicious function toolchain artifact is downloaded.

## Evidence
`performDownload()` obtains `const resp = await fetch(url, undefined, 'slow-request')`, streams the body to a temp file, then runs `await chmod(tmpFile, 0o775)` and `await moveFile(tmpFile, bin.path, {overwrite: true})`. Subsequent build/run paths call `exec(javy.path, ...)`, `exec(trampoline.path, ...)`, `exec(functionRunner.path, ...)`, or `exec('node', [wasmOptBinary().name, ...], {cwd: wasmOptDir})` with those cached paths. No checksum, signature, or pinned digest validation appears in the download path.

## Reproduction Steps
1. In a controlled environment, replace one expected function-toolchain download response (for example a `javy` or `function-runner` release asset) with a benign test executable.
2. Trigger `shopify app function build` or `shopify app function run` on a project requiring that artifact.
3. Observe the CLI write and chmod the artifact into `packages/app/bin` and execute it without verifying a digest or signature.
