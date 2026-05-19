---
Phase: 10
Sequence: 3
Slug: extension-asset-symlink-file-read
Verdict: VALID
Severity-Original: MEDIUM
PoC-Status: executed
Pre-FP-Flag: requires-malicious-project-output-symlink
Debate: piolium/chamber-workspace/c03-ui-extension-dev-server/debate.md
Origin-Drafts: p4-004-extension-asset-symlink-file-read.md
id: p10
slug: extension-asset-symlink-file-read
severity: info
Protocol: http
Auth-Required: no
Auth-Roles-Required: anonymous
---

# Extension asset route follows symlinks after lexical containment

## Summary
`/extensions/:extensionId/assets/**` resolves the requested asset under the extension output directory and checks only lexical containment before reading the file. If a malicious project or build output places a symlink inside that output directory, the route can read the symlink target outside the intended bundle root. The route is also unauthenticated and wildcard-CORS under the extension dev server.

## Location
- `packages/app/src/cli/services/dev/extension/server/middlewares.ts:75-107` — asset path resolution and lexical `relativePath` check.
- `packages/app/src/cli/services/dev/extension/server/middlewares.ts:34-56` — `fileServerMiddleware()` reads the final path with `readFile()`.

## Attacker Control
A malicious project/template can provide or generate a symlink in the extension output tree; a browser/tunnel attacker can request its output-relative name from the unauthenticated dev server.

## Trust Boundary Crossed
Untrusted project filesystem state and browser route parameters cross into local filesystem reads outside the intended extension bundle root.

## Impact
Local file disclosure from the developer machine to any origin that can reach the extension dev server, subject to the attacker being able to place or preserve a symlink in the output directory.

## Evidence
The middleware computes `candidate = resolvePath(joinPath(resolvedOutputDir, filesystemPath))`, rejects only when `relativePath(resolvedOutputDir, candidate)` starts with `..`, then calls `fileServerMiddleware(event, {filePath: candidate})`. No `realpath()` or no-follow check is applied before `readFile()`.

## Reproduction Steps
1. Create or cause the extension output directory to contain `leak.txt -> /path/to/secret`.
2. Start the extension dev server.
3. Request `http://localhost:<port>/extensions/<extensionId>/assets/leak.txt` from any browser origin.
4. The lexical check passes because the symlink path is under the output directory; `readFile()` follows the symlink and returns the target file.
