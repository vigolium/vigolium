---
Phase: 10
Sequence: 4
Slug: app-assets-prefix-path-traversal
Verdict: VALID
Severity-Original: MEDIUM
PoC-Status: executed
Protocol: http
Auth-Required: no
Auth-Roles-Required: anonymous
Pre-FP-Flag: h3-wildcard-decoding-should-be-regression-tested
Debate: piolium/chamber-workspace/c03-ui-extension-dev-server/debate.md
Origin-Drafts: p4-005-app-assets-prefix-path-traversal.md
id: p10
slug: app-assets-prefix-path-traversal
severity: info
---

# App static asset route uses unsafe string-prefix containment

## Summary
The app-level static asset route `/extensions/assets/:assetKey/**` resolves a browser-controlled path against an admin extension `static_root`, then checks containment with `resolvedFilePath.startsWith(resolvedDirectory)`. A sibling directory with the same prefix (for example `public` and `public-secret`) or a symlink under the static root can bypass this string check and be served by the unauthenticated extension dev server.

## Location
- `packages/app/src/cli/services/dev/extension/payload/store.ts:22-29`, `:72-80`, `:273-277` — admin extension `static_root` becomes the `staticRoot` asset directory.
- `packages/app/src/cli/services/dev/extension/server/middlewares.ts:155-170` — unsafe `startsWith` containment check and file read.

## Attacker Control
A browser/tunnel client controls `filePath`; a malicious app project controls the `static_root` layout and can place sibling-prefix directories or symlinks.

## Trust Boundary Crossed
Browser route parameters cross into local file reads intended to be confined to the configured app asset root.

## Impact
Local project or workstation file disclosure from sibling-prefix paths or symlink targets when the extension dev server is running.

## Evidence
The route uses:
```ts
const resolvedDirectory = resolvePath(directory)
const resolvedFilePath = resolvePath(directory, filePath)
if (!resolvedFilePath.startsWith(resolvedDirectory)) { ... }
return fileServerMiddleware(event, {filePath: resolvedFilePath})
```
A path resolving to `/app/public-secret/file` still starts with `/app/public` when the configured root is `/app/public`.

## Reproduction Steps
1. Configure an admin extension with `static_root = "public"`.
2. Place a sensitive file in a sibling such as `public-secret/secret.txt` or a symlink under `public` to an outside target.
3. Request a wildcard asset path that decodes to `../public-secret/secret.txt` under `/extensions/assets/staticRoot/`.
4. The prefix check can pass and the file is served.
