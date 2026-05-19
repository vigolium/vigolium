# [p10] Extension asset route follows symlinks after lexical containment

**Vulnerability class:** symlink traversal / local file disclosure  
**CWE:** CWE-59 (Improper Link Resolution Before File Access)

## Summary

The extension dev server's `/extensions/:extensionId/assets/**` route validates only the lexical path under an extension output directory before serving the file. A malicious project, template, or build output that places a symlink inside that output directory can cause the unauthenticated asset route to read the symlink target outside the intended bundle root and return local file contents to any origin that can reach the dev server.

## Details

The route is registered directly by `setupHTTPServer` for extension assets at [`packages/app/src/cli/services/dev/extension/server.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/server.ts#L38-L41). The dev server also installs wildcard CORS via [`corsMiddleware`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/server/middlewares.ts#L14-L16), so a browser origin that can reach the server can read successful asset responses.

The vulnerable containment check is in [`getExtensionAssetMiddleware`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/server/middlewares.ts#L95-L106). It resolves the requested name beneath `resolvedOutputDir` and rejects `..` or absolute relative paths, but it never resolves the real filesystem target before passing the path to the file server:

```ts
const resolver = payloadStore.getAssetResolver(extension.devUUID)
const filesystemPath = resolver?.get(assetPath) ?? assetPath

const resolvedOutputDir = resolvePath(resolveOutputDir(extension.outputPath))
const candidate = resolvePath(joinPath(resolvedOutputDir, filesystemPath))
const rel = relativePath(resolvedOutputDir, candidate)

if (rel.startsWith('..') || isAbsolutePath(rel)) {
  return sendError(event, {statusCode: 404, statusMessage: 'Not Found'})
}

return fileServerMiddleware(event, {filePath: candidate})
```

`fileServerMiddleware` then checks and reads the final `filePath` using normal filesystem APIs in [`middlewares.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/server/middlewares.ts#L32-L50). Those APIs follow symlinks, so a path such as `<outputDir>/leak.txt` passes the lexical containment test even when `leak.txt` points to `/path/outside/outputDir/secret`:

```ts
if (!(await fileExists(filePath))) {
  return sendError(event, {statusCode: 404, statusMessage: `Not Found: ${filePath}`})
}

// ...
const fileContent = await readFile(filePath, {})
```

## Root Cause

The implementation treats `resolvePath(joinPath(outputDir, requestedPath))` plus a `relativePath()` prefix check as an access-control boundary. That boundary is only lexical: it proves the symlink pathname is inside the output directory, not that the file ultimately opened by `readFile()` is inside the output directory. There is no `realpath()`-based containment check and no no-follow or `lstat()` rejection for symlinks before the file read.

## Proof of Concept (PoC)

**PoC status:** executed.

The executable PoC is stored at `piolium/findings/p10-extension-asset-symlink-file-read/poc.sh`. It creates a temporary extension output directory, writes a `developer-secret.txt` file outside that output directory, creates `dist/leak.txt` as a symlink to the outside file, starts the real `setupHTTPServer()` extension dev HTTP stack, and fetches:

```bash
cd /Users/bytedance/Desktop/oss-to-run/shopify-cli/piolium/findings/p10-extension-asset-symlink-file-read
./poc.sh
# internally requests: /extensions/poc-extension/assets/leak.txt
```

The captured evidence in `evidence/result.json` confirms the real server returned the outside-file marker through the asset endpoint and exposed it with wildcard CORS:

```json
{"status":"confirmed","evidence":"HTTP asset response contained outside-file marker via output-dir symlink","notes":"url=http://localhost:57801/extensions/poc-extension/assets/leak.txt; cors=*; marker=PIOLIUM_SYMLINK_LEAK_52065_1777622956824; symlink=/var/folders/2k/z4j3lfxj5fv7r20hswc8sj8r0000gn/T/shopify-cli-symlink-poc-MsVlBF/malicious-extension/dist/leak.txt; target=/var/folders/2k/z4j3lfxj5fv7r20hswc8sj8r0000gn/T/shopify-cli-symlink-poc-MsVlBF/developer-secret.txt"}
```

## Impact

An attacker who can influence a Shopify extension project or its build output can plant or preserve a symlink in the extension output tree. When the developer runs the extension dev server, any browser origin or network peer that can reach the server can request the symlink name and receive the target file's contents, limited to files readable by the CLI process. This is most relevant for malicious templates, compromised project dependencies/build steps, or shared/tunneled dev-server workflows; it does not require Shopify authentication once the dev server is running.

## Remediation

Resolve and validate the real filesystem path before serving assets. For example, compute `realpath()` for both the output root and the candidate path, ensure the candidate realpath remains inside the output root, and reject broken links or symlinks that escape. Alternatively, use `lstat()`/no-follow open semantics to reject symlinks for this route entirely. Consider removing the direct `assetPath` fallback or serving only resolver-allowlisted build artifacts, and keep CORS/network exposure as narrow as practical for a local dev server.

## Confirmation (V4)
Confirm-Status: confirmed-live
Confirm-Timestamp: 2026-05-01T09:00:22Z
Confirm-Evidence: piolium/findings/p10-extension-asset-symlink-file-read/evidence/confirmed-20260501T090022Z.log
Confirm-Variant-Count: 1
Confirm-FpCheck: not-run
Confirm-Notes: live target asset response contained outside-file marker via output-dir symlink; url=http://localhost:3469/extensions/poc-extension/assets/piolium-live-leak-20260501T090022Z.txt; marker=PIOLIUM_LIVE_SYMLINK_LEAK_20260501T090022Z_70709; symlink=/var/folders/2k/z4j3lfxj5fv7r20hswc8sj8r0000gn/T/piolium-extension-dev-68340/dist/piolium-live-leak-20260501T090022Z.txt; target=/var/folders/2k/z4j3lfxj5fv7r20hswc8sj8r0000gn/T/piolium-live-leak-20260501T090022Z.txt.secret
Confirm-Queued-V5: no
