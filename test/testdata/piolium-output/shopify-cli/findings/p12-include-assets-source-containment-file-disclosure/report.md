# [p12] Include-assets source containment bypass copies outside files into deploy bundles

**Vulnerability class:** path traversal / local file disclosure  
**CWE:** CWE-22, CWE-200

## Summary

The `include_assets` build step sanitizes output destinations but not project-controlled source paths. A malicious or compromised extension configuration can set an asset path such as `admin.static_root = "../.env"`; during deploy, Shopify CLI joins that value with the extension directory and copies the resulting outside file into the deploy bundle and generated manifest.

## Details

The admin extension schema accepts `admin.static_root` as an unrestricted string and wires it directly into a deploy-time `include_assets` `configKey` inclusion in [`admin.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/models/extensions/specifications/admin.ts#L8-L59):

```ts
const AdminSchema = zod.object({
  admin: zod
    .object({
      static_root: zod.string().optional(),
      allowed_domains: zod.array(zod.string()).optional(),
    })
    .optional(),
})

// ...
{
  id: 'hosted_app_copy_files',
  name: 'Hosted App Copy Files',
  type: 'include_assets',
  config: {
    generatesAssetsManifest: true,
    inclusions: [
      {
        type: 'configKey',
        key: 'admin.static_root',
      },
    ],
  },
}
```

When the include-assets step processes `configKey` entries, it sanitizes only `entry.destination` before calling `copyConfigKeyEntry`; the source value referenced by `entry.key` is not normalized or checked for containment in [`include-assets-step.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/build/steps/include-assets-step.ts#L139-L153):

```ts
for (const entry of config.inclusions) {
  if (entry.type !== 'configKey') continue
  const warn = (msg: string) => options.stdout.write(msg)
  const rawDest = entry.destination ? sanitizeRelativePath(entry.destination, warn) : undefined
  const sanitizedDest = rawDest === '' ? undefined : rawDest
  const result = await copyConfigKeyEntry({
    key: entry.key,
    baseDir: extension.directory,
    outputDir,
    context,
    destination: sanitizedDest,
    usedBasenames,
    preserveFilePaths: entry.preserveFilePaths,
  })
```

`copyConfigKeyEntry` then reads string values from `context.extension.configuration`, joins each raw value to `baseDir`, and copies the resulting file or directory. There is no `sanitizeRelativePath(sourcePath)`, `realpath()` containment check, rejection of `..`, or no-follow symlink policy before the copy in [`copy-config-key-entry.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/build/steps/include-assets/copy-config-key-entry.ts#L41-L115):

```ts
const value = getNestedValue(context.extension.configuration, key)
let paths: string[]
if (typeof value === 'string') {
  paths = [value]
} else if (Array.isArray(value)) {
  paths = value.filter((item): item is string => typeof item === 'string')
} else {
  paths = []
}

// ...
for (const sourcePath of uniquePaths) {
  const fullPath = joinPath(baseDir, sourcePath)
  const exists = await fileExists(fullPath)
  // ...
  await copyFile(fullPath, destPath)
  stdout.write(`Included '${sourcePath}'\n`)
  pathMap.set(sourcePath, outputRelative)
  filesCopied += 1
}
```

The same source-containment design gap is visible for pattern inclusions: [`copy-by-pattern.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/build/steps/include-assets/copy-by-pattern.ts#L16-L44) validates that the computed destination stays under the output directory, but it does not verify that each glob result's canonical source path stays under the intended source directory.

## Root Cause

The include-assets implementation treats asset source paths from project configuration and glob results as trusted after only destination-side sanitization. It never canonicalizes the selected source path, resolves symlinks, and enforces that the real source remains inside the extension or declared source root before copying it into the deploy output.

## Proof of Concept (PoC)

**PoC-Status:** executed.

The provided PoC at `piolium/findings/p12-include-assets-source-containment-file-disclosure/poc.js` creates an admin extension configuration with `admin.static_root = "../.env"`, places a marker in a `.env` file outside the app/config module directory, and executes the real `hosted_app_copy_files` include-assets deploy step.

From the repository root, run:

```bash
node piolium/findings/p12-include-assets-source-containment-file-disclosure/poc.js
```

The executed evidence confirms that the outside file was copied into the bundle and referenced by the manifest:

```text
Copied outside file into bundle: /var/folders/.../deploy-bundle/.env
Manifest static_root: .env
{"status":"confirmed","evidence":"outside .env marker copied to include-assets deploy bundle and manifest","notes":"impact log: piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/impact.log"}
```

The impact log records the decisive effect:

```text
Attacker-controlled config: admin.static_root = "../.env"
executeStep success: true
filesCopied: 1
CLI include-assets log: Included '../.env'
Copied file contents: LOCAL_SECRET_MARKER=PIOLIUM_INCLUDE_ASSETS_SECRET_1777623929564_80d6eb7d3837
Manifest contents: {
  "static_root": ".env"
}

CONFIRMED: the marker from a file outside the app/config module directory was copied into the deploy bundle and manifest.
```

## Impact

An attacker who can control an app or extension repository, extension TOML, or symlinked asset tree can make a developer or CI deploy build copy files outside the intended extension root into the build output. In deploy flows where generated assets are uploaded, this can disclose local secrets or CI files as extension assets; in local development, the copied file may also be served or exposed from the generated output. The demonstrated behavior is local file disclosure into the bundle and manifest, not arbitrary code execution.

## Remediation

Canonicalize every include-assets source candidate with `realpath()` and require it to remain within the extension directory or explicitly declared source root before copying. Reject absolute paths and `..` traversal in config-derived asset paths, disable or strictly validate symlink following for globbed pattern entries, and add regression tests covering `admin.static_root = "../.env"` and symlink escapes. Destination sanitization should remain in place, but source containment must be enforced before manifest generation or file copy operations.

## Confirmation (V4)
Confirm-Status: blocked
Confirm-Timestamp: 2026-05-01T09:00:36Z
Confirm-Evidence: piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirmed-20260501T090022Z.log
Confirm-Variant-Count: 0
Confirm-FpCheck: not-run
Confirm-Notes: Local-only exploit path is routed to V5 per V4 instructions; no network PoC executed
Confirm-Queued-V5: yes

## Confirmation (V5 generated test)
Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: piolium/findings/p12-include-assets-source-containment-file-disclosure/confirm-test.test.js
Confirm-Test-Output: piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirm-test-output.log; piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirm-test-observation.json; piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirm-test-command.sh
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-01T09:10:04Z
Confirm-Notes: Vitest executed copyConfigKeyEntry with admin.static_root = ../.env; the outside file was copied into the deploy bundle and mapped as .env.
