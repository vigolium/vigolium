---
id: p12
slug: include-assets-source-containment-file-disclosure
severity: info
---

Phase: 12
Sequence: 004
Slug: include-assets-source-containment-file-disclosure
Verdict: VALID
Rationale: Deploy-time include-assets steps copy project-controlled source paths without canonical containment/no-follow checks, allowing traversal or symlinked source trees to place outside files into extension bundles.
Severity-Original: MEDIUM
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
Origin-Finding: piolium/findings-draft/p10-003-extension-asset-symlink-file-read.md
Origin-Pattern: AP-010-003

## Summary
The include-assets build step sanitizes destinations but not source paths. Config-key inclusions read path strings from extension configuration, join them to the extension directory, and copy them into the output bundle; pattern inclusions glob source trees without disabling symlink following or checking realpaths. A malicious project can therefore copy files outside the intended extension root into the deploy bundle/manifest.

## Location
- `packages/app/src/cli/services/build/steps/include-assets-step.ts:138-151` — only `entry.destination` is sanitized before config-key copying.
- `packages/app/src/cli/services/build/steps/include-assets/copy-config-key-entry.ts:43-64` — attacker-controlled config values become `sourcePath` entries.
- `packages/app/src/cli/services/build/steps/include-assets/copy-config-key-entry.ts:61-112` — `joinPath(baseDir, sourcePath)` is copied with no source containment or realpath check.
- `packages/app/src/cli/services/build/steps/include-assets/copy-by-pattern.ts:16-18` and `:33-44` — globbed source files are copied after only destination-relative checks.
- `packages/app/src/cli/models/extensions/specifications/ui_extension.ts:99-123` and `packages/app/src/cli/models/extensions/specifications/admin.ts:45-59` — deploy steps copy project-configured asset paths such as `extension_points[].tools`, `extension_points[].assets`, `extension_points[].instructions`, `extension_points[].intents[].schema`, and `admin.static_root`.

## Attacker Control
A malicious app/extension repository controls extension TOML fields used by config-key inclusions and can also place symlinks under pattern-included source directories.

## Trust Boundary Crossed
Project-controlled path strings and symlinked filesystem state cross into local file reads/copies outside the extension directory and then into generated deploy bundles.

## Impact
Local file disclosure into the extension deploy bundle and generated assets manifest. Depending on the extension type and deploy flow, outside files can be uploaded as app extension assets or later served by the local extension dev server from the build output.

## Evidence
`copyConfigKeyEntry()` collects string values from `context.extension.configuration`, computes `const fullPath = joinPath(baseDir, sourcePath)`, and then either `copyDirectoryContents(fullPath, destDir)` or `copyFile(fullPath, destPath)`. There is no `sanitizeRelativePath(sourcePath)`, `realpath()` containment check against `baseDir`, or no-follow policy. `copyByPattern()` similarly trusts `glob(..., {cwd: sourceDir, absolute: true})` results and checks only `relativePath(outputDir, destPath).startsWith('..')` before copying.

## Reproduction Steps
1. Create a malicious UI extension configuration whose copied config-key path points outside the extension, for example a `tools`/`assets`/`instructions` path such as `../../.env`, or place a symlinked directory under a pattern-included assets directory.
2. Run `shopify app deploy` or the extension build path that executes include-assets deploy steps.
3. Observe the outside file copied into the extension output directory and referenced in the generated bundle/manifest without canonical containment validation.
