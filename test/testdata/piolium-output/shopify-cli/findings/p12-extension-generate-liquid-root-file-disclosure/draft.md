---
id: p12
slug: extension-generate-liquid-root-file-disclosure
severity: info
---

Phase: 12
Sequence: 003
Slug: extension-generate-liquid-root-file-disclosure
Verdict: VALID
Rationale: `app generate extension --clone-url` can render attacker-controlled extension templates through the same default-root Liquid helper used by the original app-init finding.
Severity-Original: MEDIUM
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
Origin-Finding: piolium/findings-draft/p10-008-liquid-template-root-file-disclosure.md
Origin-Pattern: AP-010-008

## Summary
The extension generator accepts a custom template clone URL and renders downloaded `.liquid` files with `recursiveLiquidTemplateCopy()`. That helper uses `new Liquid()` with default filesystem roots, so a malicious extension template can include files from the developer's current working directory into the generated extension scaffold.

## Location
- `packages/app/src/cli/commands/app/generate/extension.ts:42-47` — hidden `--clone-url` / `SHOPIFY_FLAG_CLONE_URL` accepts a custom template repository URL.
- `packages/app/src/cli/commands/app/generate/extension.ts:89-93` — passes the clone URL into the generation service.
- `packages/app/src/cli/services/generate/extension.ts:93-105` — uses the custom URL for `downloadGitRepository()`.
- `packages/app/src/cli/services/generate/extension.ts:142-148`, `:168-175`, and `:238-244` — renders theme/function/UI extension templates with `recursiveLiquidTemplateCopy()`.
- `packages/cli-kit/src/public/node/liquid.ts:24-26` and `:65-72` — renders `.liquid` content through default `new Liquid()`.

## Attacker Control
An attacker who convinces a developer to generate an extension from a malicious clone URL controls the `.liquid` template contents, including Liquid include/render/layout tags.

## Trust Boundary Crossed
Downloaded template text crosses into local filesystem reads outside the downloaded template directory because Liquid roots are not pinned to the template directory.

## Impact
Local file disclosure from the developer's current working directory into generated extension files, with possible follow-on exfiltration through dependency installation, build steps, commits, or later sharing of the generated extension.

## Evidence
`generateExtensionTemplate()` chooses `const url = options.cloneUrl ?? options.extensionTemplate.url` and `downloadOrFindTemplateDirectory()` clones it. Each extension initialization path calls `recursiveLiquidTemplateCopy(templateDirectory, directory, ...)`. The shared helper reads attacker-controlled `.liquid` files and calls `renderLiquidTemplate(content, data)`, whose implementation is `const engine = new Liquid()` without `root`, `partials`, or `layouts` options.

## Reproduction Steps
1. Publish an extension template repository containing `leak.txt.liquid` with `{% include ".env" %}`.
2. From a directory containing `.env`, run `shopify app generate extension --template <valid-type> --clone-url <attacker-repo-url>`.
3. Observe the generated extension contain the included local `.env` contents because Liquid looked up the include relative to the process working directory/default root.
