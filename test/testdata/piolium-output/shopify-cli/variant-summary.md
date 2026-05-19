# Piolium Stage 12 Variant Summary

Variant analysis completed for the surviving P10 findings.

## Inputs and searches

- Surviving findings reviewed: `piolium/findings-draft/p10-001` through `p10-008`.
- Attack pattern registry reviewed and updated: `piolium/attack-pattern-registry.json`.
- Attack-surface reports reviewed: `piolium/attack-surface/knowledge-base-report.md`, `architecture-entrypoints.md`, `manual-attack-surface-inventory.md`, `public-routes-authz-matrix.md`, and `source-sink-flows-all-severities.md`.
- Chamber variant-candidate directories: none present under `piolium/chamber-workspace/*/variant-candidates/`.
- CodeQL/Semgrep/grep artifacts written:
  - `piolium/tmp/p12-semgrep-custom.json`
  - `piolium/tmp/p12-grep-searches.md`
  - `piolium/codeql-queries/variant-p12-structural.ql`
  - `piolium/tmp/p12-structural-codeql.json`
  - `piolium/tmp/p12-entry-sink-excerpts.md`
- `## Phase 8 Addendum` was not present as a literal KB section; Stage 8/manual inventory targets were reviewed instead.

## Confirmed variants

| Draft | Origin pattern | Severity | Summary |
|---|---|---:|---|
| `piolium/findings-draft/p12-001-function-toolchain-download-exec-no-integrity.md` | AP-010-005 | MEDIUM | Function build/run downloads `javy`, `function-runner`, trampoline, and `wasm-opt` artifacts, chmods/caches them, then executes them without independent integrity verification. |
| `piolium/findings-draft/p12-002-mkcert-download-exec-no-integrity.md` | AP-010-005 | MEDIUM | The localhost certificate helper downloads `mkcert` via `downloadGitHubRelease()`, chmods it, and executes it without checksum/signature verification. |
| `piolium/findings-draft/p12-003-extension-generate-liquid-root-file-disclosure.md` | AP-010-008 | MEDIUM | `app generate extension --clone-url` renders attacker-controlled extension templates through `new Liquid()` default roots, allowing CWD file includes. |
| `piolium/findings-draft/p12-004-include-assets-source-containment-file-disclosure.md` | AP-010-003 | MEDIUM | Include-assets config-key and pattern copies trust project-controlled source paths/symlinked trees without canonical containment/no-follow checks, copying outside files into bundles. |

## Rejected / not retained candidates

| Origin finding | Candidate | Decision |
|---|---|---|
| p10-001 tree-kill Windows command injection | Other template-string `execSync` matches (`bin/get-graphql-schemas.js`, Cloudflared macOS `tar`) | Not retained. `bin/get-graphql-schemas.js` interpolates fixed schema repo names, and Cloudflared `tar` injection requires controlling the same local env path that already grants equivalent local control. |
| p10-002 unauthenticated extension dev control plane | GraphiQL wildcard-CORS `/graphiql/status` | Not retained as a P12 draft. It exposes app/store status metadata and token-refresh side effects, but lacks the extension server's control-plane mutation/file-read impact and was already tracked as lower severity in the registry/attack-surface notes. |
| p10-003/p10-004 path containment | `copy-by-pattern.ts` destination `relativePath(outputDir, destPath).startsWith('..')` alone | Not retained by itself. The stronger retained variant is the source-side containment gap in include-assets; the destination check is not independently exploitable in reviewed hardcoded step configs. |
| p10-004 string-prefix path containment | `findNearestTsConfigDir()` prefix check | Not retained. It can misclassify sibling-prefix tsconfig locations, but the observed impact is generated type-file placement in a local project, not Medium-or-higher file disclosure or code execution. |
| p10-006 agentic workflow prompt injection | Other workflows with write tokens or GitHub event data | Not retained. No second AI coding-agent workflow with untrusted issue/PR text and write-capable tools was found. |
| p10-007 GraphiQL script-context XSS | Other `JSON.stringify()` and `<script>` matches | Not retained. Matches were CLI JSON output, first-party static scripts, SSE JSON, or the original GraphiQL template; no second attacker-controlled JSON-in-inline-script sink was confirmed. |
| p10-008 Liquid default root | First-party GraphiQL/dev-console template rendering | Not retained. These callers render first-party template strings/files; attacker input is data, not Liquid source. The retained clone-url extension generator variant has attacker-controlled template source. |

## Registry updates

`piolium/attack-pattern-registry.json` now appends the four P12 drafts to the relevant `confirmed_instances` for AP-010-003, AP-010-005, and AP-010-008.

## Totals

Variants found: 4.
