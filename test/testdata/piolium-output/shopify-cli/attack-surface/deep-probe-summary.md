# Deep Probe Summary: Manual Attack Surface Probe

Status: complete  
Stage: P8 `/piolium-deep` single-team MVP  
Generated: 2026-05-01T07:26:59Z  
Loops: 1  
Inventory: `piolium/attack-surface/manual-attack-surface-inventory.md`  
Hypotheses notes: `piolium/attack-surface/manual-probe-hypotheses.md`

## Counts

| Metric | Count |
|---|---:|
| New hypotheses considered | 7 |
| New P8 drafts written | 2 |
| Validated new P8 findings | 2 |
| Needs-deeper items | 1 |
| Invalidated/no-new-draft items | 1 |
| Existing P4/P5 findings corroborated/de-duped | 4 |

Stop reason: highest-impact P7-deferred gaps and top local-dev attack surfaces were covered; remaining high-impact issues are already represented by P4/P5/P6 drafts or require runtime built-package/tunnel testing.

## Validated P8 Findings

### P8-001: Extension dev WebSocket accepts cross-site unauthenticated control connections

- Reasoning model: Backward + contradiction.
- Target: `packages/app/src/cli/services/dev/extension/websocket/handlers.ts:19-24` — `websocketUpgradeHandler()`.
- Attack input: Malicious webpage or tunnel visitor opens `ws://localhost:<port>/extensions` and sends JSON `update`/`dispatch`/`log` messages.
- Code path: `websocket.ts:8-13` → `handlers.ts:19-24` → connected payload at `handlers.ts:31-38` → message handling at `handlers.ts:99-134` → broadcast at `handlers.ts:169-170` or terminal output at `handlers.ts:93-95`.
- Sanitizers on path: URL equality only; no Origin/key/session check. App API key check is bypassable because payloads disclose the key and extension-only updates do not require `eventData.app`.
- Security consequence: App/store/extension dev metadata disclosure, unauthorized dev payload mutation/broadcast, attacker-controlled terminal output.
- Severity estimate: MEDIUM.
- Evidence file: `piolium/findings-draft/p8-001-extension-dev-websocket-cross-site-hijack.md`.

### P8-002: Custom app templates render Liquid includes against the process CWD

- Reasoning model: Backward + contradiction.
- Target: `packages/cli-kit/src/public/node/liquid.ts:24-26` — `renderLiquidTemplate()`.
- Attack input: Malicious GitHub template containing a `.liquid` file with `{% include ".env" %}` or similar include/render/layout tags.
- Code path: template flag `packages/app/src/cli/commands/app/init.ts:41-45` → GitHub-origin-only validation `services/init/validate.ts:11-16` → download/render `services/init/init.ts:72-101` → `new Liquid()` default root `liquid.ts:24-26` → rendered file write `liquid.ts:65-72` → dependency install `init.ts:174-179`.
- Sanitizers on path: GitHub origin check only; no Liquid root/partials/layouts confinement to downloaded template directory.
- Security consequence: Local file disclosure from the CLI invocation CWD into generated project files, with possible exfiltration during install or later commit/share.
- Severity estimate: MEDIUM.
- Evidence file: `piolium/findings-draft/p8-002-liquid-template-root-file-disclosure.md`.

## Existing Findings Corroborated / De-duplicated

| Existing draft | Surface | P8 note |
|---|---|---|
| `p4-002-graphiql-status-wildcard-cors-info-leak.md` / `p5-002-graphiql-status-missing-key-gate.md` | `GET /graphiql/status` | Confirmed wildcard CORS at `server.ts:128-137` and no key check before status response at `server.ts:161-170`. |
| `p4-003-graphiql-api-version-path-injection.md` | `POST /graphiql/graphql.json` | Confirmed `adminUrl(storeFqdn, query.api_version as string)` at `server.ts:244` after only key check. |
| `p4-009-graphiql-script-context-xss.md` | `GET /graphiql` | Confirmed query/variables are rendered into script context at `templates/graphiql.tsx:254-259`. |
| `p5-001-ui-extension-dev-server-missing-auth.md` | `/extensions*` HTTP/WS | P8-001 is the spec-focused WebSocket subcase; HTTP routes remain covered by P5. |

## Needs-Deeper

### ND-01: Dev-console static asset route may allow traversal in built packages

- Target: `packages/app/src/cli/services/dev/extension/server/middlewares.ts:135-152` — `devConsoleAssetsMiddleware()` joins `assetPath` from route params to the generated dev-console asset root without a containment check.
- Why unresolved: The source checkout does not include generated `assets/dev-console/...`; exploitability depends on packaged assets and H3/runtime path normalization for encoded `..` segments.
- Suggested follow-up: Build or install the package, start the extension dev server, and request `/extensions/dev-console/assets/%2e%2e/...` variants. If file reads escape the bundle root, draft a local file disclosure finding.

## Coverage Summary

| Entry point / slice | Backward reasoning | Contradiction reasoning | Outcome |
|---|:-:|:-:|---|
| `WS /extensions` | BW-01 | CR-01, CR-02 | VALIDATED → `p8-001` |
| `GET /extensions*` HTTP payload/assets | BW-01 support | CR-02 support | De-duped to existing `p5-001`; supports `p8-001` |
| Custom `shopify app init --template https://github.com/...` | BW-02 | CR-03 | VALIDATED → `p8-002` |
| `GET /graphiql/status` | Covered from inventory | Covered from patch-bypass contradiction | Existing `p4-002`/`p5-002` |
| `POST /graphiql/graphql.json` | Covered from inventory | Existing API-version contradiction | Existing `p4-003` |
| `GET /graphiql` script context | Covered from inventory | Existing script-context contradiction | Existing `p4-009` |
| Theme dev CORS/proxy/SSE | Reviewed | CR-04 | No new P8 draft; CORS/host mitigations present |
| Store auth callback | Reviewed | State-bypass contradiction | No new P8 draft; store/state checks present |
| Dev-console static assets | BW-03 | — | NEEDS-DEEPER runtime check |

## Verification method

Used `read`, `grep`, and `bash`/`nl -ba` evidence extraction against source and P3-P7 artifacts. No live localhost/tunnel dynamic testing was performed in this P8 pass.
