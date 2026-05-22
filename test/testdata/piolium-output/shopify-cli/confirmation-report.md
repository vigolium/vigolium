# Confirmation Report

| Field | Value |
|-------|-------|
| Audit ID | 2026-05-01T05:32:59.050Z |
| Repository | shopify/cli |
| Confirmed at | 2026-05-01T09:16:47Z |
| Environment | test-server (http://localhost:3469) |
| Original audit mode | deep |

## Summary

| Status | Count | Findings |
|--------|-------|----------|
| confirmed-live | 4 | P10-002, P10-003, P10-004, P10-007 |
| confirmed-test | 8 | P10-001, P10-005, P10-006, P10-008, P12-001, P12-002, P12-003, P12-004 |
| confirmed-fp | 0 | — |
| analytical-only | 0 | — |
| unconfirmed | 0 | — |
| inconclusive | 0 | — |
| blocked | 0 | — |
| no-poc | 0 | — |
| error | 0 | — |

**Confirmation rate**: 12/12 (100%) findings confirmed — `confirmed-fp` and `analytical-only` are excluded from the denominator.

## One-line Finding Inventory

| Finding | Status | Evidence pointer | Reproduction command summary |
|---------|--------|------------------|------------------------------|
| P10-001 `p10-tree-kill-windows-command-injection` | confirmed-test | `piolium/findings/p10-tree-kill-windows-command-injection/confirm-test.test.js`; `piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirm-test-command.sh`; `piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirm-test-output.log`; `piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirm-test-observation.json` | `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/cli-kit/vite.config.ts piolium/findings/p10-tree-kill-windows-command-injection/confirm-test.test.js --testTimeout=60000 --reporter=verbose 2>&1 \| tee piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirm-test-output.log` |
| P10-002 `p10-extension-dev-server-unauthenticated-control-plane` | confirmed-live | `piolium/findings/p10-extension-dev-server-unauthenticated-control-plane/evidence/confirmed-20260501T090022Z.log` | `BASE_URL=http://localhost:3469 ORIGIN=https://attacker.example python3 piolium/findings/p10-extension-dev-server-unauthenticated-control-plane/confirm-evidence/poc-adapted.py` |
| P10-003 `p10-extension-asset-symlink-file-read` | confirmed-live | `piolium/findings/p10-extension-asset-symlink-file-read/evidence/confirmed-20260501T090022Z.log` | `BASE_URL=http://localhost:3469 PROCESS_PID=68340 bash piolium/findings/p10-extension-asset-symlink-file-read/evidence/live-target-symlink-poc-20260501T090022Z.sh` |
| P10-004 `p10-app-assets-prefix-path-traversal` | confirmed-live | `piolium/findings/p10-app-assets-prefix-path-traversal/evidence/confirmed-20260501T090022Z.log` | `BASE_URL=http://localhost:3469 bash piolium/findings/p10-app-assets-prefix-path-traversal/poc.sh` |
| P10-005 `p10-cloudflared-download-exec-no-integrity` | confirmed-test | `piolium/findings/p10-cloudflared-download-exec-no-integrity/confirm-test.test.js`; `piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirm-test-command.sh`; `piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirm-test-output.log`; `piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirm-test-observation.json` | `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/plugin-cloudflare/vite.config.ts piolium/findings/p10-cloudflared-download-exec-no-integrity/confirm-test.test.js --testTimeout=60000 --reporter=verbose 2>&1 \| tee piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirm-test-output.log` |
| P10-006 `p10-agentic-gardener-issue-prompt-injection` | confirmed-test | `piolium/findings/p10-agentic-gardener-issue-prompt-injection/confirm-test.test.js`; `piolium/findings/p10-agentic-gardener-issue-prompt-injection/evidence/confirm-test-command.sh`; `piolium/findings/p10-agentic-gardener-issue-prompt-injection/evidence/confirm-test-output.log`; `piolium/findings/p10-agentic-gardener-issue-prompt-injection/evidence/confirm-test-observation.json`; `piolium/findings/p10-agentic-gardener-issue-prompt-injection/evidence/confirm-test-injected-issue-body.md` | `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/cli-kit/vite.config.ts piolium/findings/p10-agentic-gardener-issue-prompt-injection/confirm-test.test.js --testTimeout=60000 --reporter=verbose 2>&1 \| tee piolium/findings/p10-agentic-gardener-issue-prompt-injection/evidence/confirm-test-output.log` |
| P10-007 `p10-graphiql-script-context-xss` | confirmed-live | `piolium/findings/p10-graphiql-script-context-xss/evidence/confirmed-20260501T090022Z.log` | `BASE_URL=http://localhost:3469 node piolium/findings/p10-graphiql-script-context-xss/poc.js` |
| P10-008 `p10-liquid-template-root-file-disclosure` | confirmed-test | `piolium/findings/p10-liquid-template-root-file-disclosure/confirm-test.test.js`; `piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirm-test-command.sh`; `piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirm-test-output.log`; `piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirm-test-observation.json` | `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/cli-kit/vite.config.ts piolium/findings/p10-liquid-template-root-file-disclosure/confirm-test.test.js --testTimeout=60000 --reporter=verbose --pool=forks 2>&1 \| tee piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirm-test-output.log` |
| P12-001 `p12-function-toolchain-download-exec-no-integrity` | confirmed-test | `piolium/findings/p12-function-toolchain-download-exec-no-integrity/confirm-test.test.js`; `piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirm-test-command.sh`; `piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirm-test-output.log`; `piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirm-test-observation.json` | `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/app/vite.config.ts piolium/findings/p12-function-toolchain-download-exec-no-integrity/confirm-test.test.js --testTimeout=60000 --reporter=verbose 2>&1 \| tee piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirm-test-output.log` |
| P12-002 `p12-mkcert-download-exec-no-integrity` | confirmed-test | `piolium/findings/p12-mkcert-download-exec-no-integrity/confirm-test.test.js`; `piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirm-test-command.sh`; `piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirm-test-output.log`; `piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirm-test-observation.json` | `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/app/vite.config.ts piolium/findings/p12-mkcert-download-exec-no-integrity/confirm-test.test.js --testTimeout=60000 --reporter=verbose 2>&1 \| tee piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirm-test-output.log` |
| P12-003 `p12-extension-generate-liquid-root-file-disclosure` | confirmed-test | `piolium/findings/p12-extension-generate-liquid-root-file-disclosure/confirm-test.test.js`; `piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirm-test-command.sh`; `piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirm-test-output.log`; `piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirm-test-observation.json` | `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/cli-kit/vite.config.ts piolium/findings/p12-extension-generate-liquid-root-file-disclosure/confirm-test.test.js --testTimeout=60000 --reporter=verbose --pool=forks 2>&1 \| tee piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirm-test-output.log` |
| P12-004 `p12-include-assets-source-containment-file-disclosure` | confirmed-test | `piolium/findings/p12-include-assets-source-containment-file-disclosure/confirm-test.test.js`; `piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirm-test-command.sh`; `piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirm-test-output.log`; `piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirm-test-observation.json` | `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/app/vite.config.ts piolium/findings/p12-include-assets-source-containment-file-disclosure/confirm-test.test.js --testTimeout=60000 --reporter=verbose 2>&1 \| tee piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirm-test-output.log` |

## Breakdown by Exploitability Class

| Class | Total | confirmed-live | confirmed-test | unconfirmed | blocked | analytical-only |
|-------|-------|----------------|----------------|-------------|---------|-----------------|
| network-exploitable | 5 | 4 | 1 | 0 | 0 | — |
| local-exploitable | 7 | — | 7 | 0 | 0 | — |
| non-exploitable | 0 | — | — | — | — | 0 |

## Confirmed Findings (Live)

### P10-002 — UI extension dev server exposes an unauthenticated control plane [MEDIUM]

- **Vulnerability**: network-exploitable — Missing authentication / unauthenticated local dev control plane
- **Method**: PoC executed against `http://localhost:3469` via `test-server`
- **Evidence**: `piolium/findings/p10-extension-dev-server-unauthenticated-control-plane/evidence/confirmed-20260501T090022Z.log`
- **Execution time**: 0.074s
- **Observation**: CORS-readable payload and unauthenticated websocket state mutation; store=piolium-dev-store.myshopify.com; marker=piolium-poc-411abf83
- **Reproduce**: `BASE_URL=http://localhost:3469 ORIGIN=https://attacker.example python3 piolium/findings/p10-extension-dev-server-unauthenticated-control-plane/confirm-evidence/poc-adapted.py`

---

### P10-003 — Extension asset route follows symlinks after lexical containment [MEDIUM]

- **Vulnerability**: network-exploitable — Symlink traversal / local file disclosure (CWE-59)
- **Method**: PoC executed against `http://localhost:3469` via `test-server`
- **Evidence**: `piolium/findings/p10-extension-asset-symlink-file-read/evidence/confirmed-20260501T090022Z.log`
- **Execution time**: 0.214s
- **Observation**: live target asset response contained outside-file marker via output-dir symlink; url=http://localhost:3469/extensions/poc-extension/assets/piolium-live-leak-20260501T090022Z.txt; marker=PIOLIUM_LIVE_SYMLINK_LEAK_20260501T090022Z_70709; symlink=/var/folders/2k/z4j3lfxj5fv7r20hswc8sj8r0000gn/T/piolium-extension-dev-68340/dist/piolium-live-leak-20260501T090022Z.txt; target=/var/folders/2k/z4j3lfxj5fv7r20hswc8sj8r0000gn/T/piolium-live-leak-20260501T090022Z.txt.secret
- **Reproduce**: `BASE_URL=http://localhost:3469 PROCESS_PID=68340 bash piolium/findings/p10-extension-asset-symlink-file-read/evidence/live-target-symlink-poc-20260501T090022Z.sh`

---

### P10-004 — App static asset route uses unsafe prefix containment [MEDIUM]

- **Vulnerability**: network-exploitable — Path traversal / local file disclosure (CWE-22/CWE-200)
- **Method**: PoC executed against `http://localhost:3469` via `test-server`
- **Evidence**: `piolium/findings/p10-app-assets-prefix-path-traversal/evidence/confirmed-20260501T090022Z.log`
- **Execution time**: 6.226s
- **Observation**: sibling public-secret/secret.txt contents in HTTP body; variant1 live mock route probe recorded; variant2 started real setupHTTPServer app-assets route with vulnerable staticRoot; Encoded backslashes become route filePath "..\public-secret\secret.txt"; pathe resolvePath normalizes them before the unsafe startsWith check.
- **Reproduce**: `BASE_URL=http://localhost:3469 bash piolium/findings/p10-app-assets-prefix-path-traversal/poc.sh`

---

### P10-007 — GraphiQL inline script context XSS via query parameters [MEDIUM]

- **Vulnerability**: network-exploitable — Cross-site scripting in inline script context (CWE-79)
- **Method**: PoC executed against `http://localhost:3469` via `test-server`
- **Evidence**: `piolium/findings/p10-graphiql-script-context-xss/evidence/confirmed-20260501T090022Z.log`
- **Execution time**: 7.573s
- **Observation**: standalone <script id='poc-xss'> emitted in GraphiQL HTML; variant1 live mock route probe recorded; variant2 started real GraphiQL server and rendered exploitable HTML; The injected script includes a same-origin /graphiql/graphql.json POST using the valid GraphiQL key.
- **Reproduce**: `BASE_URL=http://localhost:3469 node piolium/findings/p10-graphiql-script-context-xss/poc.js`

---

## Confirmed Findings (Test)

### P10-001 — Windows `treeKill` string PID command injection [MEDIUM]

- **Vulnerability**: local-exploitable — OS command injection (CWE-78)
- **Method**: Generated `vitest` reproducer test
- **Test file**: `piolium/findings/p10-tree-kill-windows-command-injection/confirm-test.test.js`
- **Test output**: `piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p10-tree-kill-windows-command-injection/confirm-test.test.js`; `piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirm-test-command.sh`; `piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirm-test-output.log`; `piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirm-test-observation.json`
- **Observation**: Mocked Win32 branch observed attacker PID metacharacters verbatim in child_process.exec taskkill command.
- **Reproduce**: `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/cli-kit/vite.config.ts piolium/findings/p10-tree-kill-windows-command-injection/confirm-test.test.js --testTimeout=60000 --reporter=verbose 2>&1 \| tee piolium/findings/p10-tree-kill-windows-command-injection/evidence/confirm-test-output.log`

---

### P10-005 — Cloudflared installer executes downloaded release artifacts without integrity verification [MEDIUM]

- **Vulnerability**: local-exploitable — Download of Code Without Integrity Check (CWE-494)
- **Method**: Generated `vitest` reproducer test
- **Test file**: `piolium/findings/p10-cloudflared-download-exec-no-integrity/confirm-test.test.js`
- **Test output**: `piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p10-cloudflared-download-exec-no-integrity/confirm-test.test.js`; `piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirm-test-command.sh`; `piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirm-test-output.log`; `piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirm-test-observation.json`
- **Observation**: Mocked release fetch installed a shell payload as cloudflared, chmodded it executable, and executed it with tunnel arguments.
- **Reproduce**: `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/plugin-cloudflare/vite.config.ts piolium/findings/p10-cloudflared-download-exec-no-integrity/confirm-test.test.js --testTimeout=60000 --reporter=verbose 2>&1 \| tee piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence/confirm-test-output.log`

---

### P10-006 — Gardener issue prompt injection into write-capable Claude workflow [MEDIUM]

- **Vulnerability**: network-exploitable — Agentic prompt injection / confused deputy
- **Method**: Generated `vitest` reproducer test
- **Test file**: `piolium/findings/p10-agentic-gardener-issue-prompt-injection/confirm-test.test.js`
- **Test output**: `piolium/findings/p10-agentic-gardener-issue-prompt-injection/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p10-agentic-gardener-issue-prompt-injection/confirm-test.test.js`; `piolium/findings/p10-agentic-gardener-issue-prompt-injection/evidence/confirm-test-command.sh`; `piolium/findings/p10-agentic-gardener-issue-prompt-injection/evidence/confirm-test-output.log`; `piolium/findings/p10-agentic-gardener-issue-prompt-injection/evidence/confirm-test-observation.json`; `piolium/findings/p10-agentic-gardener-issue-prompt-injection/evidence/confirm-test-injected-issue-body.md`
- **Observation**: Workflow reproducer confirmed a labeled issue URL reaches Claude while contents/PR write permissions and write-capable tools are enabled; hosted Claude action was not executed.
- **Reproduce**: `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/cli-kit/vite.config.ts piolium/findings/p10-agentic-gardener-issue-prompt-injection/confirm-test.test.js --testTimeout=60000 --reporter=verbose 2>&1 \| tee piolium/findings/p10-agentic-gardener-issue-prompt-injection/evidence/confirm-test-output.log`

---

### P10-008 — Custom app templates can include files from the developer's working directory [MEDIUM]

- **Vulnerability**: local-exploitable — Liquid template unrestricted include / local file disclosure
- **Method**: Generated `vitest` reproducer test
- **Test file**: `piolium/findings/p10-liquid-template-root-file-disclosure/confirm-test.test.js`
- **Test output**: `piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p10-liquid-template-root-file-disclosure/confirm-test.test.js`; `piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirm-test-command.sh`; `piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirm-test-output.log`; `piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirm-test-observation.json`
- **Observation**: recursiveLiquidTemplateCopy rendered an attacker .liquid include from a victim CWD and wrote the victim .env marker into the scaffold.
- **Reproduce**: `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/cli-kit/vite.config.ts piolium/findings/p10-liquid-template-root-file-disclosure/confirm-test.test.js --testTimeout=60000 --reporter=verbose --pool=forks 2>&1 \| tee piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirm-test-output.log`

---

### P12-001 — Function toolchain downloads are executed without integrity verification [MEDIUM]

- **Vulnerability**: local-exploitable — Download of Code Without Integrity Check (CWE-494)
- **Method**: Generated `vitest` reproducer test
- **Test file**: `piolium/findings/p12-function-toolchain-download-exec-no-integrity/confirm-test.test.js`
- **Test output**: `piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p12-function-toolchain-download-exec-no-integrity/confirm-test.test.js`; `piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirm-test-command.sh`; `piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirm-test-output.log`; `piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirm-test-observation.json`
- **Observation**: downloadBinary accepted a gzipped function-runner payload, chmodded it, and the CLI exec wrapper ran it with -f function.wasm.
- **Reproduce**: `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/app/vite.config.ts piolium/findings/p12-function-toolchain-download-exec-no-integrity/confirm-test.test.js --testTimeout=60000 --reporter=verbose 2>&1 \| tee piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence/confirm-test-output.log`

---

### P12-002 — mkcert release download is executed without integrity verification [MEDIUM]

- **Vulnerability**: local-exploitable — Download of Code Without Integrity Check (CWE-494)
- **Method**: Generated `vitest` reproducer test
- **Test file**: `piolium/findings/p12-mkcert-download-exec-no-integrity/confirm-test.test.js`
- **Test output**: `piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p12-mkcert-download-exec-no-integrity/confirm-test.test.js`; `piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirm-test-command.sh`; `piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirm-test-output.log`; `piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirm-test-observation.json`
- **Observation**: generateCertificate downloaded a mocked mkcert release payload to .shopify/mkcert, chmodded it executable, and ran it to create cert/key files.
- **Reproduce**: `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/app/vite.config.ts piolium/findings/p12-mkcert-download-exec-no-integrity/confirm-test.test.js --testTimeout=60000 --reporter=verbose 2>&1 \| tee piolium/findings/p12-mkcert-download-exec-no-integrity/evidence/confirm-test-output.log`

---

### P12-003 — Extension template Liquid include can disclose local root files [MEDIUM]

- **Vulnerability**: local-exploitable — Liquid template unrestricted include / local file disclosure
- **Method**: Generated `vitest` reproducer test
- **Test file**: `piolium/findings/p12-extension-generate-liquid-root-file-disclosure/confirm-test.test.js`
- **Test output**: `piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p12-extension-generate-liquid-root-file-disclosure/confirm-test.test.js`; `piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirm-test-command.sh`; `piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirm-test-output.log`; `piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirm-test-observation.json`
- **Observation**: Shared Liquid template copy used by extension generation rendered {% include ".env" %} from a victim app CWD into a generated extension file.
- **Reproduce**: `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/cli-kit/vite.config.ts piolium/findings/p12-extension-generate-liquid-root-file-disclosure/confirm-test.test.js --testTimeout=60000 --reporter=verbose --pool=forks 2>&1 \| tee piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirm-test-output.log`

---

### P12-004 — Include-assets source containment bypass copies outside files into deploy bundles [MEDIUM]

- **Vulnerability**: local-exploitable — Path traversal / local file disclosure (CWE-22/CWE-200)
- **Method**: Generated `vitest` reproducer test
- **Test file**: `piolium/findings/p12-include-assets-source-containment-file-disclosure/confirm-test.test.js`
- **Test output**: `piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p12-include-assets-source-containment-file-disclosure/confirm-test.test.js`; `piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirm-test-command.sh`; `piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirm-test-output.log`; `piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirm-test-observation.json`
- **Observation**: copyConfigKeyEntry with admin.static_root=../.env copied the outside file into the output bundle and pathMap as .env.
- **Reproduce**: `cd /Users/j3ssie/Desktop/oss-to-run/shopify-cli timeout 90 pnpm vitest run --config packages/app/vite.config.ts piolium/findings/p12-include-assets-source-containment-file-disclosure/confirm-test.test.js --testTimeout=60000 --reporter=verbose 2>&1 \| tee piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence/confirm-test-output.log`

---

## Analytical-only Findings

None.

## Unconfirmed / Inconclusive Findings

None. V4 inconclusive/blocked attempts were either confirmed by V5 generated tests or never applied to the final deduplicated status.

## Blocked Findings

None as final status. Eight V4 local-only findings were initially `blocked` from live network execution and then confirmed by V5 generated tests.

## Other Non-confirmed Categories

- **no-poc**: 0.
- **error**: 0.

## False-positive Findings

**False-positive count (`confirmed-fp`)**: 0.

No `FP-*` finding directories were present. `piolium/confirm-workspace/false-positive-renames.json` records an empty `renames` array, so no findings were drained from severity counts as false positives in V5.

## Environment Details

- **Session UUID**: `613a6a3b-ccce-475e-b192-09025e326d01`
- **Provisioning method**: `test-server`
- **Target URL / base_url**: `http://localhost:3469`
- **Actual port** (after fallback): `3469` (fallback used: `False`)
- **Startup/build duration**: approximately `34s` across successful setup attempts (`pnpm nx build cli`, Vite dev console, mock extension dev server).
- **Healthcheck**: `/extensions` result=`True`; V4 reachability `curl -sf -o /dev/null --max-time 5 http://localhost:3469` exit `0`.
- **Containers/processes**: no containers. Processes were extension dev server PID `68340` and Vite dev console PID `67178`; cleanup result `success`.
- **Setup log**: `piolium/confirm-workspace/setup.log`
- **Healthcheck-failure log**: not present; healthcheck passed.
- **Cleanup command**: `bash piolium/confirm-workspace/cleanup.sh + env-connection process tree cleanup`
- **Cleanup result**: `success` at `2026-05-01T09:14:42Z`; ports 3469/5173 listeners after cleanup: `{'3469': [], '5173': []}`; log `piolium/confirm-workspace/cleanup.log`. Live reproduction commands require re-provisioning the test server because cleanup stopped the target.

### Environment setup notes

- Repository identified as a Node.js/TypeScript pnpm/Nx monorepo for the Shopify CLI; the primary runtime is an oclif CLI, not a root daemon.
- `pnpm nx build cli` succeeded, and the CLI version command succeeded during provisioning.
- Full `shopify app dev` and `shopify theme dev` strategies were skipped because they require real Shopify app/theme projects, authenticated accounts/tokens, and stores.
- V3 therefore used a `test-server` strategy: real built extension HTTP/WebSocket server modules with a local mock payload store on `http://localhost:3469`, plus a Vite dev-console process on port 5173.
- Auth seeding was unsupported because this repo uses external Shopify OAuth/device-flow and token/session caches rather than a local database-backed identity system.

## Auth Context

| Label | Email | Role | Token Available | Used By |
|-------|-------|------|-----------------|---------|
| — | — | — | none | No local identities seeded; external Shopify OAuth/session tokens unavailable in this confirmation workspace. |

Auth seed note: Shopify CLI uses external Shopify OAuth/device-flow and token-based sessions. The repository has no local registration endpoint, login endpoint, role table, seed script, or local datastore where privileged/low-privileged identities can be created by the provisioner.

## Methodology

1. Scanned every `piolium/findings/*/report.md` plus any `piolium/findings/FP-*` directory and cross-referenced the V1 inventory.
2. Extracted finding ID, slug, title, severity, original PoC status, confirmation fields, and evidence/test pointers from the reports; used V4/V5 workspace JSON only to reconcile structured execution details and commands.
3. Applied the required one-category deduplication priority: `confirmed-live` > `confirmed-test` > `confirmed-fp` > `analytical-only` > `unconfirmed` > `inconclusive` > `blocked` > `no-poc` > `error`.
4. Counted `confirmed-live` and `confirmed-test` as confirmed. Excluded only `confirmed-fp` and `analytical-only` from the confirmation-rate denominator.
5. Ran final cleanup after report data collection and recorded the result under `piolium/confirm-workspace/cleanup-result.json` and `cleanup.log`.
