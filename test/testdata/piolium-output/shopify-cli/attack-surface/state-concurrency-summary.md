# Stage 06 — State Machine & Concurrency Summary

Target: Shopify CLI monorepo (`/Users/bytedance/Desktop/oss-to-run/shopify-cli`)  
Mode: deep / Piolium Stage 06  

## Scope loaded

- Reviewed `piolium/attack-surface/knowledge-base-report.md` architecture, DFD/CFD, data-store, domain attack research, and CodeQL structural sections.
- Reviewed `piolium/codeql-artifacts/entry-points.json` and `sinks.json` at a sampling level for write/state-changing flows.
- Checked for first-party DB schemas/migrations/ORM models: no application SQL/ORM migration set was found (only GraphQL operation documents and generated CodeQL DB artifacts). State is held in local `conf` stores, in-memory dev-server objects, local filesystem/project files, and Shopify remote Admin/App Management resources.

## State-holding entities catalogued

| # | Entity / store | State fields | Owner / files | Notes |
|---:|---|---|---|---|
| 1 | CLIKit local session store | `sessionStore`, `currentSessionId`, `devSessionStore`, `currentDevSessionId` | `packages/cli-kit/src/private/node/conf-store.ts`, `session/store.ts` | JSON-in-`conf`; no cross-process lock. |
| 2 | CLIKit cache / rate-limit store | `cache`, `most-recent-occurrence-*`, `rate-limited-occurrences-*`, `autoUpgradeEnabled` | `packages/cli-kit/src/private/node/conf-store.ts` | RMW cache updates; telemetry/cache impact only. |
| 3 | Store app auth sessions | `currentUserId`, `sessionsByUserId`, `accessToken`, `refreshToken`, `expiresAt`, `refreshTokenExpiresAt` | `packages/store/src/cli/services/store/auth/session-store.ts` | Local token bucket per store; RMW merge on write. |
| 4 | App local cache | `appId`, `appGid`, `orgId`, `storeFqdn`, `updateURLs`, `previousAppId`, selected config | `packages/app/src/cli/services/local-storage.ts` | Local context cache; not authoritative for server authZ. |
| 5 | Theme local cache | `themeStore`, development/repl theme IDs, storefront password | `packages/theme/src/cli/services/local-storage.ts` | Uses `AsyncLocalStorage` for multi-env context, not a lock. |
| 6 | Remote Online Store themes | `id`, `name`, `role`, `processing`; asset checksums | `packages/cli-kit/src/public/node/themes/api.ts`, GraphQL theme docs | Remote mutable resource; used by push/dev/publish/delete. |
| 7 | Theme filesystem sync state | `files`, `unsyncedFileKeys`, `uploadErrors`, remote checksum snapshots | `packages/theme/src/cli/utilities/theme-fs.ts`, `theme-uploader.ts` | Snapshot/diff model; no remote compare-and-swap. |
| 8 | App versions/releases | `appVersion`, `versionTag`, release status/user errors | `packages/app/src/cli/services/deploy.ts`, `deploy/upload.ts`, `release.ts` | Server-side deploy/release mutations appear authoritative. |
| 9 | Bulk operations | `bulkOperation.id`, `status`, `createdAt`, `completedAt`, staged upload key | `packages/app/src/cli/services/bulk-operations/**` | Mutating path lacks persisted idempotency/resume key. |
| 10 | Dev sessions | `devSessionCreate/Update/Delete`, local `DevSessionStatus` (`isReady`, URLs, status message) | `packages/app/src/cli/services/dev/**` | Remote dev session plus local in-memory status manager. |
| 11 | Extension dev payload store | extension/app payload, websocket update/log/dispatch events | `packages/app/src/cli/services/dev/extension/payload/store.ts`, `websocket/handlers.ts` | In-memory dev-server mutable state. |
| 12 | Cloudflare tunnel state | `currentStatus` (`not-started`, `starting`, `connected`, `error`) | `packages/plugin-cloudflare/src/tunnel.ts` | In-memory status; no persistent security state. |
| 13 | Downloaded function/tool binaries | shared binary paths; `downloadsInProgress` map | `packages/app/src/cli/services/function/binaries.ts` | In-process concurrency guard only; cross-process race is reliability/supply-chain adjacent. |

## Concurrency primitives observed

- `AsyncLocalStorage` in `packages/theme/src/cli/services/local-storage.ts` to isolate theme store context during multi-environment execution.
- In-process promise dedupe map `downloadsInProgress` in `packages/app/src/cli/services/function/binaries.ts` for same-process binary downloads.
- No database transaction boundaries, `SELECT FOR UPDATE`, advisory locks, Redis/Redlock/SETNX, or distributed locks found in first-party TypeScript sources.
- No stored idempotency table/key infrastructure found. `request_id` appears as telemetry/API request tracking, not dedupe. `bulkOperationRunMutation` GraphQL supports a `clientIdentifier` argument, but the CLI's mutation caller does not populate it.

## Hypothesis sweep results

| Class | Result |
|---|---|
| TOCTOU / RMW on money | No financial balance/credit/debit inventory-ledger entity is implemented in this repo. No money double-spend finding filed. |
| RMW-no-transaction | Local `conf` stores use read/merge/write patterns, but reviewed cases were caches/session preferences with local-user reliability impact rather than a security boundary. |
| Missing `SELECT FOR UPDATE` | Not applicable; no SQL/ORM data store. |
| State-machine violations | Store PKCE callback checks `state` with constant-time compare and single promise settlement; app release uses version IDs. No state-machine violation filed. |
| Idempotency failures | **Filed p6-001** for Admin bulk mutations: ambiguous request outcomes can be retried without a persisted idempotency/resume key. |
| Replay windows on signed tokens | No JWT/HMAC state-changing local endpoint found in scope; OAuth state is checked. |
| Saga compensation gaps | Staged upload + bulk operation has orphaned-upload risk on failure, but impact is secondary; the stronger issue is the missing idempotency on mutation submission. |
| Double-submit races | **Filed p6-002** for development-theme `findOrCreate`: lookup-by-name and create are separate remote operations. |
| Stale-read/lost-update | Theme push uses remote checksum snapshots and non-conditional upsert/delete. This is a design-level lost-update risk among actors already able to mutate the same theme; not filed as a standalone security draft in this pass. |
| Client-provided timestamps | No authorization/quota decision based directly on request-provided timestamps found. |

## Drafts filed

1. `piolium/findings-draft/p6-001-bulk-mutation-replay-without-idempotency.md` — `idempotency`, MEDIUM.
2. `piolium/findings-draft/p6-002-development-theme-find-or-create-double-submit.md` — `double-submit`, MEDIUM.

## Recommended follow-up

- For bulk operations, add a deterministic request key and persist operation IDs locally so retries can resume/poll instead of submitting again.
- For development themes, prefer a server-side atomic create-or-get keyed by `(shop, development context)`; otherwise add a local/distributed lock and duplicate reconciliation.
- If future phases confirm `clientIdentifier` is a Shopify API dedupe key, wire it through `runBulkOperationMutation`; if it is only diagnostic metadata, implement local dedupe/resume around operation creation.
