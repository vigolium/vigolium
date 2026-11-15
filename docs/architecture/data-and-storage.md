# Data & Persistence Architecture

> _Architecture series: [overview](overview.md) · [native-scan](native-scan.md) · [agentic-scan](agentic-scan.md) · **data-and-storage** · [server-and-api](server-and-api.md)_

Every scan path in Vigolium — native, agentic, ingestion — converges on the same persistence layer. This document explains how data is **scoped** (multi-tenancy), **modeled** (the database schema), **written** (the repository pattern and async writer), and **moved between machines** (cloud storage). It is the architectural companion to the task-oriented [projects.md](../projects.md) and [storage.md](../storage.md) guides; reach for those for CLI/API recipes.

---

## 1. Multi-Tenancy: the `project_uuid` spine

All scan data is partitioned by **project** — a named container with a UUID
and optional config overlay. There is no separate database per project;
isolation is a `project_uuid` column on major tables, filtered on reads and
stamped on writes.

```
Built-in defaults
  → ~/.vigolium/vigolium-configs.yaml          (global config)
    → ~/.vigolium/projects/<uuid>/config.yaml  (per-project overlay)
      → --scanning-profile                     (scanning profile)
        → CLI flags                            (highest precedence)
```

- **Default project** — `00000000-0000-0000-defa-c01001000001`, used whenever no project is selected.
- **Selection precedence** — `--project-uuid` > `--project-name` > `VIGOLIUM_PROJECT_UUID` > `VIGOLIUM_PROJECT_NAME` > `~/.vigolium/active-project` > default. On the server, `X-Project-UUID` selects the project.
- **Project config** is a partial YAML overlay (same shape as a scanning profile) at `~/.vigolium/projects/<uuid>/config.yaml`; only the keys it sets are overridden.
- **Management safety** — `VIGOLIUM_PROJECT_READONLY=true` disables mutating
  `project` CLI subcommands. Project selection scopes data; it is not an
  email/domain authorization layer.

### Tables carrying `project_uuid`

`scans` · `http_records` · `findings` · `finding_observations` · `finding_status_events` · `scopes` · `oast_interactions` · `oast_payloads` · `scan_logs` · `analysis_artifacts` · `agentic_scans` · `authentication_hostnames` · `host_observations` · `agent_sections` · `agent_finding_candidates`

Existing databases are migrated in place — the column is added with the default-project UUID as its default, so pre-multi-tenancy data lands in the default project.

---

## 2. The database backend

Vigolium uses the **repository pattern over Bun ORM**, with two interchangeable backends:

| Backend | Driver | Use |
|---------|--------|-----|
| SQLite (default) | `sqliteshim` → modernc | Single-binary, zero-config, local scans |
| PostgreSQL | `pgdriver` | Shared/server deployments, concurrent writers |

The schema is intentionally **denormalized** — there are no separate hosts or parameters tables; JSONB columns carry structured sub-data. This keeps a single `http_records` row self-contained and avoids join fan-out on the hot ingestion path.

### Schema DDL per dialect

The schema lives in one place, `pkg/database/schema_ddl.go`: `schemaTables`, `columnMigrations`, `schemaIndexes` and `recordSecondaryIndexes`. Each statement is a template that names its dialect-sensitive types with a token, and `renderDDL` spells the token for the driver:

| Token | SQLite | PostgreSQL |
|---|---|---|
| `{{AUTOINC_PK}}` | `INTEGER PRIMARY KEY AUTOINCREMENT` | `SERIAL PRIMARY KEY` |
| `{{BLOB}}` | `BLOB` | `BYTEA` |
| `{{BOOL}}`, `{{TRUE}}`/`{{FALSE}}` | `INTEGER`, `1`/`0` | `BOOLEAN`, `TRUE`/`FALSE` |
| `{{TIMESTAMP}}` | `TIMESTAMP` | `TIMESTAMP` |
| `{{JSON}}` | `TEXT` | `TEXT` (queries cast to `jsonb` where they need it) |
| `{{FLOAT}}` | `REAL` | `DOUBLE PRECISION` |

Tests render both dialects without a server: no SQLite-only token (`AUTOINCREMENT`, `BLOB`, `INSERT OR`, …) reaches Postgres, the SQLite spelling of every column is unchanged, every bool / `type:jsonb` / float field of a bun model is declared with its token, and both renders create the same tables, columns and indexes in the same order. A template that spells one of these types literally fails a test.

Postgres stores created before the templates may hold a bool column as `INTEGER` (`http_records.chain_truncated` always did; `is_authenticated` did when added by a column migration), and every bool write to it fails. The readiness check reports such a column as a gap (`http_records.chain_truncated is integer, not boolean`), and the schema pass (`vigolium db migrate`, or any writer's open) converts it in place to `BOOLEAN` (non-zero becomes `TRUE`), one column per transaction. The conversion rewrites the table once.

`pkg/database/pg_suite_test.go` runs the core repository scenarios (record, finding lifecycle, scan row, bool columns, project isolation) against SQLite always and against Postgres when `VIGOLIUM_PG_DSN` is set, plus the legacy-column conversion. Without the variable the `TestPg_` tests skip; when it is set but unreachable, they fail. Locally: `make postgres-up`, then `VIGOLIUM_PG_DSN='postgres://vigolium_test:vigolium_test_pass@localhost:5433/vigolium_test?sslmode=disable' go test -run TestPg_ ./pkg/database/`. CI's `postgres` job runs them next to the e2e `TestPg_` suite. Per decision D22 the job stays non-blocking for now.

### Core models (`pkg/database/models.go`)

**`HTTPRecord`** (table `http_records`) — the unit of ingested traffic:

- *Identity*: `UUID` (PK), `RequestHash` (SHA-256 of the raw request, used for per-source dedup)
- *Host*: `Scheme`, `Hostname`, `Port`, `IP`
- *Request*: `Method`, `Path`, `URL`, `RequestHeaders` (JSONB), `RawRequest`, `RequestBody`
- *Response*: `StatusCode`, `ResponseHeaders` (JSONB), `RawResponse`, `ResponseBody`, `ResponseTitle`, `ResponseWords`
- *Derived*: `Parameters` (JSONB array of `EmbeddedParam`), `RiskScore`, `Remarks`
- *Metadata*: `Source`, `SentAt`, `ReceivedAt`, `CreatedAt`

**`Finding`** (table `findings`) — a detected issue:

- *Identity*: `ID` (auto-increment), `FindingHash` (unique constraint → dedup key, set from the `ResultEvent` ID)
- *Module*: `ModuleID`, `ModuleName`, `Description`, `Severity`, `Confidence`
- *Evidence*: `MatchedAt` (JSONB), `ExtractedResults`, `Request`, `Response`, `AdditionalEvidence` (merged-duplicate request/response pairs, capped at 10)
- *Relations*: `HTTPRecordUUIDs` (JSONB), `ScanUUID` (the most recent scan that observed it); the `finding_records` junction table is the many-to-many link to HTTP records.
- *Lifecycle*: `Status` (`draft`, `triaged`, `confirmed`, `false_positive`, `accepted_risk`, `fixed`) plus the current verdict's `StatusNote`, `StatusActor`, `StatusUpdatedAt`. `Verification` (JSON verdict of the last re-verification) and `VerifiedAt` are kept apart from `Status`.
- *Replay context*: `OriginRecordUUID` (the baseline record the module scanned), `InsertionPoint` (JSON `{type, name}`), `Payload`.

**Finding history.** `finding_observations` holds one row per (finding, scan that observed it), written in the same transaction as every finding save that carries a scan UUID — first detection and re-detection alike — so `findings.scan_uuid` being overwritten by the latest observer loses nothing. `finding_status_events` is the append-only status history. Both are keyed by `findings.id` and carry `project_uuid`: finding deletes, finding dedup (history folds onto the survivor), project reassign/purge and `--db-isolate`/glob merges (with finding-id remapping) all carry them. Schema v3 backfilled one observation per existing finding from `(scan_uuid, found_at)` and stamped `schema_meta.observation_history_since`; history before that instant is partial.

**`Scan`** (table `scans`) also records run liveness (`heartbeat_at`, `current_phase`, `pid`, `runner_host`), the resolved `plan` (JSON) and per-run `module_errors` / `extensions_failed` (JSON). **`oast_payloads`** maps a minted OAST nonce to its scan, module, target, parameter and payload, so out-of-band callbacks can be attributed later.

Agent-produced findings (autopilot/swarm/audit/piolium) flow into the **same `findings` table**, tagged by source so native and AI results coexist and dedup together.

### Converters (`pkg/database/converters.go`)

The in-memory scan types never touch the DB directly. `HTTPRecord.FromHttpRequestResponse()` and `Finding.FromResultEvent()` are the only seam — they generate UUIDs, compute hashes, parse URLs, extract titles, and count words, keeping persistence concerns out of the executor and modules.

---

## 3. Write paths

| Method (`pkg/database/repository.go`) | Role |
|---|---|
| `SaveRecord()` / `SaveRecordsBatch()` | Single vs. bulk INSERT (batch = one transaction) |
| `SaveFinding()` | `INSERT … ON CONFLICT (finding_hash) DO NOTHING` + evidence append + junction rows |
| `DeduplicateFindings()` | Post-phase grouping: merge findings sharing `(module_id, severity, matched_at URL)` |
| `CreateScanWithCursor()` / `CountRecordsAfterCursor()` | Cursor bookkeeping for incremental rescans |
| `GetRecordsWithResponseBody()` | UUID-cursor pagination for batch scanners such as the native secret detector |
| `UpdateRiskScores()` | Batched `CASE/WHEN` UPDATE, 500 UUIDs per statement |

### Async batched ingestion — `RecordWriter`

High-throughput ingestion (proxy capture, bulk import, spidering) does **not** call the repository synchronously. `pkg/database/record_writer.go` fronts it with a buffered channel:

```
Write() ──► buffered chan (cap 4096) ──► single flushLoop goroutine
                                            │  batch of 128, or 50ms tick
                                            ▼
                                   repo.SaveRecordsBatch()  (one txn)
```

Each caller blocks until its row is flushed and gets a `WriteResult{UUID, Err}` back on a per-request result channel — backpressure is the channel capacity, ordering is preserved, and the DB sees large batched transactions instead of a write per request.

> **SQLite DSN note:** the modernc driver needs pragmas in `_pragma=name(value)` form; the `mattn`-style `_busy_timeout=` is silently ignored. Relevant when tuning concurrent-writer behavior.

### Open intent: readers never take the write lock

Every CLI command declares what it does with the store (the `DB` column of `commandTraits` in `pkg/cli/command_traits.go`, stamped on each cobra command as the `vigolium.io/db-intent` annotation; a test fails on an undeclared command). The shared opener (`clicommon.GetDBFor`) opens the store according to that intent:

| Intent | Commands | How the store is opened |
|---|---|---|
| `read` | `traffic`, `finding`, `log`, `db ls/stats/export`, `export`, `auth list`, `agent session`, `doctor` | SQLite read pool: `query_only(1)`, `_txlock=deferred`, no `journal_mode` PRAGMA, no WAL checkpoint, at most 4 connections. Postgres sessions default to read-only transactions. The schema is checked with catalog reads only. |
| `write` | scans, ingest, import, agent runs, `replay`, `fuzz`, project/auth mutations | Read-write store; the schema is made ready (`EnsureSchemaReady`: DDL only when a read-only check finds a gap). |
| evidence | any read command with `--read-only` | `mode=ro`; nothing about the file may change. |

A flag that makes a read write (`--save-to-vigolium-db`, `--in-replace`) flips the invocation to `write`. A read command therefore never queues behind a scan that is writing the same file, and no read path calls `CreateSchema` (a lint test in `pkg/database` rejects new call sites outside the package).

When a read meets a store written by an older vigolium, `database.auto_migrate_on_read` (default `true` for this release) migrates it first through a separate, short-lived writer. With it set to `false` the read fails with `error.code: "schema_outdated"`; run `vigolium db migrate [-j]` to upgrade explicitly. The server keeps the same split: list handlers query a read pool (`DB.OpenReader`) while ingestion and scans use the writer.

Transient lock contention is retried by `database.RetryBusy(ctx, fn, policy)` (exponential backoff, used by `log`, the DB input source, merges and the REST list handlers). When the budget runs out the error carries the code `database_locked` (REST: `503` with `Retry-After`).

### Schema versions and the compatibility guard

`schema_meta` (one row) records `version` (schema revision of the newest binary that migrated the store), `min_reader_version` (oldest binary revision that can still read it), `written_by` (that binary's version) and `updated_at`. A binary whose schema revision is C:

- reads a store when `min_reader_version <= C`;
- writes or migrates it only when `version <= C`; otherwise it refuses with `error.code: "schema_too_new"` ("upgrade vigolium").

Schema history: v1 introduced `schema_meta`; v2 added the guard columns; v3 added the finding-lifecycle and run-liveness columns and the `finding_observations`, `finding_status_events` and `oast_payloads` tables (all additive, `min_reader_version` stays 1). Every schema statement, column migrations and indexes included, is a per-dialect template (see [Schema DDL per dialect](#schema-ddl-per-dialect)).

Additive migrations leave `min_reader_version` unchanged, so an older binary keeps reading a store a newer one upgraded; a breaking migration raises it. The stored version only ever moves up. `vigolium version --json` reports `db_schema_version` and `db_min_reader_version`; `vigolium doctor` shows the store's version, reader floor and `written_by`. Binaries from before the guard (schema v1) cannot be stopped from opening a newer store; the guard protects stores from v2 on.

---

## 4. Deduplication

Two layers, by design:

1. **Per-source HTTP-record dedup** — `RequestHash` (SHA-256 of the raw request) plus `DeduplicateRecordsBySource` collapses re-ingested identical requests within a source.
2. **Finding dedup** — the `finding_hash` unique constraint prevents exact duplicates at insert time; `DeduplicateFindings()` runs after a phase to *group* near-duplicates (same module/severity/URL), folding the extra request/response pairs into the survivor's `AdditionalEvidence` (capped). The multi-driver `audit` command runs an additional project-wide findings dedup pass once its drivers exit.

---

## 5. Cloud storage (optional)

Storage is **disabled by default**. When enabled (`storage.enabled: true`), a single minio-go S3 client talks to GCS (HMAC), S3, or self-hosted MinIO — the driver differs, the rest is identical.

```
gs://<project-uuid>/<key>   ⇒   s3://<storage.bucket>/<project-uuid>/<key>
```

The key architectural point: the **project UUID is the in-bucket prefix**, not the bucket name. Every key is validated (`storage.ValidateKey` rejects `..`, backslashes, absolute paths) and project-prefixed server-side, so one bucket safely holds many projects and clients cannot reach outside their own.

| Conventional prefix | Producer |
|---|---|
| `ugc/<file>` | `vigolium storage upload` (default) |
| `imports/<base>-<ts>.<ext>` | `vigolium import --upload` |
| `native-scans/<scan-uuid>/results.tar.gz` | `vigolium scan --upload-results` |
| `agentic-scans/<run-uuid>/results.tar.gz` | `vigolium agent … --upload-results` |

`gs://` URLs are first-class inputs/outputs: `vigolium import gs://…` downloads-then-imports (detecting audit folders or JSONL inside `.tar.gz`/`.zip`), and any `export -o gs://…` writes locally then uploads on success. The `{ts}` and `{project-uuid}` placeholders expand in any `-o` path. The `bundle` export format round-trips a full snapshot (JSONL + HTML report + manifest + agent session dirs) that another machine can re-import.

---

## Related

- [projects.md](../projects.md) — project CLI/API recipes and access-control management
- [storage.md](../storage.md) — full `vigolium storage` command and `gs://` reference
- [native-scan.md](native-scan.md) — Stage 11 traces a finding from `ResultEvent` to row
- [configuration.md](../configuration.md) — the `storage:` and project config YAML blocks
