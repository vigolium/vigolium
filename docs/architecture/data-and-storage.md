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
- **Selection precedence** — `--project-uuid` > `--project-name` > `VIGOLIUM_PROJECT_UUID` > legacy `VIGOLIUM_PROJECT` > `~/.vigolium/active-project` > default. On the server, `X-Project-UUID` selects the project.
- **Project config** is a partial YAML overlay (same shape as a scanning profile) at `~/.vigolium/projects/<uuid>/config.yaml`; only the keys it sets are overridden.
- **Management safety** — `VIGOLIUM_PROJECT_READONLY=true` disables mutating
  `project` CLI subcommands. Project selection scopes data; it is not an
  email/domain authorization layer.

### Tables carrying `project_uuid`

`scans` · `http_records` · `findings` · `scopes` · `source_repos` · `oast_interactions` · `scan_logs`

Existing databases are migrated in place — the column is added with the default-project UUID as its default, so pre-multi-tenancy data lands in the default project.

---

## 2. The database backend

Vigolium uses the **repository pattern over Bun ORM**, with two interchangeable backends:

| Backend | Driver | Use |
|---------|--------|-----|
| SQLite (default) | `sqliteshim` → modernc | Single-binary, zero-config, local scans |
| PostgreSQL | `pgdriver` | Shared/server deployments, concurrent writers |

The schema is intentionally **denormalized** — there are no separate hosts or parameters tables; JSONB columns carry structured sub-data. This keeps a single `http_records` row self-contained and avoids join fan-out on the hot ingestion path.

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
- *Relations*: `HTTPRecordUUIDs` (JSONB), `ScanUUID`; the `finding_records` junction table is the many-to-many link to HTTP records.

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
