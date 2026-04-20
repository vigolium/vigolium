# Database Model Design Review

Date: 2026-04-13

## Scope

This review covers the current database model design in:

- `pkg/database/models.go`
- `pkg/database/db.go`
- `pkg/database/repository.go`
- `pkg/database/query.go`
- `pkg/database/repository_agentic_scans.go`
- `pkg/database/repository_sessions.go`
- `pkg/database/stats.go`

The focus is schema design, data integrity, normalization tradeoffs, and likely optimization/cleanup opportunities based on actual query paths.

## Overall Assessment

The current design is pragmatic and optimized for fast feature delivery:

- it is strongly append-oriented
- it favors denormalized read models
- it keeps SQLite compatibility front and center
- it pushes a lot of integrity enforcement into Go code instead of database constraints

That approach is workable, but the codebase is now carrying visible schema debt in a few places:

- some uniqueness rules are too broad for a multi-project system
- some relationships are represented twice
- several hot queries do not line up well with the current indexes
- the largest tables combine hot query fields with heavy blob/text payloads
- project scoping is not enforced consistently in all read paths

## Highest Priority Findings

### 1. `findings.finding_hash` uniqueness is global instead of project-scoped

Current schema:

- `finding_hash TEXT NOT NULL`
- unique index on `findings(finding_hash)`

Relevant code:

- `pkg/database/db.go`: unique index `idx_findings_hash_unique`
- `pkg/database/repository.go`: inserts use `ON CONFLICT (finding_hash) DO NOTHING`
- `pkg/database/repository.go`: duplicate merge lookup is `WHERE finding_hash = ?`

Why this is a problem:

- the database is explicitly multi-project
- identical finding hashes in two different projects can collide
- one project can silently suppress or merge another project's finding
- the current dedup behavior crosses tenant boundaries

Recommendation:

- replace global uniqueness with a composite unique constraint/index on `(project_uuid, finding_hash)`
- update all conflict clauses and merge lookups to include `project_uuid`

Priority: High

## 2. `scans.modules` is a brittle text key for incremental cursor reuse

Current schema:

- `modules TEXT`

Relevant code:

- `pkg/database/repository.go`: `CreateScanWithCursor` looks up prior completed scans by exact `modules` string
- that lookup does not scope by `project_uuid`

Why this is a problem:

- exact string matching is fragile
- the same modules in different orders produce different values
- formatting/canonicalization bugs change behavior
- cursor state can leak across projects because the lookup is not project-aware

Recommendation:

- best option: normalize into a `scan_modules` child table
- acceptable option: store canonical sorted JSON and hash it into a stable key
- scope the previous-scan lookup by `project_uuid`
- add an index that supports project-aware resume lookups

Priority: High

## 3. `findings` has two competing record-link representations

Current schema:

- `findings.http_record_uuids TEXT NOT NULL`
- `finding_records(finding_id, record_uuid)` junction table

Relevant code:

- schema backfills `finding_records` from `http_record_uuids`
- runtime queries use `finding_records`
- writes still update both representations

Why this is a problem:

- two sources of truth means drift risk
- repair and backfill logic becomes permanent complexity
- delete and dedup paths must clean both layers
- the JSON array adds storage overhead without giving better queryability

Recommendation:

- keep `finding_records` as the canonical relation
- stop storing `http_record_uuids` in `findings`
- migrate read/write paths fully to the junction table
- optionally keep a derived cached count if the UI needs fast badge rendering

Priority: High

## Medium Priority Findings

### 4. `http_records` mixes hot metadata with heavy request/response blobs

Current table includes:

- routing/query fields like `project_uuid`, `hostname`, `path`, `method`, `status_code`
- plus large payloads like `raw_request`, `request_body`, `raw_response`, `response_body`

Why this is a problem:

- this is likely the largest table in the system
- list/filter queries pay the storage and IO cost of very wide rows
- vacuuming, compaction, and cache behavior get worse as the table grows
- full request/response content is not needed for many operational queries

Recommendation:

- split cold payload fields into a side table keyed by record UUID
- keep the base `http_records` row focused on queryable metadata and compact summaries
- consider storing only one canonical body form where possible

Priority: Medium

### 5. `findings` stores heavy inline evidence text

Current table includes:

- `request TEXT`
- `response TEXT`
- `additional_evidence TEXT`

Why this is a problem:

- findings are frequently listed and filtered
- large inline evidence inflates table size
- some list queries explicitly exclude heavy columns, which is a sign the row is too wide for its main read path

Recommendation:

- move request/response/evidence blobs to a child table such as `finding_evidence`
- keep the main `findings` table focused on classification and status

Priority: Medium

### 6. Several hot queries do not match existing indexes

Observed examples:

- `GetUnprobedRecordsBySource` filters by `project_uuid`, `source`, `hostname`, `has_response` and orders by `created_at`
- `ListAgenticScans` filters by `project_uuid`, sometimes `mode`, excludes child runs, and orders by `created_at DESC`
- `GetSessionHostnamesByScan` filters by `project_uuid`, `scan_uuid` and orders by `hostname`, `position`

Current indexes are only partially aligned.

Recommendation:

- add a composite index for the unprobed queue pattern on `http_records`
- add an agent run index shaped for project root-run listing
- add a session hostname index shaped for project+scan ordered retrieval

Suggested shapes:

- `http_records(project_uuid, source, hostname, has_response, created_at)`
- `agentic_scans(project_uuid, mode, created_at)` or a variant that also supports root-run filtering
- `session_hostnames(project_uuid, scan_uuid, hostname, position)`

Priority: Medium

### 7. Integrity is enforced mostly in application code, not the schema

Observed patterns:

- no real foreign keys on obvious child tables
- enum-like columns are free-form text
- cleanup helpers like orphan deletion compensate for weak relational enforcement

Examples:

- `finding_records` has no FK to `findings` or `http_records`
- `scan_logs.scan_uuid` is logically a child reference with no FK
- status columns are plain text with comments, not `CHECK` constraints

Why this matters:

- invalid states can be written silently
- cleanup logic becomes mandatory instead of exceptional
- bugs become data-quality issues

Recommendation:

- add FKs where they are operationally safe and low-risk
- add `CHECK` constraints for enum-like values
- keep soft references only where cross-mode flexibility is truly required

Priority: Medium

### 8. Project scoping is not fully consistent in read paths

Observed example:

- `GetRelatedRecords` fetches sibling records by hostname/path without project filtering after loading the source record

Why this matters:

- in a multi-project database, some reads can cross project boundaries
- even when UUIDs are globally unique, related-record expansion should respect project isolation

Recommendation:

- make project scoping explicit in all secondary lookups
- review getter/query helpers for project-bound semantics

Priority: Medium

## Lower Priority Cleanup Opportunities

### 9. `source_repos` is carrying array-shaped discovery data in one row

Current columns include JSON arrays for:

- `endpoints`
- `route_params`
- `sinks`
- `auth_endpoints`
- `tags`

This is reasonable if the table is low-volume and mostly write-once. It becomes awkward if:

- these arrays grow large
- they need partial querying
- dedup and incremental refresh become important

Recommendation:

- keep as-is if usage remains low-volume metadata
- otherwise split high-cardinality arrays into child tables

Priority: Low to Medium

### 10. Enum-like string columns should be formalized

Examples:

- `findings.severity`
- `findings.status`
- `findings.confidence`
- `scans.status`
- `agentic_scans.status`
- `agentic_scans.mode`
- `source_repos.repo_type`
- `source_repos.third_party_scan_status`

Recommendation:

- add `CHECK` constraints now, or
- introduce compact lookup tables if values are expected to evolve

Priority: Low to Medium

### 11. Some text columns are likely overloading multiple semantics

Examples:

- `scans.target`
- `scans.modules`
- `agentic_scans.input_raw`
- `session_hostnames.extract_rules`

These fields are convenient, but they are doing too much work:

- raw storage
- transport
- identity
- query key

Recommendation:

- keep them for payload capture
- avoid relying on them as stable relational keys or matching fields

Priority: Low

## Table-by-Table Improvement Summary

### `findings`

Improve:

- make uniqueness project-scoped
- remove `http_record_uuids`
- move large evidence fields out of the main row
- add constraints for severity/status/confidence

### `http_records`

Improve:

- split heavy payload blobs from hot metadata
- add queue/list indexes for actual repository query patterns
- review whether some JSON/text search fields should remain inline or move to derived/search tables

### `scans`

Improve:

- redesign `modules`
- make cursor inheritance project-aware
- add a resume-friendly index for prior-scan lookup

### `finding_records`

Improve:

- make it the only source of truth for finding-to-record relations
- add foreign keys if operationally acceptable

### `agentic_scans`

Improve:

- add list-query indexes shaped for `project_uuid`, root/child filtering, `mode`, and `created_at`
- consider whether large debug/output text should remain inline forever or move to artifacts-only storage

### `session_hostnames`

Improve:

- add indexes that match `project+scan` and ordered host retrieval
- consider whether sensitive token material should be separated or protected differently

### `source_repos`

Improve:

- normalize only if array fields become actively queried or high-cardinality
- otherwise leave mostly as-is

### `oast_interactions`

Improve:

- add constraints if `protocol` and related classification values are stable
- review whether `unique_id` uniqueness should be project-scoped or globally guaranteed by the upstream system

## Recommended Migration Order

1. Fix `findings` dedup scope:
   - move unique key to `(project_uuid, finding_hash)`
   - update conflict handling and merge lookups

2. Eliminate duplicate link storage:
   - make `finding_records` canonical
   - remove `http_record_uuids` from runtime usage

3. Fix cross-project scan cursor reuse:
   - scope previous-scan lookup by project
   - redesign `scans.modules`

4. Add missing query-shape indexes:
   - unprobed record queue
   - agent run list
   - session hostname by scan

5. Split cold payload/evidence data from hot tables:
   - `http_records` payloads
   - `findings` evidence blobs

6. Add schema-level integrity:
   - FKs where safe
   - `CHECK` constraints for enum-like values

## Closing View

The current schema is serviceable, but the biggest structural issue is that the logical multi-project design is stronger in the application layer than in the database layer. The two highest-value corrections are:

- making dedup/uniqueness rules project-safe
- removing duplicated relationship storage

After that, the next payoff is operational:

- align indexes to real repository queries
- split cold large payloads away from hot list/filter rows

Those changes would reduce correctness risk first, then improve performance and maintainability.
