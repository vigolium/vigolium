// Package database provides the repository layer over SQLite (default) or
// PostgreSQL via the Bun ORM. It persists scans, HTTP records, findings, scopes,
// and OAST interactions — all scoped to a project_uuid for multi-tenancy. It
// supports batched HTTP-record ingestion (SaveRecordBatch, RecordWriter) and
// per-source deduplication (DeduplicateRecordsBySource).
package database
