// Package dedup provides deduplication primitives for the scan: disk-backed
// seen-sets (DiskSet) and request-hash managers, plus a per-scan Manager that
// vends and owns them keyed by module. Modules hold a Lazy[T] handle that
// resolves once per scan against the runner's Manager, so a shared module
// singleton stays isolated across concurrent scans. A creation failure degrades
// gracefully (dedup is disabled for that key) and is logged rather than
// swallowed.
package dedup
