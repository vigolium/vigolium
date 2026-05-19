// Package storage provides interfaces, types, and implementations for result storage and site map management.
//
// This package combines the domain model (interfaces, types) with the concrete implementation,
// providing thread-safe flat storage for discovered URLs with complete request/response data
// and discovery metadata.
//
// Key Components:
//   - Storage interface: Core contract for result storage implementations
//   - SiteMap: Database-backed storage with SQLite/PostgreSQL support
//   - TreeNode: Node representing a discovered URL (flat storage, not hierarchical)
//   - Result: Complete discovery result with request/response/metadata
//   - Semantic hash-based deduplication: FNV-1a-64 hash of request structure
//   - Export formats: JSON, CSV, HTML, and text output
//
// Deduplication:
// Nodes are deduplicated by semantic hash, not URL string. The hash includes:
//   - scheme, host, method, statusCode, serverHeader, path, queryNames, bodyKeys
//
// This allows requests with same structure but different parameter values to be deduplicated.
// For example, /api/users?id=1 and /api/users?id=2 share the same hash.
//
// Thread Safety:
// The SiteMap implementation is fully thread-safe and supports concurrent access from
// multiple discovery workers using a mutex for serializing writes.
//
// Session Isolation:
// Each discovery run creates a new session. Nodes are stored globally and linked to sessions
// via a junction table (session_nodes) with action="discovered" or "updated".
//
// Usage Example:
//
//	cfg := storage.SQLiteConfig("/path/to/db.sqlite")
//	sm, _ := storage.NewSiteMap(cfg)
//	defer sm.Close()
//
//	// Store discovery result
//	result := storage.NewResultBuilder().
//	    WithURL(url).
//	    WithRequest("GET", headers, body).
//	    WithResponse(200, respHeaders, respBody, int64(len(respBody)), "text/html", "", "").
//	    WithMetadata("spider", 1, time.Now()).
//	    Build()
//
//	sm.Store(result)
package storage
