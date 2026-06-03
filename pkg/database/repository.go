package database

import (
	"errors"

	"github.com/vigolium/vigolium/pkg/output"
)

// Repository handles HTTP record and finding storage
type Repository struct {
	db *DB
}

// ErrScanProjectMismatch is returned by CreateScan / CreateAgenticScan when
// the caller pins a UUID that already exists under a different project. This
// guards against cross-project record corruption when remote nodes sync via
// --scan-uuid.
var ErrScanProjectMismatch = errors.New("scan UUID exists under a different project")

// NewRepository creates a new repository instance
func NewRepository(db *DB) *Repository {
	return &Repository{db: db}
}

// defaultProjectUUID returns DefaultProjectUUID when the given value is empty.
// This prevents Bun from inserting an empty string that bypasses the column DEFAULT.
func defaultProjectUUID(v string) string {
	if v == "" {
		return DefaultProjectUUID
	}
	return v
}

// DB returns the underlying database handle.
func (r *Repository) DB() *DB { return r.db }

// buildEvidence creates an evidence string from a request/response pair.
// Returns empty string if both are empty. Delegates to output.BuildEvidence (the
// single source of truth for the evidence format) with no label, matching the
// unlabeled pairs the merge path appends from duplicate findings.
func buildEvidence(request, response string) string {
	return output.BuildEvidence("", request, response)
}

// EvidenceSeparator is the delimiter between request and response inside an
// AdditionalEvidence entry. Re-exported from pkg/output (the canonical owner) so
// the storage-layer dedup/merge path splits evidence the same way modules emit it.
const EvidenceSeparator = output.EvidenceSeparator

// mergeUniqueStrings returns the deduplicated union of two string slices.
func mergeUniqueStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	result := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}
