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

// maxAdditionalEvidence caps how many request/response pairs a survivor finding
// retains under AdditionalEvidence when duplicates are folded in (the evidence
// merge paths in repository_dedup.go). Kept small so a noisy module (one that
// fires on many sibling paths of the same host) does not balloon the stored
// request/response payload — and, via the converter cap, the http_records table.
const maxAdditionalEvidence = 5

// appendUniqueEvidence appends each candidate to existing, skipping any that is
// empty, byte-identical to primary, or already present. primary is the survivor's
// own request/response pair (already shown as the finding's primary evidence), so
// folding a duplicate that carries the same request/response — e.g. the same
// secret re-detected on the same stored response across scan passes — would just
// print the response twice. This keeps "Additional Evidence" to genuinely
// distinct pairs.
func appendUniqueEvidence(existing []string, primary string, candidates ...string) []string {
	seen := make(map[string]struct{}, len(existing)+len(candidates)+1)
	for _, e := range existing {
		seen[e] = struct{}{}
	}
	if primary != "" {
		seen[primary] = struct{}{}
	}
	out := existing
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

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
