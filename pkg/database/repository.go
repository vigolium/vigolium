package database

import (
	"errors"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// Repository handles HTTP record and finding storage
type Repository struct {
	db *DB

	// OnRecordSaved, when non-nil, is invoked with each newly inserted HTTP
	// record (deduplicated saves and dedup hits do NOT fire). OnFindingSaved is
	// the equivalent for newly inserted findings (a dedup-append to an existing
	// finding does not fire). Both run synchronously on the save goroutine, so
	// implementations must be fast and non-blocking (e.g. enqueue and return).
	// Used by the server's --mirror-fs filesystem mirror; left nil elsewhere, so
	// CLI scans and other repo users are unaffected.
	OnRecordSaved  func(*HTTPRecord)
	OnFindingSaved func(*Finding)
}

// emitRecordSaved fires the OnRecordSaved hook when set. Centralized so every
// record-insert path notifies the same way without repeating the nil check.
func (r *Repository) emitRecordSaved(rec *HTTPRecord) {
	if r.OnRecordSaved != nil {
		r.OnRecordSaved(rec)
	}
}

// emitFindingSaved fires the OnFindingSaved hook when set.
func (r *Repository) emitFindingSaved(f *Finding) {
	if r.OnFindingSaved != nil {
		r.OnFindingSaved(f)
	}
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

// maxAdditionalEvidence caps how many request/response pairs a finding retains
// under AdditionalEvidence, both for its own emitted evidence (the converter cap
// in converters.go) and for a survivor that folds in duplicates (the evidence
// merge paths in repository_dedup.go). It is pinned to modkit.MaxEvidencePairs —
// the same cap the emit-time collector enforces — so a module's carefully
// collected pairs are never silently truncated on the way to storage, and the two
// layers can never drift apart again. Kept bounded so a noisy module (one that
// fires on many sibling paths of the same host) does not balloon the stored
// request/response payload — and, via the converter cap, the http_records table.
const maxAdditionalEvidence = modkit.MaxEvidencePairs

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
