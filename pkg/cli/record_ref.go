package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// Record references: every flag or argument that names a stored record by UUID
// accepts a unique prefix of it, the way git resolves a short hash. Eight hex
// characters is what `uuid_short` prints and what fits a readout; transcribing
// 36 characters is something a model gets wrong often enough to matter.

// uuidShortLen is the length of a uuid_short: the shortest prefix the resolver
// expands.
const uuidShortLen = database.MinUUIDPrefix

// uuidShort returns the resolvable short form of a record UUID.
func uuidShort(u string) string {
	if len(u) <= uuidShortLen {
		return u
	}
	return u[:uuidShortLen]
}

// resolveRecordRef expands ref — a full record UUID or a unique prefix of one —
// to the full UUID of a record in the current project.
//
// A full UUID is returned unchanged without a lookup (the caller's own read
// reports a missing row in its own words). Anything shorter is one range scan
// within projectUUID, which an exact id falls inside too and wins (imported
// records can carry ids that are not UUIDs), and which never names another
// project's records in an ambiguity. A ref under eight characters is accepted
// only as an exact id. No match is sql.ErrNoRows; several are ambiguous_id.
func resolveRecordRef(ctx context.Context, repo *database.Repository, ref, projectUUID string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || len(ref) >= 36 || repo == nil {
		return ref, nil
	}
	if len(ref) < uuidShortLen {
		owner, err := repo.RecordProjectUUID(ctx, ref)
		switch {
		case err == nil && (projectUUID == "" || owner == projectUUID):
			return ref, nil
		case err == nil:
			return "", sql.ErrNoRows // another project's record reads as missing
		case errors.Is(err, sql.ErrNoRows):
			return "", usageErrorf("record reference %q is too short: give at least %d characters of the UUID (uuid_short)", ref, uuidShortLen)
		default:
			return "", err
		}
	}
	full, candidates, err := repo.ResolveRecordUUIDInProject(ctx, ref, projectUUID)
	if err != nil {
		return "", err
	}
	if len(candidates) > 1 {
		return "", ambiguousRecordRef(ref, candidates)
	}
	return full, nil
}

// recordNotFound is the error for a record reference that names nothing the
// read may see. Another project's record reads the same as a missing one:
// saying it belongs elsewhere would confirm it exists.
func recordNotFound(ref string) error {
	return codedErrorf(apicontract.CodeRecordNotFound,
		"no stored record matches %q.\n\nList what is there with: vigolium traffic --compact --fields uuid_short,url -j", ref)
}

// isRecordNotFound reports whether err is recordNotFound's.
func isRecordNotFound(err error) bool {
	var coded clicommon.CodedError
	return errors.As(err, &coded) && coded.Code() == apicontract.CodeRecordNotFound
}

// loadRecordRef resolves ref within the current project and loads the record.
func loadRecordRef(ctx context.Context, repo *database.Repository, ref string) (*database.HTTPRecord, string, error) {
	scope, err := effectiveProjectUUID()
	if err != nil {
		return nil, "", err
	}
	full, err := resolveRecordRef(ctx, repo, ref, scope)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, scope, recordNotFound(ref)
	}
	if err != nil {
		return nil, scope, err
	}
	rec, err := repo.GetRecordByUUID(ctx, full)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && rec == nil) {
		return nil, scope, recordNotFound(ref)
	}
	if err != nil {
		return nil, scope, fmt.Errorf("read record %q: %w", full, err)
	}
	if scope != "" && rec.ProjectUUID != scope {
		return nil, scope, recordNotFound(ref)
	}
	return rec, scope, nil
}

// ambiguousRecordRef is the error for a prefix that matches several records.
func ambiguousRecordRef(ref string, candidates []database.RecordRefCandidate) error {
	lines := make([]string, 0, len(candidates))
	for _, c := range candidates {
		lines = append(lines, "  "+c.UUID+"  "+c.Method+" "+c.URL)
	}
	return codedErrorf(apicontract.CodeAmbiguousID,
		"record reference %q matches more than one record — give more characters. Candidates (up to 5):\n%s",
		ref, strings.Join(lines, "\n"))
}

// resolveRecordRefs resolves every entry of refs (see resolveRecordRef).
func resolveRecordRefs(ctx context.Context, repo *database.Repository, refs []string, projectUUID string) ([]string, error) {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		full, err := resolveRecordRef(ctx, repo, r, projectUUID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, recordNotFound(r)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, full)
	}
	return out, nil
}
