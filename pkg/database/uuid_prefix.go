package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/uptrace/bun"
)

// uuidPrefixTables are the tables ResolveUUIDPrefix may scan: each has a text
// uuid primary key and a project_uuid column.
var uuidPrefixTables = map[string]bool{
	"http_records":  true,
	"scans":         true,
	"agentic_scans": true,
}

// MaxUUIDPrefixCandidates bounds the candidates an ambiguous prefix returns.
const MaxUUIDPrefixCandidates = 5

// ResolveUUIDPrefix resolves a UUID prefix in table, within projectUUID
// ("" = every project). It returns the full UUID of the one match;
// sql.ErrNoRows when nothing matches; and, when the prefix is ambiguous, ""
// with up to MaxUUIDPrefixCandidates matching UUIDs. A full UUID that exists
// resolves to itself even when it also prefixes a longer id.
//
// The scan is a range on the primary key (uuid >= prefix AND uuid < next),
// so it uses the index rather than a LIKE. Scoping by project keeps an
// ambiguity from naming another project's rows. The minimum prefix length is
// the caller's policy.
func (r *Repository) ResolveUUIDPrefix(ctx context.Context, table, projectUUID, prefix string) (string, []string, error) {
	if !uuidPrefixTables[table] {
		return "", nil, fmt.Errorf("resolve uuid prefix: table %q is not resolvable", table)
	}
	upper, ok := prefixUpperBound(prefix)
	if !ok {
		return "", nil, sql.ErrNoRows
	}
	var uuids []string
	q := r.db.NewSelect().
		TableExpr("?", bun.Ident(table)).
		Column("uuid").
		Where("uuid >= ? AND uuid < ?", prefix, upper)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if err := q.OrderExpr("uuid").Limit(MaxUUIDPrefixCandidates).Scan(ctx, &uuids); err != nil {
		return "", nil, err
	}
	switch {
	case len(uuids) == 0:
		return "", nil, sql.ErrNoRows
	case len(uuids) == 1, uuids[0] == prefix:
		return uuids[0], nil, nil
	}
	return "", uuids, nil
}
