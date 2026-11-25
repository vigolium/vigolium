package database

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/uptrace/bun"
)

// Record tags: caller labels on stored records (the record_tags table).
//
// A caller that composes stores (a board built from many runs' traffic, a run
// seeded with carried records) needs to know which records arrived how, and to
// take them back out. `import --tag k=v` labels the records an import wrote,
// `traffic --tag k=v` reads them back, and `db clean --tag k=v` deletes them
// with the findings they alone proved. A record holds one value per key; a
// later import of the same record under the same key replaces the value.

// RecordTag is one key=value label on a stored record.
type RecordTag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// String renders the tag the way the flags spell it.
func (t RecordTag) String() string { return t.Key + "=" + t.Value }

// recordTagKey is the key spelling: it names a label in argv, in SQL
// parameters and in a -j object key, so it stays a plain identifier.
var recordTagKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

// ParseRecordTag parses one "key=value" tag. The key is an identifier
// (letters, digits, '_', '.', ':', '-'); the value is any non-empty text.
func ParseRecordTag(s string) (RecordTag, error) {
	k, v, ok := strings.Cut(s, "=")
	k = strings.TrimSpace(k)
	if !ok || k == "" {
		return RecordTag{}, fmt.Errorf("tag %q is not key=value", s)
	}
	if !recordTagKey.MatchString(k) {
		return RecordTag{}, fmt.Errorf("tag key %q must start with a letter or digit and use only letters, digits, '_', '.', ':' or '-'", k)
	}
	if v == "" {
		return RecordTag{}, fmt.Errorf("tag %q has an empty value", s)
	}
	return RecordTag{Key: k, Value: v}, nil
}

// ParseRecordTags parses repeated "key=value" flags. A key named twice is an
// error: a record holds one value per key, so two values would silently keep
// whichever was written last.
func ParseRecordTags(raw []string) ([]RecordTag, error) {
	out := make([]RecordTag, 0, len(raw))
	seen := map[string]string{}
	for _, s := range raw {
		t, err := ParseRecordTag(s)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[t.Key]; dup {
			if prev == t.Value {
				continue
			}
			return nil, fmt.Errorf("tag key %q is given twice (%q and %q); a record holds one value per key", t.Key, prev, t.Value)
		}
		seen[t.Key] = t.Value
		out = append(out, t)
	}
	return out, nil
}

// recordTagRowsPerInsert bounds one multi-row INSERT: three bound parameters
// per row stays far below SQLite's and Postgres's parameter limits.
const recordTagRowsPerInsert = 500

// execer is the statement runner tagRecords writes through: a bun handle or
// transaction, or the raw transaction a SQLite merge runs in.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// tagRecords writes every tag onto every record uuid, replacing a value the
// record already held under the same key.
func tagRecords(ctx context.Context, db execer, uuids []string, tags []RecordTag) error {
	if len(uuids) == 0 || len(tags) == 0 {
		return nil
	}
	perChunk := max(1, recordTagRowsPerInsert/len(tags))
	for chunk := range slices.Chunk(uuids, perChunk) {
		var (
			values strings.Builder
			args   = make([]any, 0, 3*len(chunk)*len(tags))
		)
		for _, u := range chunk {
			for _, t := range tags {
				if values.Len() > 0 {
					values.WriteString(", ")
				}
				values.WriteString("(?, ?, ?)")
				args = append(args, u, t.Key, t.Value)
			}
		}
		q := "INSERT INTO record_tags (record_uuid, key, value) VALUES " + values.String() +
			" ON CONFLICT (record_uuid, key) DO UPDATE SET value = excluded.value"
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("tag records: %w", err)
		}
	}
	return nil
}

// TagRecords labels the stored records uuids with tags. Records that do not
// exist are not checked for: callers pass the uuids an import just wrote.
func (r *Repository) TagRecords(ctx context.Context, uuids []string, tags []RecordTag) error {
	return tagRecords(ctx, r.db, uuids, tags)
}

// LoadRecordTags returns the tags of the given records, keyed by record uuid
// then tag key. Records with no tag are absent. A store created before
// record_tags existed holds no tag, so it answers an empty map.
func LoadRecordTags(ctx context.Context, db *DB, uuids []string) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	if db == nil || len(uuids) == 0 || !db.tableExists(ctx, "record_tags") {
		return out, nil
	}
	for chunk := range slices.Chunk(uuids, SQLChunkSize) {
		var rows []struct {
			RecordUUID string `bun:"record_uuid"`
			Key        string `bun:"key"`
			Value      string `bun:"value"`
		}
		if err := db.NewRaw("SELECT record_uuid, key, value FROM record_tags WHERE record_uuid IN (?)",
			bun.List(chunk)).Scan(ctx, &rows); err != nil {
			return nil, fmt.Errorf("load record tags: %w", err)
		}
		for _, row := range rows {
			if out[row.RecordUUID] == nil {
				out[row.RecordUUID] = map[string]string{}
			}
			out[row.RecordUUID][row.Key] = row.Value
		}
	}
	return out, nil
}

// applyTagFilter keeps the records (alias r) that carry every tag.
func applyTagFilter(query *bun.SelectQuery, tags []RecordTag) {
	for _, t := range tags {
		query.Where("EXISTS (SELECT 1 FROM record_tags rt WHERE rt.record_uuid = r.uuid AND rt.key = ? AND rt.value = ?)",
			t.Key, t.Value)
	}
}
