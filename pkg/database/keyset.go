package database

import (
	"context"
	"database/sql"
	"errors"

	"github.com/uptrace/bun"
)

// Keyset paging for the finding and traffic list reads.
//
// An offset page is a position in a list that a running scan keeps changing:
// the default order is newest first, so every row a scan stores pushes the next
// page's rows down by one, and every finding the dedup pass merges pulls them
// up. Following --offset across pages under a live scan repeats rows or skips
// them. A keyset page is instead positioned AFTER one row's sort value and
// tie-breaker, which rows written or removed elsewhere in the order cannot
// move.
//
// The sort value of the boundary row is read back from the store as the store
// holds it (KeysetAt), not from the Go value: a timestamp column holds text in
// more than one layout (bun's, SQLite's CURRENT_TIMESTAMP, an import's), and a
// value re-rendered from time.Time compares as different text than the stored
// one. Text and time columns are compared as text, numeric ones as integers,
// which is how ORDER BY compares them.

// Keyset is a position in a list read's order: one row's sort value as the
// store holds it, and the row's unique tie-breaker.
type Keyset struct {
	// Value is a string (text and time columns) or an int64 (numeric ones).
	Value any
	// Tie is the row's unique id: the finding id (int64) or the record uuid
	// (string).
	Tie any
}

// keysetOrder is a list read's resolved order: the sort expression, whether
// it is numeric, the unique tie-breaker column and the direction.
type keysetOrder struct {
	expr    string
	numeric bool
	tie     string
	desc    bool
}

// identity names the order a keyset belongs to, so a cursor issued for one
// order is refused under another.
func (o keysetOrder) identity() string {
	dir := "asc"
	if o.desc {
		dir = "desc"
	}
	return o.expr + " " + dir
}

func (o keysetOrder) apply(query *bun.SelectQuery) {
	dir := " ASC"
	if o.desc {
		dir = " DESC"
	}
	query.OrderExpr(o.expr + dir)
	if o.expr != o.tie {
		query.OrderExpr(o.tie + dir)
	}
}

// after narrows query to the rows strictly after k in this order.
func (o keysetOrder) after(query *bun.SelectQuery, k *Keyset) {
	if k == nil {
		return
	}
	cmp := " > "
	if o.desc {
		cmp = " < "
	}
	if o.expr == o.tie {
		query.Where(o.tie+cmp+"?", k.Tie)
		return
	}
	query.Where("("+o.expr+cmp+"? OR ("+o.expr+" = ? AND "+o.tie+cmp+"?))", k.Value, k.Value, k.Tie)
}

// position reads one row's keyset back from the store. ok is false when the
// row is gone (removed between the page read and this one).
func (o keysetOrder) position(ctx context.Context, query *bun.SelectQuery, tie any) (*Keyset, bool, error) {
	query.Where(o.tie+" = ?", tie).Limit(1)
	var err error
	k := &Keyset{Tie: tie}
	if o.numeric {
		var n sql.NullInt64
		err = query.ColumnExpr(o.expr).Scan(ctx, &n)
		k.Value = n.Int64
	} else {
		var s sql.NullString
		err = query.ColumnExpr("CAST("+o.expr+" AS TEXT)").Scan(ctx, &s)
		k.Value = s.String
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return k, true, nil
}

// findingKeysetOrder is the finding list's order for this builder's sort.
func (fqb *FindingsQueryBuilder) keysetOrder() keysetOrder {
	sortBy := fqb.filters.SortBy
	if sortBy == "" {
		sortBy = "found_at"
	}
	expr := fqb.mapFindingSortColumn(sortBy)
	return keysetOrder{expr: expr, numeric: expr == severitySortRankExpr, tie: "f.id", desc: !fqb.filters.SortAsc}
}

// KeysetOrder names the order this builder's pages follow; a cursor carries
// it and is refused under any other.
func (fqb *FindingsQueryBuilder) KeysetOrder() string { return fqb.keysetOrder().identity() }

// ExecutePage reads one page of findings: the rows after `after` (or from the
// filters' offset when after is nil) up to the filters' limit, the total that
// match the filters (whatever the page), and whether rows remain after this
// page. A limit of 0 reads every remaining row.
func (fqb *FindingsQueryBuilder) ExecutePage(ctx context.Context, after *Keyset) ([]*Finding, int64, bool, error) {
	order := fqb.keysetOrder()
	findings := make([]*Finding, 0)
	query := fqb.db.NewSelect().Model(&findings).ExcludeColumn(findingBodyColumns...)
	fqb.applyFindingFilters(query)
	order.after(query, after)
	order.apply(query)
	limit := fqb.filters.Limit
	if limit > 0 {
		query.Limit(int64(limit + 1))
	}
	if after == nil && fqb.filters.Offset > 0 {
		query.Offset(int64(fqb.filters.Offset))
	}
	if err := query.Scan(ctx); err != nil {
		return nil, 0, false, err
	}
	more := limit > 0 && len(findings) > limit
	if more {
		findings = findings[:limit]
	}
	total, err := fqb.Count(ctx)
	if err != nil {
		return nil, 0, false, err
	}
	return findings, total, more, nil
}

// KeysetAt is the position just after f in this builder's order, read from
// the store. ok is false when f is no longer stored.
func (fqb *FindingsQueryBuilder) KeysetAt(ctx context.Context, f *Finding) (*Keyset, bool, error) {
	if f == nil {
		return nil, false, nil
	}
	return fqb.keysetOrder().position(ctx, fqb.db.NewSelect().Model((*Finding)(nil)), f.ID)
}

// recordKeysetOrder is the traffic list's order for this builder's sort.
// source is the one nullable sort column, so it orders by COALESCE: NULL and
// "" are the same "no source", and a NULL never compares false against a
// cursor value.
func (qb *QueryBuilder) keysetOrder() keysetOrder {
	sortBy := qb.filters.SortBy
	if sortBy == "" {
		sortBy = "created_at"
	}
	expr := qb.mapSortColumn(sortBy)
	numeric := false
	switch expr {
	case "r.status_code", "r.response_time_ms", "r.risk_score", "r.surface_score":
		numeric = true
	case "r.source":
		expr = "COALESCE(r.source, '')"
	}
	return keysetOrder{expr: expr, numeric: numeric, tie: "r.uuid", desc: !qb.filters.SortAsc}
}

// KeysetOrder names the order this builder's pages follow.
func (qb *QueryBuilder) KeysetOrder() string { return qb.keysetOrder().identity() }

// ExecutePage reads one page of records; see FindingsQueryBuilder.ExecutePage.
func (qb *QueryBuilder) ExecutePage(ctx context.Context, after *Keyset) ([]*HTTPRecord, int64, bool, error) {
	order := qb.keysetOrder()
	records := make([]*HTTPRecord, 0)
	query := qb.db.NewSelect().Model(&records)
	if qb.omitBodies {
		query = query.ExcludeColumn(recordBodyColumns...)
	}
	qb.applyFilters(query)
	order.after(query, after)
	order.apply(query)
	limit := qb.filters.Limit
	if limit > 0 {
		query.Limit(int64(limit + 1))
	}
	if after == nil && qb.filters.Offset > 0 {
		query.Offset(int64(qb.filters.Offset))
	}
	if err := query.Scan(ctx); err != nil {
		return nil, 0, false, err
	}
	more := limit > 0 && len(records) > limit
	if more {
		records = records[:limit]
	}
	total, err := qb.Count(ctx)
	if err != nil {
		return nil, 0, false, err
	}
	return records, total, more, nil
}

// KeysetAt is the position just after rec in this builder's order.
func (qb *QueryBuilder) KeysetAt(ctx context.Context, rec *HTTPRecord) (*Keyset, bool, error) {
	if rec == nil {
		return nil, false, nil
	}
	return qb.keysetOrder().position(ctx, qb.db.NewSelect().Model((*HTTPRecord)(nil)), rec.UUID)
}
