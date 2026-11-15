package database

import (
	"context"
	"database/sql"
	"errors"

	"github.com/uptrace/bun"
)

// DeleteCounts is the number of rows a delete removed from each table, or, for
// a dry run, would remove. A table the delete did not touch is absent.
type DeleteCounts map[string]int64

// Total is the sum over every table.
func (c DeleteCounts) Total() int64 {
	var n int64
	for _, v := range c {
		n += v
	}
	return n
}

type deleteCountsKey struct{}

// noteDeleted adds res's affected rows to table in the DeleteCounts carried
// by ctx, if any. The shared delete helpers call it on every statement, so a
// caller that wants per-table counts only has to put a map on the context.
func noteDeleted(ctx context.Context, table string, res sql.Result) {
	counts, _ := ctx.Value(deleteCountsKey{}).(DeleteCounts)
	if counts == nil || res == nil {
		return
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		counts[table] += n
	}
}

// errDryRunRollback rolls a counted dry-run transaction back.
var errDryRunRollback = errors.New("dry run: rolled back")

// countedTx runs fn in one transaction that records its deletes in counts.
// With dryRun the transaction is rolled back after fn, so the counts are the
// exact rows a real run would delete and nothing is deleted.
func (db *DeleteBuilder) countedTx(ctx context.Context, counts DeleteCounts, dryRun bool, fn func(context.Context, bun.Tx) error) error {
	ctx = context.WithValue(ctx, deleteCountsKey{}, counts)
	err := db.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		if err := fn(ctx, tx); err != nil {
			return err
		}
		if dryRun {
			return errDryRunRollback
		}
		return nil
	})
	if errors.Is(err, errDryRunRollback) {
		return nil
	}
	return err
}
