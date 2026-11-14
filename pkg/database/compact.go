package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/pathglob"
	"go.uber.org/zap"
)

// Body compaction: bounding a traffic store's size without deleting a record.
//
// A crawl stores every exchange whole, and a store that accumulates many runs
// ends up dominated by a minority of large bodies — bundles, images, archives.
// Measured on one merged store: 8,111 records, 1,282 bodies over 64 KiB holding
// 927 MB of a 1 GB file. Deleting those records would also delete the URL,
// status, headers and timing every later query of the store relies on, so
// compaction keeps the record and replaces only the large body with its head.
//
// What a compacted record keeps:
//
//   - every column except raw_request / raw_response, unchanged — url, status,
//     content type, response_content_length, response_hash, content_hash and
//     timing all still describe the ORIGINAL exchange;
//   - the stored header block, byte for byte, and the first KeepHead bytes of
//     the body;
//   - in body_compaction, the original body length and its SHA-256, so a reader
//     can tell a compacted body from a short one and can still check identity.
//
// A part that is already compacted is never compacted again: its recorded hash
// is the hash of the ORIGINAL body, and recomputing it over the head would
// silently replace that fact with a weaker one. Repeating a pass is therefore a
// no-op, which is what lets a caller run it on every cadence.

// bodyCompactionVersion is the shape version written into body_compaction.
const bodyCompactionVersion = 1

// compactMetaPage is how many candidate rows one metadata read returns. Only
// small columns are read at this stage; the blobs are loaded one row at a time.
const compactMetaPage = 256

// compactCommitEvery is how many compacted rows share one transaction.
const compactCommitEvery = 32

// BodyCompaction is the marker stored in http_records.body_compaction.
type BodyCompaction struct {
	Version int `json:"version"`
	// CompactedAt is when the most recent part was compacted.
	CompactedAt time.Time `json:"compacted_at"`
	// KeepHead is the head size of the most recent pass that compacted a part.
	KeepHead int64 `json:"keep_head"`
	// Response and Request are present only for the parts that were compacted.
	Response *CompactedBody `json:"response,omitempty"`
	Request  *CompactedBody `json:"request,omitempty"`
}

// CompactedBody describes one replaced body.
type CompactedBody struct {
	// OriginalLength is the body's length in bytes before compaction, headers
	// excluded.
	OriginalLength int64 `json:"original_length"`
	// SHA256 is the lowercase hex SHA-256 of the original body bytes.
	SHA256 string `json:"sha256"`
	// KeptLength is how many body bytes the stored message still holds.
	KeptLength int64 `json:"kept_length"`
}

// CompactOptions selects which bodies a compaction pass replaces.
type CompactOptions struct {
	// ProjectUUID confines the pass to one project; empty means every project
	// in the file.
	ProjectUUID string
	// BodyOver is the body size, in bytes, above which a body is compacted.
	BodyOver int64
	// KeepHead is how many body bytes a compacted body keeps. Must be less than
	// BodyOver.
	KeepHead int64
	// SkipContentTypes / OnlyContentTypes are globs over the response media
	// type; SkipPaths / OnlyPaths are globs over the URL path. See
	// compactFilter for how they combine.
	SkipContentTypes []string
	OnlyContentTypes []string
	SkipPaths        []string
	OnlyPaths        []string
	// OlderThan, when set, restricts the pass to records sent strictly before it.
	OlderThan *time.Time
	// MaxDBSize, when positive, turns the pass into a budget: records are
	// compacted oldest first until the estimated size after VACUUM is at most
	// this many bytes, and the pass stops there.
	MaxDBSize int64
	// DryRun counts what the pass would do and changes nothing.
	DryRun bool
	// Vacuum runs VACUUM (and a WAL checkpoint) after a pass that changed rows,
	// so the freed pages are returned to the filesystem.
	Vacuum bool
	// Now stamps compacted_at; nil means time.Now.
	Now func() time.Time
}

// CompactSummary reports what a pass did. It is the `items` payload of
// `vigolium db compact -j`.
type CompactSummary struct {
	DryRun bool `json:"dry_run"`
	// RecordsCompacted counts records with at least one body replaced (or, on a
	// dry run, that would be).
	RecordsCompacted        int64 `json:"records_compacted"`
	ResponseBodiesCompacted int64 `json:"response_bodies_compacted"`
	RequestBodiesCompacted  int64 `json:"request_bodies_compacted"`
	// BodyBytesBefore / BodyBytesAfter sum the compacted bodies' lengths before
	// and after.
	BodyBytesBefore int64 `json:"body_bytes_before"`
	BodyBytesAfter  int64 `json:"body_bytes_after"`
	// DBBytesBefore / DBBytesAfter are the database file plus its WAL. On a dry
	// run DBBytesAfter is the estimated size after compaction and VACUUM.
	DBBytesBefore int64 `json:"db_bytes_before"`
	DBBytesAfter  int64 `json:"db_bytes_after"`
	// MaxDBSize echoes the budget; 0 means none was set.
	MaxDBSize int64 `json:"max_db_size"`
	// BudgetMet is true when no budget was set, or when the database ends at or
	// under it. False means every selected body was compacted and the file is
	// still over budget.
	BudgetMet bool `json:"budget_met"`
	// Remaining counts selected records that still hold a body over BodyOver
	// after this pass — non-zero when a budget stopped the pass early.
	Remaining int64 `json:"remaining"`
	Vacuumed  bool  `json:"vacuumed"`
}

// ErrCompactUnsupported reports a database driver compaction does not handle.
var ErrCompactUnsupported = errors.New("db compact is only supported for SQLite")

// Validate checks the option combination.
func (o *CompactOptions) Validate() error {
	if o.BodyOver <= 0 {
		return fmt.Errorf("body-over must be positive")
	}
	if o.KeepHead < 0 {
		return fmt.Errorf("keep-head must not be negative")
	}
	if o.KeepHead >= o.BodyOver {
		return fmt.Errorf("keep-head (%d) must be smaller than body-over (%d)", o.KeepHead, o.BodyOver)
	}
	if o.MaxDBSize < 0 {
		return fmt.Errorf("max-db-size must not be negative")
	}
	for _, globs := range [][]string{o.SkipContentTypes, o.OnlyContentTypes, o.SkipPaths, o.OnlyPaths} {
		for _, g := range globs {
			if strings.TrimSpace(g) == "" {
				return fmt.Errorf("empty glob in a content-type or path filter")
			}
		}
	}
	return nil
}

// compactCandidate is one row's metadata, read without its blobs.
type compactCandidate struct {
	UUID           string
	SentAt         string
	Path           string
	ContentType    string
	RequestLength  int64
	ResponseLength int64
	Marker         *BodyCompaction
}

// CompactBodies runs one compaction pass. See the package comment above.
func (db *DB) CompactBodies(ctx context.Context, opts CompactOptions) (*CompactSummary, error) {
	if db.driver != driverSQLite {
		return nil, ErrCompactUnsupported
	}
	if !db.writable() {
		return nil, fmt.Errorf("db compact needs a writable database")
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	filter := newCompactFilter(opts)

	sum := &CompactSummary{DryRun: opts.DryRun, MaxDBSize: opts.MaxDBSize, BudgetMet: true}
	sum.DBBytesBefore = db.fileBytes()

	c := &compactor{db: db, opts: opts, filter: filter, sum: sum, stamp: now().UTC()}
	if err := c.run(ctx); err != nil {
		return sum, err
	}
	return sum, nil
}

// compactor carries one pass's state.
type compactor struct {
	db     *DB
	opts   CompactOptions
	filter *compactFilter
	sum    *CompactSummary
	stamp  time.Time

	// cursor is the (sent_at, uuid) of the last candidate read, for keyset
	// paging. Compaction rewrites rows the metadata query may match again, so
	// offset paging would skip or repeat rows.
	cursorSent string
	cursorUUID string
	exhausted  bool

	// base is the live size (see liveBytes) last measured, and saved the body
	// bytes freed since. A budget is judged against base - saved after every
	// row, so a pass stops within one row of the budget rather than within one
	// transaction; base is re-measured after each commit, which corrects the
	// estimate. A dry run never commits, so for it saved is the running total.
	base, saved int64
}

func (c *compactor) run(ctx context.Context) error {
	budget := c.opts.MaxDBSize
	for {
		if err := c.compactUntilBudget(ctx); err != nil {
			return err
		}
		if c.opts.DryRun {
			after := c.db.liveBytes(ctx) - c.saved
			if after < 0 {
				after = 0
			}
			c.sum.DBBytesAfter = after
			if budget > 0 {
				c.sum.BudgetMet = after <= budget
			}
			break
		}
		changed := c.sum.RecordsCompacted > 0
		// A store over budget with free pages (left by an earlier --no-vacuum
		// pass, or by deletes) is vacuumed even when this pass changed nothing;
		// one with no free pages is not, so a periodic pass over a store that
		// nothing selectable can shrink does not rebuild the file every time.
		overBudget := budget > 0 && c.db.fileBytes() > budget && c.db.freePages(ctx) > 0
		if c.opts.Vacuum && (changed || overBudget) {
			if err := c.db.vacuum(ctx); err != nil {
				return err
			}
			c.sum.Vacuumed = true
		}
		size := c.db.fileBytes()
		if !c.opts.Vacuum {
			// Without a VACUUM the file keeps its freed pages, so the budget is
			// judged against the size a VACUUM would leave.
			size = c.db.liveBytes(ctx)
		}
		c.sum.DBBytesAfter = c.db.fileBytes()
		if budget <= 0 {
			break
		}
		c.sum.BudgetMet = size <= budget
		// The live-page estimate that stopped the loop can be optimistic
		// (partially filled pages survive until VACUUM packs them), so a pass
		// that is still over budget resumes from its cursor. Each round consumes
		// candidates, so this ends when the budget holds or nothing is left.
		if c.sum.BudgetMet || c.exhausted || !c.opts.Vacuum {
			break
		}
	}
	return c.countRemaining(ctx)
}

// compactUntilBudget walks candidates oldest first, compacting each, until the
// budget (if any) is met or the candidates run out.
func (c *compactor) compactUntilBudget(ctx context.Context) error {
	budget := c.opts.MaxDBSize
	// measure must run with no transaction open: the size pragmas go through
	// the database handle, which a one-connection pool would block on.
	measure := func() {
		c.base, c.saved = c.db.liveBytes(ctx), 0
	}
	if budget > 0 {
		measure()
		if c.base <= budget {
			return nil
		}
	}

	var tx *sql.Tx
	pending := 0
	commit := func() error {
		if tx == nil {
			return nil
		}
		err := tx.Commit()
		tx, pending = nil, 0
		return err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	for !c.exhausted {
		page, err := c.nextPage(ctx, c.on(tx))
		if err != nil {
			return err
		}
		for _, cand := range page {
			if !c.filter.selects(cand) || !c.hasCompactablePart(cand) {
				continue
			}
			if !c.opts.DryRun && tx == nil {
				if tx, err = c.db.SQLDB().BeginTx(ctx, nil); err != nil {
					return fmt.Errorf("begin compaction transaction: %w", err)
				}
			}
			if err := c.compactRow(ctx, c.on(tx), cand); err != nil {
				return err
			}
			pending++
			if budget > 0 && c.base-c.saved <= budget {
				if c.opts.DryRun {
					c.rewind(cand)
					return nil
				}
				if err := commit(); err != nil {
					return fmt.Errorf("commit compaction: %w", err)
				}
				measure()
				if c.base <= budget {
					c.rewind(cand)
					return nil
				}
				continue
			}
			if !c.opts.DryRun && pending >= compactCommitEvery {
				if err := commit(); err != nil {
					return fmt.Errorf("commit compaction: %w", err)
				}
			}
		}
	}
	return commit()
}

// rewind moves the cursor back to cand, the last row this pass handled, when
// it stops part way through a page: the rest of that page is still ahead of the
// cursor, for a resumed round or for countRemaining.
func (c *compactor) rewind(cand compactCandidate) {
	c.cursorSent, c.cursorUUID = cand.SentAt, cand.UUID
	c.exhausted = false
}

// hasCompactablePart reports whether a row's metadata leaves room for a part
// over the threshold that is not yet compacted. The stored length includes the
// header block, so this over-selects; compactRow measures the body itself.
func (c *compactor) hasCompactablePart(cand compactCandidate) bool {
	respDone := cand.Marker != nil && cand.Marker.Response != nil
	reqDone := cand.Marker != nil && cand.Marker.Request != nil
	return (!respDone && cand.ResponseLength > c.opts.BodyOver) ||
		(!reqDone && cand.RequestLength > c.opts.BodyOver)
}

// queryer is the half of *sql.DB and *sql.Tx this pass uses. Every statement
// issued while a transaction is open goes through that transaction: a handle
// limited to one connection would otherwise wait on itself.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// on returns the open transaction, or the database when there is none.
func (c *compactor) on(tx *sql.Tx) queryer {
	if tx != nil {
		return tx
	}
	return c.db.SQLDB()
}

// nextPage reads the next page of candidate metadata after the cursor.
func (c *compactor) nextPage(ctx context.Context, q queryer) ([]compactCandidate, error) {
	where := []string{"(length(raw_response) > ? OR length(raw_request) > ?)"}
	args := []any{c.opts.BodyOver, c.opts.BodyOver}
	if c.opts.ProjectUUID != "" {
		where = append(where, "project_uuid = ?")
		args = append(args, c.opts.ProjectUUID)
	}
	if c.opts.OlderThan != nil {
		// The bound is formatted the way the store writes sent_at, so the
		// comparison is between two values of one format. See sentAtText.
		where = append(where, "sent_at < ?")
		args = append(args, sentAtText(*c.opts.OlderThan))
	}
	if c.cursorUUID != "" {
		where = append(where, "(CAST(sent_at AS TEXT), uuid) > (?, ?)")
		args = append(args, c.cursorSent, c.cursorUUID)
	}
	query := `SELECT uuid, CAST(sent_at AS TEXT), COALESCE(path, ''), COALESCE(response_content_type, ''),
	        COALESCE(length(raw_request), 0), COALESCE(length(raw_response), 0), body_compaction
	   FROM http_records
	  WHERE ` + strings.Join(where, " AND ") + `
	  ORDER BY CAST(sent_at AS TEXT) ASC, uuid ASC
	  LIMIT ?`
	args = append(args, compactMetaPage)

	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("read compaction candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var page []compactCandidate
	for rows.Next() {
		var cand compactCandidate
		var marker sql.NullString
		if err := rows.Scan(&cand.UUID, &cand.SentAt, &cand.Path, &cand.ContentType,
			&cand.RequestLength, &cand.ResponseLength, &marker); err != nil {
			return nil, fmt.Errorf("scan compaction candidate: %w", err)
		}
		if marker.Valid && marker.String != "" {
			var m BodyCompaction
			if err := json.Unmarshal([]byte(marker.String), &m); err != nil {
				// An unreadable marker is treated as "this row was compacted, by
				// a shape this binary cannot read": both parts are left alone,
				// because recompacting would overwrite whatever it recorded.
				zap.L().Warn("unreadable body_compaction marker; leaving the record as is",
					zap.String("uuid", cand.UUID), zap.Error(err))
				m = BodyCompaction{Response: &CompactedBody{}, Request: &CompactedBody{}}
			}
			cand.Marker = &m
		}
		page = append(page, cand)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(page) < compactMetaPage {
		c.exhausted = true
	}
	if n := len(page); n > 0 {
		c.cursorSent, c.cursorUUID = page[n-1].SentAt, page[n-1].UUID
	}
	return page, nil
}

// compactRow loads one row's blobs, compacts the parts over the threshold, and
// writes the result (or, on a dry run, only counts it).
func (c *compactor) compactRow(ctx context.Context, q queryer, cand compactCandidate) error {
	var rawReq, rawResp []byte
	if err := q.QueryRowContext(ctx,
		"SELECT raw_request, raw_response FROM http_records WHERE uuid = ?", cand.UUID,
	).Scan(&rawReq, &rawResp); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("load record %s: %w", cand.UUID, err)
	}

	marker := cand.Marker
	if marker == nil {
		marker = &BodyCompaction{}
	}
	changed := false
	var newReq, newResp []byte

	if marker.Response == nil {
		if out, part, ok := compactMessage(rawResp, c.opts.BodyOver, c.opts.KeepHead); ok {
			newResp, marker.Response = out, part
			c.sum.ResponseBodiesCompacted++
			c.account(part)
			changed = true
		}
	}
	if marker.Request == nil {
		if out, part, ok := compactMessage(rawReq, c.opts.BodyOver, c.opts.KeepHead); ok {
			newReq, marker.Request = out, part
			c.sum.RequestBodiesCompacted++
			c.account(part)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	c.sum.RecordsCompacted++
	if c.opts.DryRun {
		return nil
	}

	marker.Version = bodyCompactionVersion
	marker.CompactedAt = c.stamp
	marker.KeepHead = c.opts.KeepHead
	encoded, err := json.Marshal(marker)
	if err != nil {
		return fmt.Errorf("encode body_compaction for %s: %w", cand.UUID, err)
	}

	set := []string{"body_compaction = ?"}
	args := []any{string(encoded)}
	if newResp != nil {
		set = append(set, "raw_response = ?")
		args = append(args, newResp)
	}
	if newReq != nil {
		set = append(set, "raw_request = ?")
		args = append(args, newReq)
	}
	args = append(args, cand.UUID)
	if _, err := q.ExecContext(ctx,
		"UPDATE http_records SET "+strings.Join(set, ", ")+" WHERE uuid = ?", args...); err != nil {
		return fmt.Errorf("compact record %s: %w", cand.UUID, err)
	}
	return nil
}

// account adds one compacted part to the byte totals.
func (c *compactor) account(part *CompactedBody) {
	c.sum.BodyBytesBefore += part.OriginalLength
	c.sum.BodyBytesAfter += part.KeptLength
	c.saved += part.OriginalLength - part.KeptLength
}

// countRemaining counts the selected records past the cursor that still hold an
// uncompacted part over the threshold — what a budget left behind.
func (c *compactor) countRemaining(ctx context.Context) error {
	for !c.exhausted {
		page, err := c.nextPage(ctx, c.db.SQLDB())
		if err != nil {
			return err
		}
		for _, cand := range page {
			if c.filter.selects(cand) && c.hasCompactablePart(cand) {
				c.sum.Remaining++
			}
		}
	}
	return nil
}

// compactMessage replaces the body of one raw HTTP message with its first
// keepHead bytes when the body is longer than bodyOver. The header block, up to
// and including the blank line that ends it, is kept byte for byte. A message
// with no header/body separator is not an HTTP message this can split, and is
// left alone.
func compactMessage(raw []byte, bodyOver, keepHead int64) ([]byte, *CompactedBody, bool) {
	if int64(len(raw)) <= bodyOver {
		return nil, nil, false
	}
	start := httpmsg.FindHeaderBodySeparator(raw, 0)
	if start < 0 {
		return nil, nil, false
	}
	body := raw[start:]
	if int64(len(body)) <= bodyOver {
		return nil, nil, false
	}
	digest := sha256.Sum256(body)
	out := make([]byte, 0, int64(start)+keepHead)
	out = append(out, raw[:start]...)
	out = append(out, body[:keepHead]...)
	return out, &CompactedBody{
		OriginalLength: int64(len(body)),
		SHA256:         hex.EncodeToString(digest[:]),
		KeptLength:     keepHead,
	}, true
}

// sentAtText formats t the way bun's SQLite dialect writes a timestamp, so a
// bound compares against stored sent_at values as text of the same shape.
func sentAtText(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05.999999-07:00")
}

// fileBytes is the database file plus its WAL, or 0 when there is no file.
func (db *DB) fileBytes() int64 {
	path := db.Path()
	if path == "" {
		return 0
	}
	var total int64
	for _, p := range []string{path, path + "-wal"} {
		if st, err := os.Stat(p); err == nil {
			total += st.Size()
		}
	}
	return total
}

// liveBytes estimates the size VACUUM would leave: the pages in use, without
// the free list. Partially filled pages are counted whole, so the real result
// is at most this.
func (db *DB) liveBytes(ctx context.Context) int64 {
	var pageCount, freelist, pageSize int64
	if err := db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
		return db.fileBytes()
	}
	if err := db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freelist); err != nil {
		return db.fileBytes()
	}
	if err := db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return db.fileBytes()
	}
	return (pageCount - freelist) * pageSize
}

// freePages is the number of pages on the free list, or 0 when unreadable.
func (db *DB) freePages(ctx context.Context) int64 {
	var n int64
	if err := db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&n); err != nil {
		return 0
	}
	return n
}

// vacuum rebuilds the file and folds the WAL back into it, so the reported size
// is the size on disk rather than the size of the main file alone.
func (db *DB) vacuum(ctx context.Context) error {
	if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		zap.L().Debug("wal checkpoint after vacuum failed", zap.Error(err))
	}
	return nil
}

// compactFilter decides, from metadata alone, whether a record is in scope.
//
// A record is selected when it matches no skip glob and, if any only glob is
// given, at least one only glob (content type OR path). Skip wins over only, so
// a caller protecting a class of bodies cannot have the protection undone by a
// broad only list.
// compactFilter selects candidates by content-type and path globs
// (pathglob: "*" crosses "/", so `*.js` matches a script at any depth),
// case-insensitively.
type compactFilter struct {
	skipType, onlyType, skipPath, onlyPath []string
}

func newCompactFilter(o CompactOptions) *compactFilter {
	return &compactFilter{
		skipType: lowerGlobs(o.SkipContentTypes),
		onlyType: lowerGlobs(o.OnlyContentTypes),
		skipPath: lowerGlobs(o.SkipPaths),
		onlyPath: lowerGlobs(o.OnlyPaths),
	}
}

// lowerGlobs trims and lowercases globs; the subjects they match are
// lowercased too (compactMediaType, compactPath).
func lowerGlobs(globs []string) []string {
	out := make([]string, 0, len(globs))
	for _, g := range globs {
		out = append(out, strings.ToLower(strings.TrimSpace(g)))
	}
	return out
}

func (f *compactFilter) selects(cand compactCandidate) bool {
	ct := compactMediaType(cand.ContentType)
	path := compactPath(cand.Path)
	if anyMatch(f.skipType, ct) || anyMatch(f.skipPath, path) {
		return false
	}
	if len(f.onlyType) == 0 && len(f.onlyPath) == 0 {
		return true
	}
	return anyMatch(f.onlyType, ct) || anyMatch(f.onlyPath, path)
}

// compactMediaType lowercases a Content-Type and drops its parameters.
func compactMediaType(ct string) string {
	ct, _, _ = strings.Cut(ct, ";")
	return strings.ToLower(strings.TrimSpace(ct))
}

// compactPath lowercases a URL path and drops any query or fragment.
func compactPath(p string) string {
	p, _, _ = strings.Cut(p, "?")
	p, _, _ = strings.Cut(p, "#")
	return strings.ToLower(p)
}

func anyMatch(globs []string, s string) bool {
	for _, g := range globs {
		if pathglob.Match(g, s) {
			return true
		}
	}
	return false
}
