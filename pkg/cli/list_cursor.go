package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/database"
)

// List cursors: `finding -j` and `traffic -j` say when a page stops short of
// the rows that match (truncated) and hand back an opaque next_cursor that
// `--cursor` resumes from. The cursor is a keyset position (database.Keyset):
// the sort value and unique id of the page's last row, so rows a running scan
// writes ahead of it, and rows the dedup pass merges behind it, do not move the
// next page the way they move an --offset.
//
// The cursor names the order it was issued for (sort column and direction);
// one presented under another order is refused as a usage error. The filters
// are the caller's to repeat: a cursor resumes a position, not a query.

const (
	listTruncatedKey  = "truncated"
	listNextCursorKey = "next_cursor"
	// listCursorVersion is the cursor encoding's own version.
	listCursorVersion = 1
)

// The --cursor values of `finding` and `traffic`.
var (
	findingCursor string
	trafficCursor string
)

// registerListCursorFlag adds --cursor to a keyset-paged list read.
func registerListCursorFlag(flags *pflag.FlagSet, target *string) {
	flags.StringVar(target, "cursor", "",
		"Resume a -j listing after the page that returned this next_cursor (stable while a scan writes; repeat the same filters, --sort and --asc; not with --offset)")
}

// listCursor is the decoded cursor. Value is exactly one of S (text and time
// sort columns, as stored) and N (numeric ones); the tie is exactly one of TI
// (finding id) and TS (record uuid).
type listCursor struct {
	V     int     `json:"v"`
	List  string  `json:"l"`
	Order string  `json:"o"`
	S     *string `json:"s,omitempty"`
	N     *int64  `json:"n,omitempty"`
	TI    *int64  `json:"ti,omitempty"`
	TS    *string `json:"ts,omitempty"`
}

// orderTag is a short, stable name for a keyset order.
func orderTag(order string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(order))
	return fmt.Sprintf("%08x", h.Sum32())
}

// encodeListCursor renders the cursor for position k of list under order.
func encodeListCursor(list, order string, k *database.Keyset) string {
	if k == nil {
		return ""
	}
	c := listCursor{V: listCursorVersion, List: list, Order: orderTag(order)}
	switch v := k.Value.(type) {
	case int64:
		c.N = &v
	case string:
		c.S = &v
	default:
		return ""
	}
	switch t := k.Tie.(type) {
	case int64:
		c.TI = &t
	case string:
		c.TS = &t
	default:
		return ""
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// decodeListCursor parses a --cursor for list under order. An empty value is
// no cursor.
func decodeListCursor(raw, list, order string) (*database.Keyset, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	bad := func(why string) error {
		return usageErrorf("--cursor: %s; pass the next_cursor a %s -j page returned, with the same --sort and --asc", why, list)
	}
	body, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, bad("not a cursor")
	}
	var c listCursor
	if err := json.Unmarshal(body, &c); err != nil || c.V != listCursorVersion {
		return nil, bad("not a cursor")
	}
	if c.List != list {
		return nil, bad("issued by `" + c.List + "`, not `" + list + "`")
	}
	if c.Order != orderTag(order) {
		return nil, bad("issued for a different --sort/--asc")
	}
	k := &database.Keyset{}
	switch {
	case c.N != nil && c.S == nil:
		k.Value = *c.N
	case c.S != nil && c.N == nil:
		k.Value = *c.S
	default:
		return nil, bad("not a cursor")
	}
	switch {
	case c.TI != nil && c.TS == nil:
		k.Tie = *c.TI
	case c.TS != nil && c.TI == nil && strings.TrimSpace(*c.TS) != "":
		k.Tie = *c.TS
	default:
		return nil, bad("not a cursor")
	}
	return k, nil
}

// validateListCursorFlags refuses --cursor with --offset: the cursor is the
// position, and an offset on top of it would skip rows from it.
func validateListCursorFlags(cursor string, offset int) error {
	if strings.TrimSpace(cursor) != "" && offset > 0 {
		return usageErrorf("--cursor and --offset are exclusive: the cursor already names where the page starts")
	}
	return nil
}

// listPage is what a keyset-paged read states about its page: whether rows
// remain after it, the cursor after its last row, and how to issue the cursor
// after its first k emitted rows when the output budget cuts the page.
type listPage struct {
	more bool
	// next resumes after the page's last row read; "" when no rows remain or
	// no cursor can be issued.
	next string
	// after returns the cursor that resumes after the first k emitted rows,
	// "" when none can be issued; nil for a read that cannot issue cursors (a
	// merged Burp bridge page).
	after func(k int) string
}

// cursorAfterRows builds listPage.after over a page of rows: the cursor after
// the first k rows is the keyset of row k-1, read back from the store, or of
// the nearest earlier row still stored. Memoised, since the output budget asks
// for several k while it searches.
func cursorAfterRows[T any](ctx context.Context, rows []T, list, order string, at func(context.Context, T) (*database.Keyset, bool, error)) func(k int) string {
	memo := map[int]string{}
	return func(k int) string {
		if c, ok := memo[k]; ok {
			return c
		}
		c := ""
		for i := min(k, len(rows)) - 1; i >= 0; i-- {
			pos, ok, err := at(ctx, rows[i])
			if err != nil {
				break
			}
			if ok {
				c = encodeListCursor(list, order, pos)
				break
			}
		}
		memo[k] = c
		return c
	}
}

// pageEnvOpts states the page on the envelope: truncated always, next_cursor
// when rows remain and a cursor can be issued, and the hook the output budget
// uses to re-issue it at its cut.
func pageEnvOpts(page listPage) envOpt {
	return func(env *agentEnvelope) {
		env.With(listTruncatedKey, page.more)
		if page.more && page.next != "" {
			env.With(listNextCursorKey, page.next)
		}
		env.cursorAfter = page.after
	}
}

// pageTrafficRecords is queryTrafficRecords for the `traffic` listing: a
// keyset page of the store, resumed from --cursor. A listing merged with live
// Burp history (--burp-bridge-url) pages both sources by offset and issues no
// cursor; there truncated is read off the offset and the total.
//
// cursorOver builds listPage.after over the rows the listing finally emits
// (after --exclude-not-found), so the output budget's cut indexes them; nil
// when no cursor can be issued.
func pageTrafficRecords(ctx context.Context, db *database.DB, filters database.QueryFilters, includeRaw bool, bridgeURL string) (records []*database.HTTPRecord, total int64, page listPage, cursorOver func([]*database.HTTPRecord) func(int) string, err error) {
	if bridgeURL != "" && burpbridge.Eligible(filters) {
		if strings.TrimSpace(trafficCursor) != "" {
			return nil, 0, listPage{}, nil, usageErrorf("--cursor pages the stored records only; it cannot be combined with --burp-bridge-url")
		}
		records, total, err = queryTrafficRecords(ctx, db, filters, includeRaw, bridgeURL)
		if err != nil {
			return nil, 0, listPage{}, nil, err
		}
		more := filters.Limit > 0 && int64(filters.Offset+len(records)) < total
		return records, total, listPage{more: more}, nil, nil
	}
	qb := recordsQuery(db, filters, includeRaw)
	order := qb.KeysetOrder()
	after, err := decodeListCursor(trafficCursor, "traffic", order)
	if err != nil {
		return nil, 0, listPage{}, nil, err
	}
	records, total, more, err := qb.ExecutePage(ctx, after)
	if err != nil {
		return nil, 0, listPage{}, nil, err
	}
	page = listPage{more: more}
	cursorOver = func(rows []*database.HTTPRecord) func(int) string {
		return cursorAfterRows(ctx, rows, "traffic", order, qb.KeysetAt)
	}
	if more && globalJSON {
		page.next = cursorOver(records)(len(records))
	}
	return records, total, page, cursorOver, nil
}
