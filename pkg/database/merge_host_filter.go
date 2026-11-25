package database

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// mergeHostFilter is MergeOptions.Hosts parsed: a row about a host crosses
// when ANY entry matches it. The zero value (no entries) is no filter.
//
// Each entry is parsed by ParseHostFilter, so a merge accepts the same --host
// forms every other read does (bare host, host:port, origin, `*` glob). Host
// and scheme compare case-insensitively: DNS names are case-insensitive, and
// the patterns are lower-cased here and the columns LOWER()ed in SQL, so a row
// stored with mixed case still matches.
type mergeHostFilter []HostFilter

// parseMergeHosts parses MergeOptions.Hosts. An entry that names no host (an
// empty string, a bare "https://") is an error rather than a skipped entry: a
// caller that asked for a filter and received an unfiltered merge would copy
// every other host's traffic believing it had not.
func parseMergeHosts(patterns []string) (mergeHostFilter, error) {
	out := make(mergeHostFilter, 0, len(patterns))
	for _, p := range patterns {
		h := ParseHostFilter(p)
		if h.Host == "" {
			return nil, fmt.Errorf("host filter %q names no host", p)
		}
		h.Host = strings.ToLower(h.Host)
		out = append(out, h)
	}
	return out, nil
}

func (m mergeHostFilter) active() bool { return len(m) > 0 }

// sqlPredicate renders the filter over the given hostname, port and scheme
// columns (an empty column name skips that part of every entry). Every pattern
// is a bound parameter; only the column names, which are constants at the call
// sites, are interpolated.
func (m mergeHostFilter) sqlPredicate(hostCol, portCol, schemeCol string) (string, []any) {
	hostCol = "LOWER(" + hostCol + ")"
	if schemeCol != "" {
		schemeCol = "LOWER(" + schemeCol + ")"
	}
	ors := make([]string, 0, len(m))
	var args []any
	for _, h := range m {
		pred, a := h.predicate(hostCol, portCol, schemeCol)
		ors = append(ors, "("+pred+")")
		args = append(args, a...)
	}
	return strings.Join(ors, " OR "), args
}

// match reports whether a row about host (port and scheme when known; 0 and ""
// when not) matches any entry. An entry that names a port or scheme does not
// match a row whose port or scheme is unknown.
func (m mergeHostFilter) match(host string, port int, scheme string) bool {
	host = strings.ToLower(host)
	scheme = strings.ToLower(scheme)
	if host == "" {
		return false
	}
	for _, h := range m {
		if !globMatch(h.Host, host) {
			continue
		}
		if h.Port != 0 && h.Port != port {
			continue
		}
		if h.Scheme != "" && h.Scheme != scheme {
			continue
		}
		return true
	}
	return false
}

// matchURL reports whether a row addressed by rawURL matches. hostHint, when
// non-empty, is the row's own stored hostname and wins over the URL's: it is
// the column every hostname read keys on. Port and scheme come from the URL,
// the port defaulting to the scheme's.
func (m mergeHostFilter) matchURL(rawURL, hostHint string) bool {
	host, port, scheme := hostHint, 0, ""
	if u, err := url.Parse(strings.TrimSpace(rawURL)); err == nil {
		if host == "" {
			host = u.Hostname()
		}
		scheme = strings.ToLower(u.Scheme)
		if p, err := strconv.Atoi(u.Port()); err == nil {
			port = p
		} else if scheme != "" {
			port = httpmsg.GetDefaultPort(scheme)
		}
	}
	return m.match(host, port, scheme)
}

// globMatch matches s against a pattern whose only wildcard is `*` (any run of
// characters, dots included) — the Go twin of LikeGlob, for rows filtered after
// they are read. Both arguments are expected lower-cased.
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// targetURLKeyedTables are the set-based merge tables that carry no hostname
// column and name their host only inside target_url, mapped to the key a
// filtered copy selects them by.
var targetURLKeyedTables = map[string]string{
	"agentic_scans": "uuid",
	"oast_payloads": "nonce",
}

// readSourceFindings reads src.findings, narrowed to the filtered hosts when
// hosts is active. The hostname prefilter runs in SQL so a large source is not
// buffered whole only to be discarded; rows with no hostname pass it and are
// then decided by their url, as are the port and scheme parts of an entry.
func readSourceFindings(ctx context.Context, conn *sql.Conn, hosts mergeHostFilter) ([]bufferedRow, []string, error) {
	if !hosts.active() {
		return readRows(ctx, conn, "findings")
	}
	srcCols, err := tableColumns(ctx, conn, "src", "findings")
	if err != nil {
		return nil, nil, err
	}
	var where string
	var args []any
	if indexOf(srcCols, "hostname") >= 0 {
		var pred string
		pred, args = hosts.sqlPredicate("hostname", "", "")
		where = "(" + pred + ") OR hostname IS NULL OR hostname = ''"
	}
	rows, cols, err := readRowsWhere(ctx, conn, "findings", where, args)
	if err != nil {
		return nil, nil, err
	}
	hostIdx, urlIdx := indexOf(cols, "hostname"), indexOf(cols, "url")
	kept := rows[:0]
	for _, row := range rows {
		var host, rawURL string
		if hostIdx >= 0 {
			host = sqlText(row[hostIdx])
		}
		if urlIdx >= 0 {
			rawURL = sqlText(row[urlIdx])
		}
		if hosts.matchURL(rawURL, host) {
			kept = append(kept, row)
		}
	}
	return kept, cols, nil
}

// srcKeysByTargetHost returns the keyCol values of src.<table> rows whose
// target_url names a filtered host. A source without the table or either
// column yields none, so nothing from it crosses.
func srcKeysByTargetHost(ctx context.Context, conn *sql.Conn, table, keyCol string, hosts mergeHostFilter) ([]any, error) {
	cols, err := tableColumns(ctx, conn, "src", table)
	if err != nil {
		return nil, err
	}
	if indexOf(cols, keyCol) < 0 || indexOf(cols, "target_url") < 0 {
		return nil, nil
	}
	rows, err := conn.QueryContext(ctx, fmt.Sprintf("SELECT %s, target_url FROM src.%s", keyCol, table))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var keys []any
	for rows.Next() {
		var key, target sql.NullString
		if err := rows.Scan(&key, &target); err != nil {
			return nil, err
		}
		if key.Valid && hosts.matchURL(target.String, "") {
			keys = append(keys, key.String)
		}
	}
	return keys, rows.Err()
}

// sqlText reads a buffered TEXT value, which the driver may hand back as a
// string or as []byte.
func sqlText(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	default:
		return ""
	}
}

// copyTableWhere copies src.<table> into main.<table> set-based with OR IGNORE,
// narrowed by where (all rows when empty). table and cols come from the
// mergeCopyTables allowlist and the schemas' own column lists; the predicate's
// values are bound through args.
func copyTableWhere(ctx context.Context, tx *sql.Tx, table string, cols []string, where string, args []any) (int64, error) {
	colList := strings.Join(cols, ", ")
	q := fmt.Sprintf("INSERT OR IGNORE INTO main.%s (%s) SELECT %s FROM src.%s", table, colList, colList, table)
	if where != "" {
		q += " WHERE " + where
	}
	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// copyTableKeys copies the src.<table> rows whose keyCol is in keys, in chunks.
func copyTableKeys(ctx context.Context, tx *sql.Tx, table string, cols []string, keyCol string, keys []any) (int64, error) {
	var total int64
	for chunk := range slices.Chunk(keys, SQLChunkSize) {
		in := strings.TrimSuffix(strings.Repeat("?, ", len(chunk)), ", ")
		n, err := copyTableWhere(ctx, tx, table, cols, keyCol+" IN ("+in+")", chunk)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
