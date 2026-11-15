package database

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/uptrace/bun"
)

// HostFilter is a parsed --host value. Every read that takes --host accepts
// the forms a row prints: a bare hostname or IP, host:port, an origin
// (scheme://host[:port][/path]) and a bracketed IPv6 address with or without
// a port. A * in the host makes it a glob.
type HostFilter struct {
	Host string
	// Port is 0 when the value named none. An origin without a port names
	// its scheme's default port, because that is the port the stored row has.
	Port int
	// Scheme is set only by an origin.
	Scheme string
}

// Glob reports whether Host is a * pattern.
func (h HostFilter) Glob() bool { return strings.Contains(h.Host, "*") }

// ParseHostFilter parses a --host value; the zero HostFilter means no filter.
func ParseHostFilter(raw string) HostFilter {
	s := strings.TrimSpace(raw)
	if s == "" {
		return HostFilter{}
	}
	if i := strings.Index(s, "://"); i > 0 {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			f := HostFilter{Host: u.Hostname(), Scheme: strings.ToLower(u.Scheme)}
			if p, err := strconv.Atoi(u.Port()); err == nil {
				f.Port = p
			} else {
				switch f.Scheme {
				case "http", "ws":
					f.Port = 80
				case "https", "wss":
					f.Port = 443
				}
			}
			return f
		}
	}
	// A bare IPv6 address has several colons and no brackets: all host.
	if !strings.HasPrefix(s, "[") && strings.Count(s, ":") > 1 {
		return HostFilter{Host: s}
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		if p, perr := strconv.Atoi(port); perr == nil {
			return HostFilter{Host: host, Port: p}
		}
	}
	return HostFilter{Host: strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")}
}

// predicate renders the filter over the given hostname, port and scheme
// columns (an empty column name skips that part).
func (h HostFilter) predicate(hostCol, portCol, schemeCol string) (string, []any) {
	var parts []string
	var args []any
	if h.Glob() {
		parts = append(parts, WithLikeEscape(hostCol+" LIKE ?"))
		args = append(args, LikeGlob(h.Host))
	} else {
		parts = append(parts, hostCol+" = ?")
		args = append(args, h.Host)
	}
	if h.Port != 0 && portCol != "" {
		parts = append(parts, portCol+" = ?")
		args = append(args, h.Port)
	}
	if h.Scheme != "" && schemeCol != "" {
		parts = append(parts, schemeCol+" = ?")
		args = append(args, h.Scheme)
	}
	return strings.Join(parts, " AND "), args
}

// recordHostPredicate is the --host predicate over an http_records alias, or
// "" when raw names no host.
func recordHostPredicate(raw, alias string) (string, []any) {
	h := ParseHostFilter(raw)
	if h.Host == "" {
		return "", nil
	}
	return h.predicate(alias+".hostname", alias+".port", alias+".scheme")
}

// applyRecordHostFilter adds the --host predicate over an http_records alias.
func applyRecordHostFilter(q *bun.SelectQuery, raw, alias string) {
	if pred, args := recordHostPredicate(raw, alias); pred != "" {
		q.Where(pred, args...)
	}
}
