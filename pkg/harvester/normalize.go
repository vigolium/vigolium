package harvester

import (
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg/pathshape"
	"github.com/vigolium/vigolium/pkg/utils"
)

// dropReason says why normalizeURL rejected a harvested URL. The empty value
// means the URL was kept.
type dropReason string

const (
	dropNone    dropReason = ""
	dropInvalid dropReason = "invalid"
	dropStatic  dropReason = "static"
)

// archiveExtensions are download archives. A harvested archive URL is KEPT:
// a leftover backup.zip or site.tar.gz the archive saw is worth an existence
// check, and the harvest probe stores whatever still answers. Dynamic
// assessment skips them (they are media paths to the executor), so they cost
// one request and carry no payloads.
var archiveExtensions = map[string]bool{
	"zip": true, "gz": true, "tgz": true, "tar": true, "rar": true, "7z": true, "bz2": true,
}

// IsArchivePath reports whether a URL path names a download archive.
func IsArchivePath(path string) bool {
	return archiveExtensions[utils.GetExtensionOfPath(path)]
}

// isStaticPath reports whether a URL path names a static asset (archives are
// not static here; see archiveExtensions).
func isStaticPath(path string) bool {
	return junkExtensions[utils.GetExtensionOfPath(path)]
}

// trackingParams are query keys that only carry campaign or click attribution.
// They never select server behaviour, and every distinct value would otherwise
// make a new "unique" URL. Prefix entries end in "_" (utm_source, mc_cid, …).
var trackingParams = map[string]bool{
	"fbclid": true, "gclid": true, "dclid": true, "msclkid": true,
	"_ga": true, "_gl": true, "igshid": true,
}

var trackingParamPrefixes = []string{"utm_", "mc_"}

func isTrackingParam(name string) bool {
	name = strings.ToLower(name)
	if trackingParams[name] {
		return true
	}
	for _, p := range trackingParamPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// normalizeURL canonicalises one harvested URL so equivalent spellings dedup to
// one entry: lowercase scheme and host, default port dropped, fragment dropped,
// tracking parameters removed and the remaining query pairs stably sorted by
// key (values keep their original encoding and relative order). An empty path
// becomes "/".
//
// It rejects anything that is not an absolute http(s) URL (dropInvalid) and
// static assets by extension (dropStatic, isStaticPath; JavaScript and source
// maps are kept because jstangle reads them, archives for an existence check).
func normalizeURL(raw string) (*url.URL, dropReason) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, dropInvalid
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, dropInvalid
	}

	u.Scheme = strings.ToLower(u.Scheme)
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, dropInvalid
	}

	host, port := strings.ToLower(u.Hostname()), u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	switch {
	case port != "":
		u.Host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"): // IPv6 literal
		u.Host = "[" + host + "]"
	default:
		u.Host = host
	}

	u.Fragment, u.RawFragment = "", ""
	if u.Path == "" {
		u.Path, u.RawPath = "/", ""
	}
	if isStaticPath(u.Path) {
		return nil, dropStatic
	}

	u.RawQuery = canonicalQuery(u.RawQuery)
	u.ForceQuery = false
	return u, dropNone
}

// canonicalQuery drops tracking parameters and empty pairs from a raw query and
// stably sorts what remains by (decoded) key. It works on the raw pairs rather
// than url.Values so a value's original encoding survives the round trip.
func canonicalQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	type pair struct{ key, raw string }
	var pairs []pair
	for _, piece := range strings.Split(rawQuery, "&") {
		if piece == "" {
			continue
		}
		key := queryKey(piece)
		if isTrackingParam(key) {
			continue
		}
		pairs = append(pairs, pair{key, piece})
	}
	slices.SortStableFunc(pairs, func(a, b pair) int { return strings.Compare(a.key, b.key) })

	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.raw
	}
	return strings.Join(out, "&")
}

// queryKey returns the decoded key of one raw "k=v" query pair, or the raw key
// when it does not decode.
func queryKey(piece string) string {
	key, _, _ := strings.Cut(piece, "=")
	if dec, err := url.QueryUnescape(key); err == nil {
		return dec
	}
	return key
}

// shapeKey groups URLs that hit the same endpoint with different record values:
// host (with any non-default port) + pathshape template + the sorted, unique
// query parameter names. The scheme is left out on purpose — the http and https
// copies of an archived path are the same endpoint.
func shapeKey(u *url.URL) string {
	template, _ := pathshape.Shape(u.Path)

	var names []string
	if u.RawQuery != "" {
		for _, piece := range strings.Split(u.RawQuery, "&") {
			names = append(names, queryKey(piece))
		}
		slices.Sort(names)
		names = slices.Compact(names)
	}

	var b strings.Builder
	b.WriteString(u.Host)
	b.WriteString(template)
	if len(names) > 0 {
		b.WriteByte('?')
		b.WriteString(strings.Join(names, "&"))
	}
	return b.String()
}
