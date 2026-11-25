package parammine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"golang.org/x/net/http/httpguts"
)

// builder places parameter pairs into copies of the base request.
type builder struct {
	base *httpmsg.HttpRequestResponse
	loc  Location
	// existing holds the parameter names the base request already carries in
	// the chosen location; they are never mined.
	existing map[string]bool
	// jsonBody is the decoded base body for LocationJSON.
	jsonBody map[string]json.RawMessage
}

// ParseLocation validates a user-supplied location; "" and "auto" mean pick
// from the request.
func ParseLocation(s string) (Location, error) {
	switch Location(strings.ToLower(strings.TrimSpace(s))) {
	case "", "auto":
		return "", nil
	case LocationQuery, "url", "get":
		return LocationQuery, nil
	case LocationForm, "body", "post":
		return LocationForm, nil
	case LocationJSON:
		return LocationJSON, nil
	case LocationHeader, "headers":
		return LocationHeader, nil
	case LocationCookie, "cookies":
		return LocationCookie, nil
	}
	return "", fmt.Errorf("unknown parameter location %q (want query, form, json, header, cookie or auto)", s)
}

// DetectLocation picks where to put mined names for a request: the query
// string for bodiless methods and multipart bodies, the JSON object for a JSON
// body, the form body otherwise.
func DetectLocation(req *httpmsg.HttpRequest) Location {
	switch strings.ToUpper(req.Method()) {
	case "GET", "HEAD", "DELETE", "OPTIONS":
		return LocationQuery
	}
	ct := strings.ToLower(req.Header("Content-Type"))
	switch {
	case strings.Contains(ct, "json"):
		return LocationJSON
	case strings.Contains(ct, "multipart/"):
		return LocationQuery
	case ct == "" || strings.Contains(ct, "x-www-form-urlencoded"):
		return LocationForm
	}
	return LocationQuery
}

func newBuilder(base *httpmsg.HttpRequestResponse, loc Location) (*builder, error) {
	req := base.Request()
	if loc == "" {
		loc = DetectLocation(req)
	}
	b := &builder{base: base, loc: loc, existing: make(map[string]bool)}
	switch loc {
	case LocationQuery:
		if _, q, ok := strings.Cut(req.Path(), "?"); ok {
			if vals, err := url.ParseQuery(q); err == nil {
				for k := range vals {
					b.existing[k] = true
				}
			}
		}
	case LocationForm:
		if vals, err := url.ParseQuery(string(req.Body())); err == nil {
			for k := range vals {
				b.existing[k] = true
			}
		}
	case LocationHeader:
		// Header names are case-insensitive: compare them lowercased.
		for _, h := range req.Headers() {
			b.existing[strings.ToLower(h.Name)] = true
		}
	case LocationCookie:
		// Cookie names are case-sensitive (RFC 6265 §5.3): compared as sent.
		for _, c := range requestCookies(req) {
			b.existing[c.name] = true
		}
	case LocationJSON:
		b.jsonBody = map[string]json.RawMessage{}
		if body := bytes.TrimSpace(req.Body()); len(body) > 0 {
			if err := json.Unmarshal(body, &b.jsonBody); err != nil {
				return nil, fmt.Errorf("parammine: JSON location needs a JSON object body: %w", err)
			}
		}
		for k := range b.jsonBody {
			b.existing[k] = true
		}
	default:
		return nil, fmt.Errorf("parammine: unknown location %q", loc)
	}
	return b, nil
}

// filterExisting drops names the base request already sends and, for the
// header location, names that are not header tokens or that frame or route the
// request itself (ValidHeaderName); for the cookie location, names that are not
// cookie tokens (ValidCookieName).
func (b *builder) filterExisting(words []string) []string {
	out := make([]string, 0, len(words))
	seen := make(map[string]bool, len(words))
	for _, w := range words {
		key := w
		switch b.loc {
		case LocationHeader:
			if !ValidHeaderName(w) {
				continue
			}
			key = strings.ToLower(w)
		case LocationCookie:
			if !ValidCookieName(w) {
				continue
			}
		}
		if !b.existing[key] && !seen[key] {
			seen[key] = true
			out = append(out, w)
		}
	}
	return out
}

// unminableHeaders are the headers a mined value must never replace: they frame
// the message (Content-Length, Transfer-Encoding), select the host or the
// connection (Host, Connection, Upgrade, hop-by-hop fields) or carry the
// session (Cookie). Sending a random value in one breaks the request instead of
// testing whether the application reads the name. RFC 9110/9112 field names.
// Cookie names are mined under LocationCookie, inside the Cookie header, never
// by replacing it.
var unminableHeaders = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"keep-alive": true, "te": true, "trailer": true, "upgrade": true, "expect": true,
	"proxy-connection": true, "proxy-authorization": true, "cookie": true,
}

// ValidHeaderName reports whether s can be mined as a request header: an RFC
// 9110 token (tchar only), bounded, and not one of unminableHeaders.
func ValidHeaderName(s string) bool {
	return ValidCookieName(s) && !unminableHeaders[strings.ToLower(s)]
}

// ValidCookieName reports whether s can be mined as a cookie name: an RFC 6265
// cookie-name (an RFC 9110 token), bounded. Every built-in parameter name that
// is a token qualifies.
func ValidCookieName(s string) bool {
	return len(s) <= maxNameLen && httpguts.ValidHeaderFieldName(s)
}

// requestCookie is one name=value pair of a request's Cookie header.
type requestCookie struct{ name, value string }

// requestCookies reads every Cookie header of req (a client may send several)
// as its name=value pairs, in order, values untouched.
func requestCookies(req *httpmsg.HttpRequest) []requestCookie {
	var out []requestCookie
	for _, h := range req.Headers() {
		if !strings.EqualFold(h.Name, "Cookie") {
			continue
		}
		for _, part := range strings.Split(h.Value, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name, value, _ := strings.Cut(part, "=")
			out = append(out, requestCookie{strings.TrimSpace(name), value})
		}
	}
	return out
}

// cookieHeaderLen is the length of the Cookie header req sends today, every
// Cookie line joined as one.
func cookieHeaderLen(req *httpmsg.HttpRequest) int {
	n := 0
	for _, c := range requestCookies(req) {
		if n > 0 {
			n += 2 // "; "
		}
		n += len(c.name) + 1 + len(c.value)
	}
	return n
}

// withMergedCookies returns req with one Cookie header carrying every cookie it
// already sends, in order, then pairs. A session cookie stays exactly as it
// was; the mined names only ever join it.
func withMergedCookies(req *httpmsg.HttpRequest, pairs []pair) *httpmsg.HttpRequest {
	parts := make([]string, 0, len(pairs)+4)
	for _, c := range requestCookies(req) {
		parts = append(parts, c.name+"="+c.value)
	}
	for _, p := range pairs {
		parts = append(parts, p.name+"="+p.value)
	}
	for i := 0; i < 32 && req.HasHeader("Cookie"); i++ {
		req = req.WithRemovedHeader("Cookie")
	}
	return req.WithAddedHeader("Cookie", strings.Join(parts, "; "))
}

// build returns a copy of the base request carrying pairs.
func (b *builder) build(pairs []pair) (*httpmsg.HttpRequestResponse, error) {
	req := b.base.Request()
	switch b.loc {
	case LocationQuery:
		path := req.Path()
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
			if strings.HasSuffix(path, "?") || strings.HasSuffix(path, "&") {
				sep = ""
			}
		}
		req = req.WithPath(path + sep + encodePairs(pairs))
	case LocationForm:
		body := req.Body()
		var buf bytes.Buffer
		buf.Write(body)
		if len(body) > 0 && !bytes.HasSuffix(body, []byte("&")) {
			buf.WriteByte('&')
		}
		buf.WriteString(encodePairs(pairs))
		if req.Header("Content-Type") == "" {
			req = req.WithHeader("Content-Type", "application/x-www-form-urlencoded")
		}
		req = req.WithBody(buf.Bytes())
	case LocationJSON:
		obj := make(map[string]json.RawMessage, len(b.jsonBody)+len(pairs))
		for k, v := range b.jsonBody {
			obj[k] = v
		}
		for _, p := range pairs {
			v, _ := json.Marshal(p.value)
			obj[p.name] = v
		}
		body, err := json.Marshal(obj)
		if err != nil {
			return nil, err
		}
		if req.Header("Content-Type") == "" {
			req = req.WithHeader("Content-Type", "application/json")
		}
		req = req.WithBody(body)
	case LocationHeader:
		headers := make([][2]string, len(pairs))
		for i, p := range pairs {
			headers[i] = [2]string{p.name, p.value}
		}
		req = req.WithAddedHeaders(headers)
	case LocationCookie:
		req = withMergedCookies(req, pairs)
	}
	return httpmsg.NewHttpRequestResponse(req, nil), nil
}

func encodePairs(pairs []pair) string {
	var sb strings.Builder
	for i, p := range pairs {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(url.QueryEscape(p.name))
		sb.WriteByte('=')
		sb.WriteString(url.QueryEscape(p.value))
	}
	return sb.String()
}

// pairCost is how many bytes one name adds to a request in this location.
func (b *builder) pairCost(name string) int {
	switch b.loc {
	case LocationJSON:
		return len(name) + canaryLen + 6 // "name":"value",
	case LocationHeader:
		return len(name) + canaryLen + 4 // Name: value CRLF
	case LocationCookie:
		return len(name) + canaryLen + 3 // ; name=value
	default:
		return len(url.QueryEscape(name)) + canaryLen + 2 // &name=value
	}
}

// chunk splits names into groups that fit the location's transport budget and
// the per-chunk name cap. A name too long to fit even alone is dropped.
func (b *builder) chunk(names []string, cfg Config) [][]string {
	req := b.base.Request()
	limit, used := cfg.MaxBodyBytes, len(req.Body())
	maxNames := cfg.MaxNamesPerChunk
	switch b.loc {
	case LocationQuery:
		limit, used = cfg.MaxQueryBytes, len(req.Path())
	case LocationHeader:
		limit, used = cfg.MaxHeaderBytes, 0
		// The baseline adds one header of its own; leave room for it.
		maxNames = min(maxNames, DefaultMaxHeadersPerChunk-len(req.Headers())-1)
		if maxNames < 1 {
			maxNames = 1
		}
	case LocationCookie:
		// The chunk adds at most MaxHeaderBytes, and the whole Cookie header,
		// the request's own cookies and the baseline's one included, stays
		// within DefaultMaxCookieHeaderBytes.
		limit, used = min(cfg.MaxHeaderBytes, DefaultMaxCookieHeaderBytes-cookieHeaderLen(req)-b.pairCost(strings.Repeat("x", canaryLen))), 0
	}
	room := limit - used
	var out [][]string
	var cur []string
	size := 0
	for _, n := range names {
		c := b.pairCost(n)
		if c > room {
			continue
		}
		if len(cur) > 0 && (size+c > room || len(cur) >= maxNames) {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, n)
		size += c
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}
