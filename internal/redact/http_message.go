package redact

import (
	"strings"
)

// HeaderNameSet is the lowercased name set of "Name: value" header strings
// (the operator's -H headers), the extra set HTTPMessage takes.
func HeaderNameSet(headers []string) map[string]struct{} {
	out := make(map[string]struct{}, len(headers))
	for _, h := range headers {
		if name, _, ok := strings.Cut(h, ":"); ok {
			if n := strings.ToLower(strings.TrimSpace(name)); n != "" {
				out[n] = struct{}{}
			}
		}
	}
	return out
}

// HTTPMessage redacts a raw HTTP request or response dump for a shareable
// artifact: the value of every credential header (HeaderNames, any
// header IsSensitiveName flags, and extra — lowercased operator -H and
// live-session header names), every cookie value in Cookie / Set-Cookie
// (names and cookie attributes kept, so the exchange's shape survives), and
// every sensitive query parameter on the request line. The body is left
// as-is: it is the evidence. Line endings are preserved.
func HTTPMessage(raw string, extra map[string]struct{}) string {
	if raw == "" {
		return raw
	}
	headEnd := headerEnd(raw)
	head, rest := raw, ""
	if headEnd >= 0 {
		head, rest = raw[:headEnd], raw[headEnd:]
	}
	nl := "\n"
	if strings.Contains(head, "\r\n") {
		nl = "\r\n"
	}
	lines := strings.Split(head, nl)
	changed := false
	for i, line := range lines {
		if i == 0 {
			if red := redactStartLine(line); red != line {
				lines[i] = red
				changed = true
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		lname := strings.ToLower(strings.TrimSpace(name))
		var red string
		switch {
		case lname == "cookie":
			red = redactCookieHeader(value)
		case lname == "set-cookie":
			red = redactSetCookie(value)
		case isSensitiveHeader(lname, extra):
			red = " " + Placeholder
		default:
			continue
		}
		if red != value {
			lines[i] = name + ":" + red
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return strings.Join(lines, nl) + rest
}

// headerEnd is the index of the blank line ending the header block, or -1.
func headerEnd(raw string) int {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return i
	}
	return strings.Index(raw, "\n\n")
}

func isSensitiveHeader(lname string, extra map[string]struct{}) bool {
	if _, ok := extra[lname]; ok {
		return true
	}
	return IsSensitiveHeader(lname)
}

// IsSensitiveHeader reports whether a request or response header name carries
// a credential: an entry of HeaderNames, a name ending in a credential suffix
// (-key, -token, -secret, -session-id, -signature), or one IsSensitiveName
// flags. Shape headers that merely contain a keyword (Content-Type,
// Access-Control-Allow-Credentials) are never credentials. It is the one header
// classifier: log and artifact redaction, the anonymous requester view, the
// modules' credential strip and the redirect-hop forwarding rule all ask it.
func IsSensitiveHeader(name string) bool {
	lname := strings.ToLower(strings.TrimSpace(name))
	if lname == "" {
		return false
	}
	if _, ok := HeaderNames[lname]; ok {
		return true
	}
	switch lname {
	// Shape headers that merely contain a keyword are never secrets.
	case "content-type", "content-length", "accept", "accept-encoding", "accept-language",
		"access-control-allow-credentials", "access-control-allow-headers", "access-control-expose-headers",
		"access-control-allow-origin", "access-control-allow-methods":
		return false
	}
	for _, suffix := range []string{"-key", "-token", "-secret", "-session-id", "-signature"} {
		if strings.HasSuffix(lname, suffix) {
			return true
		}
	}
	return IsSensitiveName(lname)
}

// redactStartLine redacts sensitive query parameters on a request line
// ("METHOD target HTTP/x"); a status line is returned unchanged.
func redactStartLine(line string) string {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return line
	}
	target := parts[1]
	q := strings.IndexByte(target, '?')
	if q < 0 {
		return line
	}
	query, frag := target[q+1:], ""
	if h := strings.IndexByte(query, '#'); h >= 0 {
		query, frag = query[:h], query[h:]
	}
	red, ok := redactPairs(query)
	if !ok {
		return line
	}
	return parts[0] + " " + target[:q+1] + red + frag + " " + parts[2]
}

// redactCookieHeader keeps each cookie's name and replaces its value.
func redactCookieHeader(value string) string {
	parts := strings.Split(value, ";")
	for i, p := range parts {
		name, _, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		parts[i] = name + "=" + Placeholder
	}
	return strings.Join(parts, ";")
}

// redactSetCookie replaces the cookie's value and keeps its name and
// attributes (Path, Domain, HttpOnly, …).
func redactSetCookie(value string) string {
	first, attrs, hasAttrs := strings.Cut(value, ";")
	name, _, ok := strings.Cut(first, "=")
	if !ok {
		return value
	}
	out := name + "=" + Placeholder
	if hasAttrs {
		out += ";" + attrs
	}
	return out
}

// HeaderValue redacts one header's value the way HTTPMessage does inside a
// message: cookie values for Cookie / Set-Cookie (names and attributes kept),
// the whole value for a credential header, anything else unchanged.
func HeaderValue(name, value string, extra map[string]struct{}) string {
	lname := strings.ToLower(strings.TrimSpace(name))
	switch {
	case lname == "cookie":
		return redactCookieHeader(value)
	case lname == "set-cookie":
		return redactSetCookie(value)
	case isSensitiveHeader(lname, extra):
		return Placeholder
	}
	return value
}

// StartLine redacts sensitive query parameters on a request line; a status
// line comes back unchanged.
func StartLine(line string) string { return redactStartLine(line) }

// Header returns a copy of h with every value passed through HeaderValue; h
// itself is not modified. nil stays nil.
func Header(h map[string][]string, extra map[string]struct{}) map[string][]string {
	if h == nil {
		return nil
	}
	out := make(map[string][]string, len(h))
	for name, values := range h {
		red := make([]string, len(values))
		for i, v := range values {
			red[i] = HeaderValue(name, v, extra)
		}
		out[name] = red
	}
	return out
}
