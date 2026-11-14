package redact

import (
	"strings"
)

// HTTPMessage redacts a raw HTTP request or response dump for a shareable
// artifact (SAFE-12): the value of every credential header (HeaderNames, any
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
	if _, ok := HeaderNames[lname]; ok {
		return true
	}
	if _, ok := extra[lname]; ok {
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
