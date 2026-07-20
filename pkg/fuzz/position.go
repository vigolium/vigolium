package fuzz

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// DefaultKeyword is the literal marker fuzz replaces when present in the raw
// request.
const DefaultKeyword = "FUZZ"

// Selectors describe which positions in a request to fuzz. Resolution order:
//  1. a literal Keyword present anywhere in the raw request wins (marker mode);
//  2. explicit NamedPoints ("TYPE:name") / HeaderNames;
//  3. Mode ("method"|"path"|"params"|"param-name"|"headers"|"cookies"|"all").
//
// An empty Selectors defaults to "auto" = every discovered insertion point.
type Selectors struct {
	Mode        string
	NamedPoints []string
	HeaderNames []string
	Keyword     string
}

// paramValueTypes are the insertion-point types treated as "param value".
var paramValueTypes = map[httpmsg.InsertionPointType]bool{
	httpmsg.INS_PARAM_URL:            true,
	httpmsg.INS_PARAM_BODY:           true,
	httpmsg.INS_PARAM_JSON:           true,
	httpmsg.INS_PARAM_XML:            true,
	httpmsg.INS_PARAM_XML_ATTR:       true,
	httpmsg.INS_PARAM_MULTIPART_ATTR: true,
	httpmsg.INS_PARAM_AMF:            true,
}

var paramNameTypes = map[httpmsg.InsertionPointType]bool{
	httpmsg.INS_PARAM_NAME_URL:  true,
	httpmsg.INS_PARAM_NAME_BODY: true,
}

var pathTypes = map[httpmsg.InsertionPointType]bool{
	httpmsg.INS_URL_PATH_FOLDER:   true,
	httpmsg.INS_URL_PATH_FILENAME: true,
}

// ResolvePositions turns a raw request + selectors into the concrete list of
// positions to fuzz.
func ResolvePositions(raw []byte, sel Selectors) ([]Position, error) {
	keyword := sel.Keyword
	if keyword == "" {
		keyword = DefaultKeyword
	}

	// (1) Marker mode — a literal keyword anywhere (request line, path, header,
	// body) takes precedence and needs no insertion-point analysis.
	if bytes.Contains(raw, []byte(keyword)) {
		return []Position{{Name: keyword, Label: "MARKER", kind: kindMarker}}, nil
	}

	// method is a special position (no INS_* type backs the request-line verb).
	if strings.EqualFold(sel.Mode, "method") {
		return []Position{{Name: "method", Label: "METHOD", kind: kindMethod}}, nil
	}

	ips, err := httpmsg.CreateAllInsertionPoints(raw, false)
	if err != nil {
		return nil, fmt.Errorf("analyze request insertion points: %w", err)
	}

	// (2) Explicit named points / header names.
	if len(sel.NamedPoints) > 0 || len(sel.HeaderNames) > 0 {
		return resolveNamed(ips, sel)
	}

	// (3) Mode-based selection.
	var want func(httpmsg.InsertionPointType) bool
	switch strings.ToLower(sel.Mode) {
	case "", "auto", "all":
		want = func(httpmsg.InsertionPointType) bool { return true }
	case "params", "param-value", "param", "values":
		want = func(t httpmsg.InsertionPointType) bool { return paramValueTypes[t] }
	case "param-name", "names":
		want = func(t httpmsg.InsertionPointType) bool { return paramNameTypes[t] }
	case "headers", "header":
		want = func(t httpmsg.InsertionPointType) bool { return t == httpmsg.INS_HEADER }
	case "cookies", "cookie":
		want = func(t httpmsg.InsertionPointType) bool { return t == httpmsg.INS_PARAM_COOKIE }
	case "path":
		want = func(t httpmsg.InsertionPointType) bool { return pathTypes[t] }
	default:
		return nil, fmt.Errorf("unknown --fuzz selector %q (want method|path|params|param-name|headers|cookies|all)", sel.Mode)
	}

	var positions []Position
	for _, ip := range ips {
		if want(ip.Type()) {
			positions = append(positions, ipToPosition(ip))
		}
	}
	if len(positions) == 0 {
		if strings.EqualFold(sel.Mode, "path") {
			return nil, fmt.Errorf("no path insertion points in this request — put a %s marker in the path to fuzz it", keyword)
		}
		return nil, fmt.Errorf("no insertion points matched selector %q; place a %s marker to fuzz an arbitrary position", sel.Mode, keyword)
	}
	return positions, nil
}

func resolveNamed(ips []httpmsg.InsertionPoint, sel Selectors) ([]Position, error) {
	var positions []Position
	for _, np := range sel.NamedPoints {
		typeName, name, ok := strings.Cut(np, ":")
		if !ok {
			return nil, fmt.Errorf("bad --point %q (want TYPE:name, e.g. URL_PARAM:id)", np)
		}
		found := false
		for _, ip := range ips {
			if strings.EqualFold(ip.Type().String(), typeName) && ip.Name() == name {
				positions = append(positions, ipToPosition(ip))
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("--point %q not found; available: %s", np, availablePoints(ips))
		}
	}
	for _, h := range sel.HeaderNames {
		found := false
		for _, ip := range ips {
			if ip.Type() == httpmsg.INS_HEADER && strings.EqualFold(ip.Name(), h) {
				positions = append(positions, ipToPosition(ip))
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("--header %q not an injectable header point; available: %s", h, availablePoints(ips))
		}
	}
	return positions, nil
}

func ipToPosition(ip httpmsg.InsertionPoint) Position {
	return Position{
		Name:  ip.Name(),
		Label: ip.Type().String(),
		Base:  ip.BaseValue(),
		kind:  kindInsertionPoint,
		ip:    ip,
	}
}

func availablePoints(ips []httpmsg.InsertionPoint) string {
	var b strings.Builder
	for i, ip := range ips {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(ip.Type().String())
		b.WriteByte(':')
		b.WriteString(ip.Name())
	}
	if b.Len() == 0 {
		return "(none)"
	}
	return b.String()
}

// NormalizeRawRequest ensures raw ends with a header terminator so
// net/http.ReadRequest (used by the send path) can parse it. A header-only
// request whose trailing CRLFs were stripped upstream — e.g. by a
// line-trimming stdin reader — gets exactly one terminator re-appended;
// a request that already carries a header/body separator (any request with a
// body, or an already-well-formed one) is returned unchanged. Idempotent.
func NormalizeRawRequest(raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
	if bytes.Contains(raw, []byte("\r\n\r\n")) || bytes.Contains(raw, []byte("\n\n")) {
		return raw
	}
	trimmed := bytes.TrimRight(raw, "\r\n")
	out := make([]byte, 0, len(trimmed)+4)
	out = append(out, trimmed...)
	out = append(out, '\r', '\n', '\r', '\n')
	return out
}

// build produces the request bytes for this position with payload injected.
func (p Position) build(raw []byte, payload string) []byte {
	switch p.kind {
	case kindInsertionPoint:
		return p.ip.BuildRequest([]byte(payload))
	case kindMethod:
		return rewriteMethod(raw, payload)
	case kindMarker:
		return fixContentLength(replaceMarker(raw, p.Name, payload))
	default:
		return raw
	}
}

// replaceMarker substitutes the keyword with payload. Occurrences in the
// request line (before the first newline) are request-target-encoded so a
// payload containing spaces or other URI-illegal bytes — e.g. a SQLi string in
// ?q=FUZZ — doesn't corrupt the "METHOD target HTTP/x" line; occurrences in
// headers/body are replaced literally (those tolerate spaces, and literal is
// what a marker there is for).
func replaceMarker(raw []byte, keyword, payload string) []byte {
	kw := []byte(keyword)
	nl := bytes.IndexByte(raw, '\n')
	if nl < 0 {
		return bytes.ReplaceAll(raw, kw, []byte(encodeRequestTarget(payload)))
	}
	line := bytes.ReplaceAll(raw[:nl+1], kw, []byte(encodeRequestTarget(payload)))
	rest := bytes.ReplaceAll(raw[nl+1:], kw, []byte(payload))
	out := make([]byte, 0, len(line)+len(rest))
	out = append(out, line...)
	out = append(out, rest...)
	return out
}

// encodeRequestTarget percent-encodes only the bytes that are illegal in an
// HTTP request target (space, controls, and a small unsafe set), leaving
// structural and payload-significant characters (/ ? & = % # ' etc.) intact so
// SQLi/traversal payloads still reach the parameter meaningfully.
func encodeRequestTarget(s string) string {
	const unsafe = " \"<>\\^`{|}"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte(unsafe, c) >= 0 {
			b.WriteByte('%')
			const hex = "0123456789ABCDEF"
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// rewriteMethod replaces the request-line verb (the first token) with payload.
func rewriteMethod(raw []byte, method string) []byte {
	nl := bytes.IndexByte(raw, '\n')
	if nl < 0 {
		return raw
	}
	line := raw[:nl]
	sp := bytes.IndexByte(line, ' ')
	if sp < 0 {
		return raw
	}
	out := make([]byte, 0, len(raw)+len(method))
	out = append(out, []byte(method)...)
	out = append(out, raw[sp:]...)
	return out
}

// fixContentLength recomputes a present Content-Length header to match the body
// after a marker replacement. Best-effort: if there's no body or no
// Content-Length header, the request is returned unchanged. Keeps marker
// fuzzing of body values from sending a mismatched length that some servers
// reject before the payload is ever parsed.
func fixContentLength(raw []byte) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return raw
	}
	head := raw[:idx]
	body := raw[idx+len(sep):]
	const clKey = "content-length:"
	lines := bytes.Split(head, []byte("\r\n"))
	for i, ln := range lines {
		if len(ln) >= len(clKey) && strings.EqualFold(string(ln[:len(clKey)]), clKey) {
			lines[i] = []byte("Content-Length: " + strconv.Itoa(len(body)))
			newHead := bytes.Join(lines, []byte("\r\n"))
			out := make([]byte, 0, len(newHead)+len(sep)+len(body))
			out = append(out, newHead...)
			out = append(out, sep...)
			out = append(out, body...)
			return out
		}
	}
	return raw
}
