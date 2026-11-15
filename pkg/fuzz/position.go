package fuzz

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// DefaultKeyword is the literal marker fuzz replaces when present in the raw
// request.
const DefaultKeyword = "FUZZ"

// Selectors describe which positions in a request to fuzz. Resolution order:
//  1. a literal Keyword present anywhere in the raw request wins (marker mode);
//  2. explicit NamedPoints ("TYPE:name") / HeaderNames;
//  3. Mode ("method"|"path"|"params"|"param-name"|"new-param[:query|body|json]"|
//     "body"|"headers"|"cookies"|"all").
//
// param-name RENAMES an existing parameter (?id=1 → ?<payload>=1); new-param
// (alias param-add) ADDS one (?id=1 → ?id=1&<payload>=<canary>), which is
// parameter discovery; body replaces the entire request body.
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
	// body) takes precedence and needs no insertion-point analysis. Numbered
	// siblings (FUZZ2, FUZZ3, ...) become additional positions, which is what
	// the multi-position attack modes bind their payload lists to.
	if markers := findMarkers(raw, keyword); len(markers) > 0 {
		return markers, nil
	}

	// method is a special position (no INS_* type backs the request-line verb).
	if strings.EqualFold(sel.Mode, "method") {
		return []Position{{Name: "method", Label: "METHOD", kind: kindMethod}}, nil
	}

	// (2) Explicit named points / header names.
	if len(sel.NamedPoints) > 0 || len(sel.HeaderNames) > 0 {
		ips, err := httpmsg.CreateAllInsertionPoints(raw, false)
		if err != nil {
			return nil, fmt.Errorf("analyze request insertion points: %w", err)
		}
		return resolveNamed(ips, sel)
	}

	// (3) Mode-based selection. The opt-in point kinds (names, entire body, a
	// new parameter) are only built when their selector asks for them, so the
	// default "all" set is the scanner's set.
	mode, arg, _ := strings.Cut(strings.ToLower(sel.Mode), ":")
	// Headers the request does not carry (X-Forwarded-For, Referer, ...) are
	// the scanner's synthetic points; fuzzing them adds positions nobody
	// asked for, so they are opt-in through headers:synthetic.
	synthetic := false
	if (mode == "headers" || mode == "header") && arg == "synthetic" {
		synthetic, arg = true, ""
	}
	var opts httpmsg.InsertionPointOptions
	var want func(httpmsg.InsertionPoint) bool
	byType := func(f func(httpmsg.InsertionPointType) bool) func(httpmsg.InsertionPoint) bool {
		return func(ip httpmsg.InsertionPoint) bool { return f(ip.Type()) }
	}
	switch mode {
	case "", "auto", "all":
		want = func(httpmsg.InsertionPoint) bool { return true }
	case "params", "param-value", "param", "values":
		want = byType(func(t httpmsg.InsertionPointType) bool { return paramValueTypes[t] })
	case "param-name", "names":
		opts.ParamNames = true
		want = func(ip httpmsg.InsertionPoint) bool {
			_, isRename := ip.(*httpmsg.ParamNameInsertionPoint)
			return isRename
		}
	case "new-param", "param-add":
		loc, err := parseNewParamLocation(arg)
		if err != nil {
			return nil, err
		}
		opts.NewParam = &httpmsg.NewParamSpec{Location: loc}
		want = func(ip httpmsg.InsertionPoint) bool {
			_, isNew := ip.(*httpmsg.NewParamInsertionPoint)
			return isNew
		}
	case "body", "entire-body":
		opts.EntireBody = true
		want = byType(func(t httpmsg.InsertionPointType) bool { return t == httpmsg.INS_ENTIRE_BODY })
	case "headers", "header":
		want = byType(func(t httpmsg.InsertionPointType) bool { return t == httpmsg.INS_HEADER })
	case "cookies", "cookie":
		want = byType(func(t httpmsg.InsertionPointType) bool { return t == httpmsg.INS_PARAM_COOKIE })
	case "path":
		want = byType(func(t httpmsg.InsertionPointType) bool { return pathTypes[t] })
	default:
		return nil, fmt.Errorf("unknown --fuzz selector %q (want %s)", sel.Mode, SelectorNames)
	}
	if arg != "" && opts.NewParam == nil {
		return nil, fmt.Errorf("--fuzz %s takes no :%s qualifier (only new-param:query|body|json and headers:synthetic do)", mode, arg)
	}

	ips, err := httpmsg.CreateInsertionPoints(raw, opts)
	if err != nil {
		return nil, fmt.Errorf("analyze request insertion points: %w", err)
	}

	var positions []Position
	for _, ip := range ips {
		if !want(ip) {
			continue
		}
		if !synthetic && ip.Type() == httpmsg.INS_HEADER && httpmsg.GetHeaderOffsets(raw, ip.Name()) == nil {
			continue
		}
		positions = append(positions, ipToPosition(ip))
	}
	if len(positions) == 0 {
		switch mode {
		case "path":
			return nil, fmt.Errorf("no path insertion points in this request — put a %s marker in the path to fuzz it", keyword)
		case "body", "entire-body":
			return nil, fmt.Errorf("the request has no body to replace — set one with -d, or place a %s marker", keyword)
		case "param-name", "names":
			return nil, fmt.Errorf("no query or form-body parameters to rename — use --fuzz new-param to discover parameters the request does not carry")
		}
		return nil, fmt.Errorf("no insertion points matched selector %q; place a %s marker to fuzz an arbitrary position", sel.Mode, keyword)
	}
	return positions, nil
}

// HasMarker reports whether raw carries keyword or a numbered sibling
// (FUZZ2, ...).
func HasMarker(raw []byte, keyword string) bool {
	if keyword == "" {
		keyword = DefaultKeyword
	}
	return len(findMarkers(raw, keyword)) > 0
}

// NearestMarker returns the token in raw that looks most like keyword (a
// different case, or within two edits: FUZ, FUZZZ, fuzz), or "" when nothing
// is close. It names the likely typo when a request carries no marker.
func NearestMarker(raw []byte, keyword string) string {
	if keyword == "" {
		keyword = DefaultKeyword
	}
	best, bestDist := "", 3
	for _, tok := range bytes.FieldsFunc(raw, func(r rune) bool {
		return r != '_' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z')
	}) {
		t := string(tok)
		if t == keyword || len(t) > 2*len(keyword) {
			continue
		}
		d := textutil.Levenshtein(strings.ToUpper(t), strings.ToUpper(keyword))
		if strings.EqualFold(t, keyword) {
			d = 0
		}
		if d < bestDist && d < len(keyword) {
			best, bestDist = t, d
		}
	}
	return best
}

// SelectorNames lists the --fuzz selector grammar for help and error text.
const SelectorNames = "method|path|params|param-name|new-param[:query|body|json]|body|headers[:synthetic]|cookies|all"

// parseNewParamLocation reads the new-param qualifier; empty means "infer from
// the request" (JSON body → json, form body → body, else query).
func parseNewParamLocation(arg string) (httpmsg.NewParamLocation, error) {
	switch arg {
	case "", "auto":
		return httpmsg.NewParamAuto, nil
	case "query", "url", "get":
		return httpmsg.NewParamQuery, nil
	case "body", "form", "post":
		return httpmsg.NewParamBody, nil
	case "json":
		return httpmsg.NewParamJSON, nil
	default:
		return "", fmt.Errorf("unknown new-param location %q (want query|body|json)", arg)
	}
}

// MaxMarkers bounds how many numbered markers are looked for. Past a handful
// the combination count under clusterbomb stops being something anyone means
// to run.
const MaxMarkers = 8

// findMarkers returns a position for the bare keyword and for each numbered
// sibling present, ordered FUZZ, FUZZ2, FUZZ3, ... so payload lists bind to
// them predictably.
//
// The bare keyword is checked with the numbered ones excluded, since "FUZZ" is
// a prefix of "FUZZ2" and a naive Contains would report the bare marker as
// present in a request that only uses numbered ones.
func findMarkers(raw []byte, keyword string) []Position {
	var out []Position

	stripped := raw
	for i := 2; i <= MaxMarkers; i++ {
		stripped = bytes.ReplaceAll(stripped, []byte(keyword+strconv.Itoa(i)), nil)
	}
	if bytes.Contains(stripped, []byte(keyword)) {
		out = append(out, Position{Name: keyword, Label: "MARKER", kind: kindMarker})
	}

	for i := 2; i <= MaxMarkers; i++ {
		name := keyword + strconv.Itoa(i)
		if bytes.Contains(raw, []byte(name)) {
			out = append(out, Position{Name: name, Label: "MARKER", kind: kindMarker})
		}
	}
	return out
}

func resolveNamed(ips []httpmsg.InsertionPoint, sel Selectors) ([]Position, error) {
	var positions []Position
	for _, np := range sel.NamedPoints {
		typeName, name, ok := strings.Cut(np, ":")
		if !ok {
			return nil, fmt.Errorf("bad --point %q (want TYPE:name, e.g. URL_PARAM:id)", np)
		}
		ip := httpmsg.FindInsertionPoint(ips, typeName, name)
		if ip == nil {
			return nil, fmt.Errorf("--point %q not found; available: %s", np, availablePoints(ips))
		}
		positions = append(positions, ipToPosition(ip))
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
			// Not present on the request — inject it rather than refusing.
			positions = append(positions, Position{Name: h, Label: "HEADER", kind: kindAddHeader})
		}
	}
	return positions, nil
}

func ipToPosition(ip httpmsg.InsertionPoint) Position {
	label := ip.Type().String()
	// A new parameter shares its INS_* type with a renamed one; label it by
	// what it does so a result reads "NEW_PARAM_QUERY <new> = debug".
	if np, ok := ip.(*httpmsg.NewParamInsertionPoint); ok {
		label = "NEW_PARAM_" + strings.ToUpper(string(np.Location()))
	}
	return Position{
		Name:  ip.Name(),
		Label: label,
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
	case kindAddHeader:
		out, err := httpmsg.AddOrReplaceHeader(raw, p.Name, payload)
		if err != nil {
			return raw
		}
		return out
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
		return replaceKeyword(raw, kw, []byte(encodeRequestTarget(payload)))
	}
	line := replaceKeyword(raw[:nl+1], kw, []byte(encodeRequestTarget(payload)))
	rest := replaceKeyword(raw[nl+1:], kw, []byte(payload))
	out := make([]byte, 0, len(line)+len(rest))
	out = append(out, line...)
	out = append(out, rest...)
	return out
}

// replaceKeyword substitutes kw with repl, skipping any occurrence immediately
// followed by a digit. Those belong to a numbered sibling — "FUZZ" is a prefix
// of "FUZZ2" — which is a separate position carrying its own payload, so
// letting the bare marker consume it would rewrite four characters of the
// sibling and leave a stray digit behind. Handling it here means no caller has
// to substitute markers in a particular order.
func replaceKeyword(src, kw, repl []byte) []byte {
	if len(kw) == 0 {
		return src
	}
	var out []byte
	for {
		i := bytes.Index(src, kw)
		if i < 0 {
			break
		}
		end := i + len(kw)
		if end < len(src) && src[end] >= '0' && src[end] <= '9' {
			// A numbered sibling: keep it verbatim and carry on past it.
			out = append(out, src[:end]...)
			src = src[end:]
			continue
		}
		out = append(out, src[:i]...)
		out = append(out, repl...)
		src = src[end:]
	}
	if out == nil {
		return src
	}
	return append(out, src...)
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
