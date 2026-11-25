// Package requesttransform evaluates a declared request transform: the
// signing, nonce and body encryption a target's own client applies to every
// request, written as data (an ordered list of operations) and never as code.
//
// The schema, the checks and the semantics are gimorra's
// (packages/validators/src/request-transform.ts). Both evaluators read the same
// conformance vectors (testdata/request-transform.json, a byte-for-byte copy of
// gimorra's packages/validators/conformance/request-transform.json) in their
// tests, so one transform answers the same bytes in either.
//
// A transform cannot change where a request goes: no operation writes the
// URL's scheme, host, port or path, and the header names that route or frame a
// request (DestinationHeaders) are refused at decode.
//
// Keys are references: hmac-header and encrypt-body name a credential
// ({"credential": "<name>"}) that Env.Key resolves at evaluation; a transform
// document never holds a key value.
package requesttransform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
)

// Ops is the closed vocabulary, in the order the refusal message lists it.
var Ops = []string{"timestamp", "nonce", "hash", "truncate", "hmac-header", "set-header", "set-query", "encrypt-body"}

// MaxOps is the most operations one transform may hold.
const MaxOps = 32

// maxLiteralChars bounds every literal an op carries (UTF-16 code units, as
// the TypeScript evaluator counts them).
const maxLiteralChars = 2048

var (
	hashAlgs       = []string{"sha256", "sha1", "sha512", "md5"}
	encodings      = []string{"hex", "base64", "base64url"}
	keyEncodings   = []string{"utf8", "hex", "base64"}
	nonceAlphabets = []string{"hex", "digits", "alnum", "base64url", "uuid"}
	ciphers        = []string{"aes-128-gcm", "aes-256-gcm", "aes-128-cbc", "aes-256-cbc"}
	layouts        = []string{"iv+ct+tag", "ct+tag", "iv+ct", "ct"}
)

// cipherSizes is the byte length each cipher takes as key and IV.
var cipherSizes = map[string]struct{ key, iv int }{
	"aes-128-gcm": {16, 12},
	"aes-256-gcm": {32, 12},
	"aes-128-cbc": {16, 16},
	"aes-256-cbc": {32, 16},
}

// DestinationHeaders are the header names that decide where a request goes
// or how it is framed; a transform never writes one.
var DestinationHeaders = map[string]bool{
	"host": true, ":authority": true, ":scheme": true, ":path": true, ":method": true,
	"forwarded": true, "x-forwarded-host": true, "x-forwarded-proto": true, "x-forwarded-port": true,
	"x-forwarded-server": true, "x-host": true, "x-original-url": true, "x-rewrite-url": true,
	"x-original-host": true, "x-http-method-override": true, "x-http-method": true,
	"x-method-override": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"te": true, "upgrade": true, "proxy-connection": true,
}

var (
	nameRE        = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	tokenRE       = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
	keyRefRE      = regexp.MustCompile(`^[A-Za-z0-9._:@/-]{1,128}$`)
	placeholderRE = regexp.MustCompile(`\{\{([^{}]*)\}\}`)
	hexPairsRE    = regexp.MustCompile(`^(?:[0-9a-fA-F]{2})+$`)
)

// KeyRef names a credential of the caller's key store, never its value.
type KeyRef struct {
	Credential string
}

// Op is one decoded operation; which fields are meaningful depends on Op.
type Op struct {
	Op string

	Name    string
	HasName bool

	Unit      string
	Length    int
	HasLength bool
	Alphabet  string

	Alg         string
	Over        []string
	Join        string
	Encoding    string
	From        string
	Keep        string
	Header      string
	Key         KeyRef
	KeyEncoding string
	Prefix      string
	Value       string
	Param       string
	IV          string
	Layout      string

	Envelope       string
	HasEnvelope    bool
	ContentType    string
	HasContentType bool
}

// Applies is where a transform applies: one host (hostname, or
// hostname:port), optionally a path prefix.
type Applies struct {
	Host          string
	PathPrefix    string
	HasPathPrefix bool
}

// Transform is a decoded, checked transform.
type Transform struct {
	ID      string
	Applies Applies
	Ops     []Op
}

// Refusal says why a transform was refused or could not be evaluated. Code
// is the stable vocabulary both evaluators share (the vectors assert it).
type Refusal struct {
	Code   string
	Detail string
	Field  string
}

func (r *Refusal) Error() string { return r.Code + ": " + r.Detail }

func refuse(code, detail string) *Refusal { return &Refusal{Code: code, Detail: detail} }

// fieldKind is how one op field is decoded.
type fieldKind int

const (
	kString fieldKind = iota
	kStrings
	kCount
	kKey
	kLiteral
)

type fieldSpec struct {
	kind     fieldKind
	required bool
	values   []string
}

func str(req bool) fieldSpec             { return fieldSpec{kind: kString, required: req} }
func lit(req bool, v []string) fieldSpec { return fieldSpec{kind: kLiteral, required: req, values: v} }
func count(req bool) fieldSpec           { return fieldSpec{kind: kCount, required: req} }
func strs(req bool) fieldSpec            { return fieldSpec{kind: kStrings, required: req} }
func key(req bool) fieldSpec             { return fieldSpec{kind: kKey, required: req} }

// opFields is each op's schema: its fields, their kinds, which are required.
// Any other key is refused, so an op has no `url` to write.
var opFields = map[string]map[string]fieldSpec{
	"timestamp": {"name": str(true), "unit": lit(true, []string{"s", "ms"})},
	"nonce":     {"name": str(true), "length": count(false), "alphabet": lit(true, nonceAlphabets)},
	"hash": {"name": str(true), "alg": lit(true, hashAlgs), "over": strs(true), "join": str(false),
		"encoding": lit(true, encodings)},
	"truncate": {"name": str(true), "from": str(true), "length": count(true), "keep": lit(false, []string{"start", "end"})},
	"hmac-header": {"header": str(true), "alg": lit(true, hashAlgs), "key": key(true),
		"keyEncoding": lit(false, keyEncodings), "over": strs(true), "join": str(false),
		"encoding": lit(true, encodings), "prefix": str(false), "name": str(false)},
	"set-header": {"header": str(true), "value": str(true)},
	"set-query":  {"param": str(true), "value": str(true)},
	"encrypt-body": {"alg": lit(true, ciphers), "key": key(true), "keyEncoding": lit(false, keyEncodings),
		"iv": str(true), "encoding": lit(true, []string{"hex", "base64"}), "layout": lit(true, layouts),
		"envelope": str(false), "contentType": str(false)},
}

// Decode decodes and checks one transform document, answering the FIRST
// refusal (the same one gimorra's decodeTransform answers).
func Decode(data []byte) (*Transform, *Refusal) {
	return DecodeWith(data, nil)
}

// DecodeWith is Decode with names defined before the first op.
func DecodeWith(data []byte, predefined []string) (*Transform, *Refusal) {
	top, err := object(data)
	if err != nil {
		return nil, refuse("bad-shape", "the transform is not { id, applies: { host, pathPrefix? }, ops: [...] }")
	}
	shape := func(at string) *Refusal {
		return refuse("bad-shape", fmt.Sprintf("the transform is not { id, applies: { host, pathPrefix? }, ops: [...] } (at %s)", at))
	}
	for k := range top {
		if k != "id" && k != "applies" && k != "ops" {
			return nil, shape(k)
		}
	}
	id, ok := stringOf(top["id"])
	if !ok {
		return nil, shape("id")
	}
	appliesRaw, err := object(top["applies"])
	if err != nil {
		return nil, shape("applies")
	}
	for k := range appliesRaw {
		if k != "host" && k != "pathPrefix" {
			return nil, shape("applies." + k)
		}
	}
	host, ok := stringOf(appliesRaw["host"])
	if !ok {
		return nil, shape("applies.host")
	}
	var applies Applies
	if raw, present := appliesRaw["pathPrefix"]; present {
		p, ok := stringOf(raw)
		if !ok {
			return nil, shape("applies.pathPrefix")
		}
		applies.PathPrefix, applies.HasPathPrefix = p, true
	}
	var rawOps []json.RawMessage
	if r, present := top["ops"]; !present || isNull(r) || json.Unmarshal(r, &rawOps) != nil {
		return nil, shape("ops")
	}

	if !nameRE.MatchString(id) {
		return nil, refuse("bad-name", fmt.Sprintf("id '%s' is not 1-64 of [A-Za-z0-9_-]", id))
	}
	applies.Host = strings.ToLower(strings.TrimSpace(host))
	if applies.Host == "" || strings.ContainsAny(applies.Host, "/?#@") || strings.IndexFunc(applies.Host, unicode.IsSpace) >= 0 {
		return nil, refuse("bad-shape", fmt.Sprintf("applies.host '%s' is not a hostname", host))
	}
	if applies.HasPathPrefix && !strings.HasPrefix(applies.PathPrefix, "/") {
		return nil, refuse("bad-shape", fmt.Sprintf("applies.pathPrefix '%s' must start with '/'", applies.PathPrefix))
	}
	if len(rawOps) == 0 || len(rawOps) > MaxOps {
		return nil, refuse("bad-shape", fmt.Sprintf("a transform holds 1-%d ops", MaxOps))
	}
	ops := make([]Op, 0, len(rawOps))
	for i, raw := range rawOps {
		op, r := decodeOp(i, raw)
		if r != nil {
			return nil, r
		}
		ops = append(ops, op)
	}
	if r := checkOps(ops, predefined); r != nil {
		return nil, r
	}
	return &Transform{ID: id, Applies: applies, Ops: ops}, nil
}

func decodeOp(i int, raw json.RawMessage) (Op, *Refusal) {
	fields, err := object(raw)
	name := "?"
	if err == nil {
		if s, ok := stringOf(fields["op"]); ok {
			name = s
		}
	}
	spec, known := opFields[name]
	if err != nil || !known {
		return Op{}, refuse("unknown-op", fmt.Sprintf("op %d ('%s') is not in the vocabulary (%s) - a shape it cannot express is not a transform",
			i, name, strings.Join(Ops, ", ")))
	}
	bad := func(field, why string) *Refusal {
		return refuse("bad-shape", fmt.Sprintf("op %d (%s): %s: %s", i, name, field, why))
	}
	op := Op{Op: name}
	for k, v := range fields {
		if k == "op" {
			continue
		}
		fs, ok := spec[k]
		if !ok {
			return Op{}, bad(k, "is not a field of this op")
		}
		switch fs.kind {
		case kString, kLiteral:
			s, ok := stringOf(v)
			if !ok {
				return Op{}, bad(k, "expected a string")
			}
			if fs.kind == kLiteral && !contains(fs.values, s) {
				return Op{}, bad(k, "expected one of "+strings.Join(fs.values, ", "))
			}
			setString(&op, k, s)
		case kStrings:
			var list []json.RawMessage
			if isNull(v) || json.Unmarshal(v, &list) != nil {
				return Op{}, bad(k, "expected an array of strings")
			}
			out := make([]string, 0, len(list))
			for _, e := range list {
				s, ok := stringOf(e)
				if !ok {
					return Op{}, bad(k, "expected an array of strings")
				}
				out = append(out, s)
			}
			op.Over = out
		case kCount:
			var f float64
			if isNull(v) || json.Unmarshal(v, &f) != nil || f != math.Trunc(f) || f < 1 || f > 256 {
				return Op{}, bad(k, "expected an integer between 1 and 256")
			}
			op.Length, op.HasLength = int(f), true
		case kKey:
			kr, err := object(v)
			if err != nil {
				return Op{}, bad(k, "expected { credential }")
			}
			for kk := range kr {
				if kk != "credential" {
					return Op{}, bad(k+"."+kk, "is not a field of a key reference")
				}
			}
			c, ok := stringOf(kr["credential"])
			if !ok {
				return Op{}, bad(k+".credential", "expected a string")
			}
			op.Key = KeyRef{Credential: c}
		}
	}
	for k, fs := range spec {
		if _, present := fields[k]; fs.required && !present {
			return Op{}, bad(k, "is missing")
		}
	}
	return op, nil
}

func setString(op *Op, k, s string) {
	switch k {
	case "name":
		op.Name, op.HasName = s, true
	case "unit":
		op.Unit = s
	case "alphabet":
		op.Alphabet = s
	case "alg":
		op.Alg = s
	case "join":
		op.Join = s
	case "encoding":
		op.Encoding = s
	case "from":
		op.From = s
	case "keep":
		op.Keep = s
	case "header":
		op.Header = s
	case "keyEncoding":
		op.KeyEncoding = s
	case "prefix":
		op.Prefix = s
	case "value":
		op.Value = s
	case "param":
		op.Param = s
	case "iv":
		op.IV = s
	case "layout":
		op.Layout = s
	case "envelope":
		op.Envelope, op.HasEnvelope = s, true
	case "contentType":
		op.ContentType, op.HasContentType = s, true
	}
}

// checkOps is gimorra's checkOps: names, destination headers, every part and
// placeholder reading a defined value, the IV, key references.
func checkOps(ops []Op, predefined []string) *Refusal {
	vars := map[string]bool{}
	for _, p := range predefined {
		vars[p] = true
	}
	ts, nonce := false, false
	for i, op := range ops {
		at := fmt.Sprintf("op %d (%s)", i, op.Op)
		parts := func(over []string) *Refusal {
			for _, p := range over {
				if code, detail := partRefusal(p, vars, ts, nonce); code != "" {
					return refuse(code, at+": "+detail)
				}
			}
			return nil
		}
		literal := func(text, field string) *Refusal {
			if jsLen(text) > maxLiteralChars {
				return refuse("bad-shape", fmt.Sprintf("%s: %s is over %d characters", at, field, maxLiteralChars))
			}
			return nil
		}
		keyRef := func(k KeyRef) *Refusal {
			if keyRefRE.MatchString(k.Credential) {
				return nil
			}
			return refuse("literal-key", at+": key.credential must NAME a credential of the engagement's store, not hold a value")
		}
		header := func(name string) *Refusal {
			// The destination check first: `:authority` is not a token, and its
			// refusal says why it matters rather than that it is spelled oddly.
			if DestinationHeaders[strings.ToLower(name)] {
				return refuse("destination-header", fmt.Sprintf("%s: '%s' decides where the request goes or how it is framed - a transform cannot change the destination", at, name))
			}
			if !tokenRE.MatchString(name) {
				return refuse("bad-name", fmt.Sprintf("%s: '%s' is not a header name", at, name))
			}
			return nil
		}
		defines := func(name string) *Refusal {
			if nameRE.MatchString(name) {
				return nil
			}
			return refuse("bad-name", fmt.Sprintf("%s: name '%s' is not 1-64 of [A-Za-z0-9_-]", at, name))
		}
		known := func(name, what string) *Refusal {
			if vars[name] {
				return nil
			}
			return refuse("unknown-var", fmt.Sprintf("%s: %s'%s' is not defined by an earlier op", at, what, name))
		}
		var bad *Refusal
		switch op.Op {
		case "timestamp":
			bad = defines(op.Name)
			ts = true
		case "nonce":
			bad = first(
				func() *Refusal { return defines(op.Name) },
				func() *Refusal {
					if op.Alphabet == "uuid" && op.HasLength && op.Length != 36 {
						return refuse("bad-shape", at+": a uuid nonce is 36 characters")
					}
					if op.Alphabet != "uuid" && !op.HasLength {
						return refuse("bad-shape", fmt.Sprintf("%s: a %s nonce needs a length", at, op.Alphabet))
					}
					return nil
				})
			nonce = true
		case "hash":
			bad = first(
				func() *Refusal { return defines(op.Name) },
				func() *Refusal { return parts(op.Over) },
				func() *Refusal { return literal(op.Join, "join") })
		case "truncate":
			bad = first(
				func() *Refusal { return defines(op.Name) },
				func() *Refusal { return known(op.From, "") })
		case "hmac-header":
			bad = first(
				func() *Refusal { return header(op.Header) },
				func() *Refusal { return keyRef(op.Key) },
				func() *Refusal { return parts(op.Over) },
				func() *Refusal { return literal(op.Join, "join") },
				func() *Refusal { return literal(op.Prefix, "prefix") },
				func() *Refusal {
					if !op.HasName {
						return nil
					}
					return defines(op.Name)
				})
		case "set-header":
			bad = first(
				func() *Refusal { return header(op.Header) },
				func() *Refusal { return literal(op.Value, "value") },
				func() *Refusal { return templateRefusal(op.Value, vars, ts, nonce, at) })
		case "set-query":
			bad = first(
				func() *Refusal {
					if tokenRE.MatchString(op.Param) {
						return nil
					}
					return refuse("bad-name", fmt.Sprintf("%s: '%s' is not a parameter name", at, op.Param))
				},
				func() *Refusal { return literal(op.Value, "value") },
				func() *Refusal { return templateRefusal(op.Value, vars, ts, nonce, at) })
		case "encrypt-body":
			bad = first(
				func() *Refusal { return keyRef(op.Key) },
				func() *Refusal { return known(op.IV, "iv ") },
				func() *Refusal { return ivOpRefusal(ops, op, at) },
				func() *Refusal {
					if !op.HasEnvelope {
						return nil
					}
					return envelopeRefusal(op.Envelope, at)
				},
				func() *Refusal {
					if !op.HasContentType {
						return nil
					}
					return literal(op.ContentType, "contentType")
				})
		}
		if bad != nil {
			return bad
		}
		if op.HasName {
			vars[op.Name] = true
		}
	}
	return nil
}

// first runs checks in order and answers the first refusal.
func first(checks ...func() *Refusal) *Refusal {
	for _, c := range checks {
		if r := c(); r != nil {
			return r
		}
	}
	return nil
}

func ivOpRefusal(ops []Op, op Op, at string) *Refusal {
	want := cipherSizes[op.Alg].iv * 2
	for _, o := range ops {
		if o.Op == "nonce" && o.Name == op.IV {
			if o.Alphabet == "hex" && o.HasLength && o.Length == want {
				return nil
			}
			break
		}
	}
	return refuse("bad-iv", fmt.Sprintf("%s: iv '%s' must be a hex nonce of %d characters (%d bytes for %s)", at, op.IV, want, want/2, op.Alg))
}

func envelopeRefusal(envelope, at string) *Refusal {
	found := placeholderRE.FindAllStringSubmatch(envelope, -1)
	if len(found) != 1 || found[0][1] != "cipher" || jsLen(envelope) > maxLiteralChars {
		return refuse("bad-template", at+": envelope must hold {{cipher}} exactly once and nothing else in {{ }}")
	}
	return nil
}

// partRefusal answers ("", "") when the part reads something defined.
func partRefusal(part string, vars map[string]bool, ts, nonce bool) (string, string) {
	switch part {
	case "method", "host", "path", "query", "target", "body":
		return "", ""
	case "ts":
		if ts {
			return "", ""
		}
		return "unknown-var", "'ts' is read before any timestamp op"
	case "nonce":
		if nonce {
			return "", ""
		}
		return "unknown-var", "'nonce' is read before any nonce op"
	}
	switch {
	case strings.HasPrefix(part, "header:"):
		if tokenRE.MatchString(strings.TrimPrefix(part, "header:")) {
			return "", ""
		}
		return "unknown-part", fmt.Sprintf("'%s' names no header", part)
	case strings.HasPrefix(part, "var:"):
		if vars[strings.TrimPrefix(part, "var:")] {
			return "", ""
		}
		return "unknown-var", fmt.Sprintf("'%s' is not defined by an earlier op", part)
	case strings.HasPrefix(part, "literal:"):
		return "", ""
	}
	return "unknown-part", fmt.Sprintf("'%s' is not a part (method, host, path, query, target, body, ts, nonce, header:<n>, var:<n>, literal:<text>)", part)
}

func templateRefusal(text string, vars map[string]bool, ts, nonce bool, at string) *Refusal {
	for _, m := range placeholderRE.FindAllStringSubmatch(text, -1) {
		part := m[1]
		if strings.HasPrefix(part, "literal:") {
			return refuse("bad-template", at+": a template holds its literal text outside {{ }}")
		}
		if code, detail := partRefusal(part, vars, ts, nonce); code != "" {
			if code == "unknown-part" {
				code = "bad-template"
			}
			return refuse(code, at+": "+detail)
		}
	}
	if strings.Contains(placeholderRE.ReplaceAllString(text, ""), "{{") {
		return refuse("bad-template", fmt.Sprintf("%s: an unclosed '{{' in '%s'", at, text))
	}
	return nil
}

// object decodes a JSON object into its raw members; null and non-objects fail.
func object(data []byte) (map[string]json.RawMessage, error) {
	if isNull(data) {
		return nil, fmt.Errorf("null")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("not an object")
	}
	return m, nil
}

func stringOf(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || isNull(raw) {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func isNull(raw []byte) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// jsLen is a string's length in UTF-16 code units - JavaScript's `.length`.
func jsLen(s string) int { return len(utf16.Encode([]rune(s))) }
