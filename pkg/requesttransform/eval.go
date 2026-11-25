package requesttransform

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Request is what a transform reads and writes: the FINAL request, with
// every header the wire carries (lowercased names) and the body.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    *string
}

// Env is what one evaluation draws on.
type Env struct {
	// Now is milliseconds since the epoch.
	Now func() int64
	// Key resolves a credential reference; false when the store holds none.
	Key func(credential string) (string, bool)
	// Random returns n random bytes; nil uses crypto/rand.
	Random func(n int) []byte
	// Fixed pins a timestamp or nonce op's value by name.
	Fixed map[string]string
	// Vars are values defined before the first op.
	Vars map[string]string
}

// URLParts is a URL split by string slicing - never a URL parser, because
// two parsers normalise a path differently and a signature over a
// normalised path signs bytes that never leave.
type URLParts struct {
	Origin   string
	Host     string
	Path     string
	Query    string
	HasQuery bool
	Fragment string
}

// SplitURL is gimorra's urlParts.
func SplitURL(raw string) URLParts {
	fragment := ""
	noHash := raw
	if i := strings.Index(raw, "#"); i >= 0 {
		fragment, noHash = raw[i:], raw[:i]
	}
	authorityStart := 0
	if i := strings.Index(noHash, "://"); i >= 0 {
		authorityStart = i + 3
	}
	authorityEnd := len(noHash)
	for _, c := range []string{"/", "?"} {
		if i := strings.Index(noHash[authorityStart:], c); i >= 0 && authorityStart+i < authorityEnd {
			authorityEnd = authorityStart + i
		}
	}
	authority := noHash[authorityStart:authorityEnd]
	host := strings.ToLower(authority[strings.LastIndex(authority, "@")+1:])
	rest := noHash[authorityEnd:]
	p := URLParts{Origin: noHash[:authorityEnd], Host: host, Fragment: fragment}
	path := rest
	if q := strings.Index(rest, "?"); q >= 0 {
		path, p.Query, p.HasQuery = rest[:q], rest[q+1:], true
	}
	if path == "" {
		path = "/"
	}
	p.Path = path
	return p
}

func (p URLParts) with(query string, has bool) string {
	s := p.Origin + p.Path
	if has {
		s += "?" + query
	}
	return s + p.Fragment
}

// PercentEncode encodes every byte outside RFC 3986's unreserved set as
// %XX, uppercase.
func PercentEncode(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// safeDecode is JavaScript's decodeURIComponent with `+` read as a space,
// answering the input unchanged where that would throw.
func safeDecode(s string) string {
	out, err := url.PathUnescape(strings.ReplaceAll(s, "+", "%20"))
	if err != nil || !utf8.ValidString(out) {
		return s
	}
	return out
}

func queryName(pair string) string {
	if i := strings.Index(pair, "="); i >= 0 {
		return safeDecode(pair[:i])
	}
	return safeDecode(pair)
}

// QueryValue is one raw query's first value for name, decoded.
func QueryValue(query, name string) (string, bool) {
	for _, pair := range strings.Split(query, "&") {
		if pair == "" || queryName(pair) != name {
			continue
		}
		if i := strings.Index(pair, "="); i >= 0 {
			return safeDecode(pair[i+1:]), true
		}
		return "", true
	}
	return "", false
}

// setQueryParam replaces the first pair named name in place, else appends.
func setQueryParam(query string, has bool, name, value string) string {
	pair := PercentEncode(name) + "=" + PercentEncode(value)
	if !has || query == "" {
		return pair
	}
	pairs := strings.Split(query, "&")
	for i, p := range pairs {
		if queryName(p) == name {
			pairs[i] = pair
			return strings.Join(pairs, "&")
		}
	}
	return query + "&" + pair
}

func encodeBytes(b []byte, encoding string) string {
	switch encoding {
	case "hex":
		return hex.EncodeToString(b)
	case "base64":
		return base64.StdEncoding.EncodeToString(b)
	default:
		return base64.RawURLEncoding.EncodeToString(b)
	}
}

// keyBytes decodes key material; nil when it is not the named encoding.
// base64 is read as leniently as Node's Buffer.from(value, "base64"):
// standard or URL alphabet, padded or not.
func keyBytes(value, encoding string) []byte {
	switch encoding {
	case "hex":
		if !hexPairsRE.MatchString(value) {
			return nil
		}
		b, _ := hex.DecodeString(value)
		return b
	case "base64":
		v := strings.TrimRight(strings.Map(func(r rune) rune {
			switch r {
			case ' ', '\t', '\n', '\r':
				return -1
			case '-':
				return '+'
			case '_':
				return '/'
			}
			return r
		}, value), "=")
		b, err := base64.RawStdEncoding.DecodeString(v)
		if err != nil || len(b) == 0 {
			return nil
		}
		return b
	default:
		return []byte(value)
	}
}

func hasher(alg string) func() hash.Hash {
	switch alg {
	case "sha1":
		return sha1.New
	case "sha512":
		return sha512.New
	case "md5":
		return md5.New
	default:
		return sha256.New
	}
}

var alphabetChars = map[string]string{
	"digits":    "0123456789",
	"alnum":     "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"base64url": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
}

var (
	uuidRE   = regexp.MustCompile(`^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`)
	hexOnlyR = regexp.MustCompile(`^[0-9a-fA-F]*$`)
)

func mintNonce(op Op, random func(int) []byte) string {
	if op.Alphabet == "uuid" {
		b := random(16)
		b[6] = (b[6] & 0x0f) | 0x40
		b[8] = (b[8] & 0x3f) | 0x80
		h := hex.EncodeToString(b)
		return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	}
	length := op.Length
	if !op.HasLength {
		length = 16
	}
	if op.Alphabet == "hex" {
		return hex.EncodeToString(random((length + 1) / 2))[:length]
	}
	chars := alphabetChars[op.Alphabet]
	var b strings.Builder
	for _, x := range random(length) {
		b.WriteByte(chars[int(x)%len(chars)])
	}
	return b.String()
}

func nonceFits(op Op, v string) bool {
	if op.Alphabet == "uuid" {
		return uuidRE.MatchString(v)
	}
	if jsLen(v) != op.Length {
		return false
	}
	if op.Alphabet == "hex" {
		return hexOnlyR.MatchString(v)
	}
	chars := alphabetChars[op.Alphabet]
	for _, r := range v {
		if !strings.ContainsRune(chars, r) {
			return false
		}
	}
	return true
}

type working struct {
	method   string
	parts    URLParts
	query    string
	hasQuery bool
	headers  map[string]string
	body     *string
	vars     map[string]string
	ts       *string
	nonce    *string
}

func (w *working) read(part string) string {
	switch part {
	case "method":
		return w.method
	case "host":
		return w.parts.Host
	case "path":
		return w.parts.Path
	case "query":
		return w.query
	case "target":
		if !w.hasQuery || w.query == "" {
			return w.parts.Path
		}
		return w.parts.Path + "?" + w.query
	case "body":
		if w.body == nil {
			return ""
		}
		return *w.body
	case "ts":
		if w.ts == nil {
			return ""
		}
		return *w.ts
	case "nonce":
		if w.nonce == nil {
			return ""
		}
		return *w.nonce
	}
	switch {
	case strings.HasPrefix(part, "header:"):
		return w.headers[strings.ToLower(strings.TrimPrefix(part, "header:"))]
	case strings.HasPrefix(part, "var:"):
		return w.vars[strings.TrimPrefix(part, "var:")]
	case strings.HasPrefix(part, "literal:"):
		return strings.TrimPrefix(part, "literal:")
	}
	return ""
}

func (w *working) fill(text string) string {
	return placeholderRE.ReplaceAllStringFunc(text, func(m string) string {
		return w.read(m[2 : len(m)-2])
	})
}

func (w *working) join(over []string, sep string) string {
	vals := make([]string, len(over))
	for i, p := range over {
		vals[i] = w.read(p)
	}
	return strings.Join(vals, sep)
}

// Evaluate applies a checked transform to one request. The URL that comes
// back keeps the request's origin byte for byte: no op writes it.
func Evaluate(t *Transform, req Request, env Env) (Request, map[string]string, *Refusal) {
	parts := SplitURL(req.URL)
	headers := make(map[string]string, len(req.Headers))
	for k, v := range req.Headers {
		headers[strings.ToLower(k)] = v
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}
	w := &working{
		method:   strings.ToUpper(method),
		parts:    parts,
		query:    parts.Query,
		hasQuery: parts.HasQuery,
		headers:  headers,
		body:     req.Body,
		vars:     map[string]string{},
	}
	for k, v := range env.Vars {
		w.vars[k] = v
	}
	random := env.Random
	if random == nil {
		random = func(n int) []byte {
			b := make([]byte, n)
			_, _ = rand.Read(b)
			return b
		}
	}
	resolve := func(at, credential string) (string, *Refusal) {
		if env.Key != nil {
			if v, ok := env.Key(credential); ok {
				return v, nil
			}
		}
		return "", refuse("key-unresolved", fmt.Sprintf("%s: no credential named '%s' in the engagement's store", at, credential))
	}
	for i, op := range t.Ops {
		at := fmt.Sprintf("op %d (%s)", i, op.Op)
		switch op.Op {
		case "timestamp":
			value, pinned := env.Fixed[op.Name]
			if !pinned {
				now := env.Now()
				if op.Unit == "s" {
					value = strconv.FormatInt(floorDiv(now, 1000), 10)
				} else {
					value = strconv.FormatInt(now, 10)
				}
			}
			w.vars[op.Name] = value
			if w.ts == nil {
				v := value
				w.ts = &v
			}
		case "nonce":
			value, pinned := env.Fixed[op.Name]
			if pinned && !nonceFits(op, value) {
				detail := fmt.Sprintf("%s: the pinned value for '%s' is not a %s nonce", at, op.Name, op.Alphabet)
				if op.HasLength {
					detail += fmt.Sprintf(" of %d characters", op.Length)
				}
				return Request{}, nil, &Refusal{Code: "mismatch", Detail: detail, Field: "var:" + op.Name}
			}
			if !pinned {
				value = mintNonce(op, random)
			}
			w.vars[op.Name] = value
			if w.nonce == nil {
				v := value
				w.nonce = &v
			}
		case "hash":
			h := hasher(op.Alg)()
			h.Write([]byte(w.join(op.Over, op.Join)))
			w.vars[op.Name] = encodeBytes(h.Sum(nil), op.Encoding)
		case "truncate":
			from := []rune(w.vars[op.From])
			if op.Keep == "start" {
				if len(from) > op.Length {
					from = from[:op.Length]
				}
			} else if len(from) > op.Length {
				from = from[len(from)-op.Length:]
			}
			w.vars[op.Name] = string(from)
		case "hmac-header":
			raw, r := resolve(at, op.Key.Credential)
			if r != nil {
				return Request{}, nil, r
			}
			k := keyBytes(raw, op.KeyEncoding)
			if len(k) == 0 {
				enc := op.KeyEncoding
				if enc == "" {
					enc = "utf8"
				}
				return Request{}, nil, refuse("bad-key", fmt.Sprintf("%s: credential '%s' is not %s key material", at, op.Key.Credential, enc))
			}
			mac := hmac.New(hasher(op.Alg), k)
			mac.Write([]byte(w.join(op.Over, op.Join)))
			sig := encodeBytes(mac.Sum(nil), op.Encoding)
			w.headers[strings.ToLower(op.Header)] = op.Prefix + sig
			if op.HasName {
				w.vars[op.Name] = sig
			}
		case "set-header":
			w.headers[strings.ToLower(op.Header)] = w.fill(op.Value)
		case "set-query":
			w.query = setQueryParam(w.query, w.hasQuery, op.Param, w.fill(op.Value))
			w.hasQuery = true
		case "encrypt-body":
			raw, r := resolve(at, op.Key.Credential)
			if r != nil {
				return Request{}, nil, r
			}
			sizes := cipherSizes[op.Alg]
			k := keyBytes(raw, op.KeyEncoding)
			if len(k) != sizes.key {
				return Request{}, nil, refuse("bad-key", fmt.Sprintf("%s: %s takes a %d-byte key", at, op.Alg, sizes.key))
			}
			ivHex := w.vars[op.IV]
			var iv []byte
			if hexPairsRE.MatchString(ivHex) {
				iv, _ = hex.DecodeString(ivHex)
			}
			if len(iv) != sizes.iv {
				return Request{}, nil, refuse("bad-iv", fmt.Sprintf("%s: %s takes a %d-byte IV", at, op.Alg, sizes.iv))
			}
			plain := ""
			if w.body != nil {
				plain = *w.body
			}
			sealed, err := encryptLayout(op, k, iv, []byte(plain))
			if err != nil {
				return Request{}, nil, refuse("bad-key", fmt.Sprintf("%s: %v", at, err))
			}
			text := encodeBytes(sealed, op.Encoding)
			if op.HasEnvelope {
				text = strings.Replace(op.Envelope, "{{cipher}}", text, 1)
			}
			w.body = &text
			if op.HasContentType {
				w.headers["content-type"] = op.ContentType
			}
		}
	}
	out := Request{Method: req.Method, URL: parts.with(w.query, w.hasQuery), Headers: w.headers, Body: w.body}
	return out, w.vars, nil
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

func encryptLayout(op Op, key, iv, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var ct, tag []byte
	if strings.HasSuffix(op.Alg, "gcm") {
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		sealed := gcm.Seal(nil, iv, plain, nil)
		ct, tag = sealed[:len(sealed)-gcm.Overhead()], sealed[len(sealed)-gcm.Overhead():]
	} else {
		pad := aes.BlockSize - len(plain)%aes.BlockSize
		padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
		ct = make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	}
	switch op.Layout {
	case "iv+ct+tag":
		return concat(iv, ct, tag), nil
	case "ct+tag":
		return concat(ct, tag), nil
	case "iv+ct":
		return concat(iv, ct), nil
	default:
		return ct, nil
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Matches reports whether t applies to rawURL: its host (and port, when
// the transform names one) and its path prefix.
func Matches(t *Transform, rawURL string) bool {
	p := SplitURL(rawURL)
	host := p.Host
	if !strings.Contains(t.Applies.Host, ":") {
		host = portSuffix.ReplaceAllString(host, "")
	}
	if host != t.Applies.Host {
		return false
	}
	return !t.Applies.HasPathPrefix || strings.HasPrefix(p.Path, t.Applies.PathPrefix)
}

var portSuffix = regexp.MustCompile(`:\d+$`)

// For picks the transform that applies to rawURL; the longest path prefix
// wins, the first among equals.
func For(list []*Transform, rawURL string) *Transform {
	var best *Transform
	for _, t := range list {
		if !Matches(t, rawURL) {
			continue
		}
		if best == nil || len(t.Applies.PathPrefix) > len(best.Applies.PathPrefix) {
			best = t
		}
	}
	return best
}
