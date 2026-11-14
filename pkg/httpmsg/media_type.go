package httpmsg

import (
	"bytes"
	"encoding/json"
	"strings"
)

// ClassifyMediaType maps a Content-Type header value (raw, parameters and all)
// to a canonical media type and the body ContentType parsers dispatch on.
//
//   - the type is lowercased and its parameters stripped;
//   - structured-syntax suffixes and vendor types map to their syntax:
//     "+json", ".../json", ".../x-json" → JSON (application/vnd.api+json,
//     application/problem+json, text/json); "+xml", ".../xml" → XML
//     (application/soap+xml, text/xml);
//   - a missing type or text/plain is SNIFFED from body: a "{"/"[" prefix that
//     is valid JSON → JSON, a "<" prefix → XML, k=v(&k=v)* → urlencoded.
//
// Before, body parsing switched on the exact header string, so
// "Application/JSON", "application/vnd.api+json" or "application/soap+xml"
// produced no body insertion points at all (MISS-10).
//
// canonical is "" when nothing could be determined; the ContentType is then
// ContentTypeUnknown.
func ClassifyMediaType(raw string, body []byte) (canonical string, ct ContentType) {
	mt := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.IndexByte(mt, ';'); i >= 0 {
		mt = strings.TrimSpace(mt[:i])
	}
	switch {
	case mt == "application/x-www-form-urlencoded":
		return mt, ContentTypeURLEncoded
	case strings.HasPrefix(mt, "multipart/"):
		return mt, ContentTypeMultipart
	case mt == "application/x-amf":
		return mt, ContentTypeAMF
	case strings.HasSuffix(mt, "+json") || strings.HasSuffix(mt, "/json") || strings.HasSuffix(mt, "/x-json"):
		return "application/json", ContentTypeJSON
	case strings.HasSuffix(mt, "+xml") || strings.HasSuffix(mt, "/xml"):
		return "application/xml", ContentTypeXML
	case mt == "" || mt == "text/plain":
		if c, t := sniffBodyMediaType(body); t != ContentTypeUnknown {
			return c, t
		}
		return mt, ContentTypeUnknown
	default:
		return mt, ContentTypeUnknown
	}
}

// sniffBodyMediaType guesses a body's syntax from its content.
func sniffBodyMediaType(body []byte) (string, ContentType) {
	b := bytes.TrimSpace(body)
	if len(b) == 0 {
		return "", ContentTypeUnknown
	}
	switch b[0] {
	case '{', '[':
		if json.Valid(b) {
			return "application/json", ContentTypeJSON
		}
		return "", ContentTypeUnknown
	case '<':
		return "application/xml", ContentTypeXML
	}
	if looksURLEncoded(b) {
		return "application/x-www-form-urlencoded", ContentTypeURLEncoded
	}
	return "", ContentTypeUnknown
}

// looksURLEncoded reports whether b is k=v(&k=v)* with non-empty keys made of
// URL-safe characters (values may be empty).
func looksURLEncoded(b []byte) bool {
	for _, pair := range bytes.Split(b, []byte{'&'}) {
		eq := bytes.IndexByte(pair, '=')
		if eq <= 0 {
			return false
		}
		for _, c := range pair {
			if c <= ' ' || c == 0x7f || c == '"' || c == '<' || c == '>' || c == '{' || c == '}' {
				return false
			}
		}
	}
	return true
}
