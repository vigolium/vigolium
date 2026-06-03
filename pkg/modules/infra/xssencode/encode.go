// Package xssencode provides reusable payload-encoding primitives and
// WAF-aware mutation for the XSS modules. Everything here is a pure function:
// callers opt in by asking for variants, so a module that never calls into
// this package behaves exactly as before.
//
//   - Encoding helpers (URLEncode, Base64): wrap a value so it gets past a WAF
//     and is reconstituted by the application's own decoding. Used by the
//     pre-encoded XSS Light variant to detect parameters the app decodes.
//   - WAF mutation (MutateForWAF, in wafmutate.go): rewrite an HTML/JS payload
//     into an execution-preserving evasion form keyed off the detected WAF.
package xssencode

import (
	"encoding/base64"
	"net/url"
)

// Variant is a named encoding/mutation of a payload. The name is carried for
// finding evidence ("base64", "slash-sep", ...).
type Variant struct {
	Name  string
	Value string
}

// URLEncode percent-encodes every byte that url.QueryEscape would, applied to
// the whole string (so structural characters like < > " ' are encoded).
func URLEncode(s string) string {
	return url.QueryEscape(s)
}

// Base64 returns the standard base64 encoding of s.
func Base64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// dedupeVariants drops variants whose value duplicates an earlier value or
// equals the provided baseline, preserving first occurrence.
func dedupeVariants(in []Variant, baseline string) []Variant {
	seen := map[string]struct{}{}
	if baseline != "" {
		seen[baseline] = struct{}{}
	}
	var out []Variant
	for _, v := range in {
		if v.Value == "" {
			continue
		}
		if _, ok := seen[v.Value]; ok {
			continue
		}
		seen[v.Value] = struct{}{}
		out = append(out, v)
	}
	return out
}
