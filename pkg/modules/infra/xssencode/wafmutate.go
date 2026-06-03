package xssencode

import (
	"regexp"
	"strings"
)

// Execution-preserving mutators. Every transform below keeps the payload
// runnable in a real browser, because the confirm-tier oracle is actual
// JavaScript-dialog execution — a mutation that merely dodges a WAF signature
// but no longer executes is worthless here (and a malformed one simply fails
// to confirm, so there is no false-positive risk).

var (
	// tagNameRe captures the tag name in an opening or closing tag.
	tagNameRe = regexp.MustCompile(`(</?)([a-zA-Z][a-zA-Z0-9]*)`)
	// simpleCallRe matches alert/prompt/confirm with a parenthesised argument
	// that itself contains no parentheses, so backtick substitution preserves
	// execution for literal arguments.
	simpleCallRe = regexp.MustCompile(`\b(alert|prompt|confirm)\(([^()]*)\)`)
)

// subSpaces replaces ASCII spaces with sep. Returns the input unchanged when it
// has no spaces, so dedup drops the no-op.
func subSpaces(p, sep string) string {
	if !strings.Contains(p, " ") {
		return p
	}
	return strings.ReplaceAll(p, " ", sep)
}

// upperTagNames uppercases HTML tag names (case-insensitive in the HTML parser)
// while leaving attribute values and JS bodies untouched.
func upperTagNames(p string) string {
	// The match is "<"/"</" plus the tag name; ToUpper only affects the
	// letters (the tag name), so it needs no submatch re-parsing.
	return tagNameRe.ReplaceAllStringFunc(p, strings.ToUpper)
}

// backtickParens rewrites alert(x)/prompt(x)/confirm(x) to tagged-template form
// (alert`x`), which executes for literal arguments and dodges parenthesis
// filters (OWASP CRS 941370, Cloudflare).
func backtickParens(p string) string {
	return simpleCallRe.ReplaceAllString(p, "$1`$2`")
}

// wafMutators returns the ordered, execution-preserving mutator set for a WAF
// type. An empty type yields nil (caller spends no extra requests); any
// non-empty type — including "generic" — yields a usable set.
func wafMutators(wafType string) []struct {
	name string
	fn   func(string) string
} {
	type m = struct {
		name string
		fn   func(string) string
	}
	slash := m{"slash-sep", func(p string) string { return subSpaces(p, "/") }}
	tab := m{"tab-ws", func(p string) string { return subSpaces(p, "\t") }}
	formfeed := m{"formfeed-ws", func(p string) string { return subSpaces(p, "\x0c") }}
	backtick := m{"backtick-parens", backtickParens}
	upper := m{"upper-tag", upperTagNames}

	switch strings.ToLower(strings.TrimSpace(wafType)) {
	case "":
		return nil
	case "cloudflare":
		return []m{backtick, slash, upper}
	case "aws_waf":
		return []m{formfeed, tab, slash}
	case "modsecurity", "generic":
		return []m{slash, formfeed, backtick, upper}
	case "akamai", "imperva", "f5_bigip", "sucuri":
		return []m{slash, tab, upper}
	default:
		return []m{slash, formfeed, backtick, upper}
	}
}

// MutateForWAF returns execution-preserving evasion variants of payload tuned to
// the detected WAF. It excludes any variant identical to the input (the plain
// payload is assumed to have already been tried). An unknown/empty wafType
// returns nil, so callers spend no extra requests when no WAF was observed.
func MutateForWAF(wafType, payload string) []Variant {
	if payload == "" {
		return nil
	}
	muts := wafMutators(wafType)
	if len(muts) == 0 {
		return nil
	}
	out := make([]Variant, 0, len(muts))
	for _, mu := range muts {
		out = append(out, Variant{Name: mu.name, Value: mu.fn(payload)})
	}
	return dedupeVariants(out, payload)
}
