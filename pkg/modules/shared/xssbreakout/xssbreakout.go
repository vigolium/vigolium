// Package xssbreakout builds executable XSS breakout payloads shared across the
// reflected, DOM-confirm, and stored XSS modules so they confirm the same
// classes of flaw with one source of truth.
package xssbreakout

// JSStringPayloads returns executable breakout payloads for a value reflected
// inside a quote-delimited JavaScript string literal (quote is '\'' or '"').
//
// It pairs operator-chaining breaks with the classic statement-terminator break.
// Operator chaining is the important part: when the reflected string sits inside
// an *expression* — a function argument, array, or object literal such as
// foo('HERE') or {k:'HERE'} — closing the string and injecting a statement
// terminator (';alert()//') produces a SyntaxError that aborts the whole
// <script>, so the alert never runs. Chaining the call into the surrounding
// expression with a binary operator keeps it syntactically valid and executes:
//
//	'weuci' ^ alert(1) ^ 'dsjiy'   →  one valid expression, alert fires.
//
// The leading quote closes the original string; the trailing quote re-opens one
// so the original closing quote still balances.
//
// alertExpr is the JavaScript to execute, e.g. alert(`canary`) (use a template
// literal so the canary's quoting never collides with the breakout quote).
//
// Payloads are ordered most-general first: operator chaining executes in both
// statement and expression position, while the terminator is a fallback for the
// rare filter that strips the chaining operators but keeps ';'.
func JSStringPayloads(quote byte, alertExpr string) []string {
	q := string(quote)
	return []string{
		q + "^" + alertExpr + "^" + q, // bitwise XOR — rarely filtered
		q + "-" + alertExpr + "-" + q, // subtraction — the dalfox classic
		q + ";" + alertExpr + "//",    // statement terminator — fallback
	}
}
