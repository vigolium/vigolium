package tag

import (
	"bytes"
	"regexp"
)

// ErrorPageMatcher detects error messages and stack traces in response body.
type ErrorPageMatcher struct {
	// Patterns for stack traces and error messages
	stackTracePatterns []*regexp.Regexp

	// Pre-lowercased keywords for fast substring checks (no allocations in Match)
	errorKeywords [][]byte
}

// NewErrorPageMatcher creates a new error page matcher.
func NewErrorPageMatcher() *ErrorPageMatcher {
	return &ErrorPageMatcher{
		stackTracePatterns: []*regexp.Regexp{
			// Java/JVM stack traces
			regexp.MustCompile(`(?i)at [a-z0-9_.$]+\([^)]+\.java:\d+\)`),
			regexp.MustCompile(`(?i)java\.(lang|io|util|sql)\.[A-Z][a-zA-Z]+Exception`),
			regexp.MustCompile(`(?i)org\.springframework\.[a-z.]+Exception`),
			regexp.MustCompile(`(?i)javax\.[a-z.]+Exception`),

			// Python stack traces
			regexp.MustCompile(`(?i)File "[^"]+\.py", line \d+`),
			regexp.MustCompile(`(?i)Traceback \(most recent call last\)`),
			regexp.MustCompile(`(?i)(ValueError|TypeError|KeyError|AttributeError|ImportError|RuntimeError|NameError|IndexError|ZeroDivisionError):`),

			// PHP stack traces
			regexp.MustCompile(`(?i)Fatal error:.*on line \d+`),
			regexp.MustCompile(`(?i)Stack trace:[\s\S]{0,100}#\d+ `),
			regexp.MustCompile(`(?i)PHP (Warning|Error|Notice|Fatal error|Parse error):`),
			regexp.MustCompile(`(?i)Uncaught (Exception|Error|TypeError) in`),

			// .NET/C# stack traces
			regexp.MustCompile(`(?i)at [A-Za-z0-9_.<>]+\([^)]*\) in [^:]+:\s*line \d+`),
			regexp.MustCompile(`(?i)System\.(NullReferenceException|ArgumentException|InvalidOperationException|FormatException)`),
			regexp.MustCompile(`(?i)Microsoft\.[A-Za-z.]+Exception`),

			// Node.js/JavaScript stack traces
			regexp.MustCompile(`(?i)at [A-Za-z0-9_.<>$]+ \([^)]+:\d+:\d+\)`),
			regexp.MustCompile(`(?i)(TypeError|ReferenceError|SyntaxError|RangeError|URIError): `),
			regexp.MustCompile(`(?i)at (Object|Module|Function)\.<anonymous>`),

			// Ruby stack traces
			regexp.MustCompile(`(?i)[^:]+\.rb:\d+:in `),
			regexp.MustCompile(`(?i)(NoMethodError|NameError|ArgumentError|RuntimeError|StandardError): `),

			// Go stack traces
			regexp.MustCompile(`(?i)goroutine \d+ \[`),
			regexp.MustCompile(`\t[a-zA-Z0-9_/]+\.go:\d+`),
			regexp.MustCompile(`(?i)panic: `),
			regexp.MustCompile(`(?i)runtime error:`),

			// SQL errors
			regexp.MustCompile(`(?i)SQL syntax.*MySQL`),
			regexp.MustCompile(`(?i)ORA-\d{5}:`), // Oracle
			regexp.MustCompile(`(?i)SQLSTATE\[\w+\]`),
			regexp.MustCompile(`(?i)pg_query\(\): Query failed`), // PostgreSQL
			regexp.MustCompile(`(?i)sqlite3?\.OperationalError`), // SQLite
			regexp.MustCompile(`(?i)Incorrect syntax near`),      // SQL Server
			regexp.MustCompile(`(?i)You have an error in your SQL syntax`),

			// Generic debug/error patterns
			regexp.MustCompile(`(?i)<b>(Warning|Fatal error|Parse error)</b>:`),
			regexp.MustCompile(`(?i)ASPNETCORE_ENVIRONMENT.*Development`),
			regexp.MustCompile(`(?i)Laravel.*Exception`),
			regexp.MustCompile(`(?i)Django.*Error`),
		},
		// Pre-lowercased keywords for O(1) comparison (no allocation in Match)
		errorKeywords: [][]byte{
			[]byte("exception in thread"),
			[]byte("unhandled exception"),
			[]byte("stack trace"),
			[]byte("internal server error"),
			[]byte("debug mode is on"),
			[]byte("development mode"),
			[]byte("django_settings_module"),
			[]byte("debug = true"),
			[]byte("web-inf/"),
			[]byte("vendor/autoload.php"),
			[]byte("node_modules/"),
			[]byte("__pycache__"),
			[]byte("document_root"),
			[]byte("server_software"),
			[]byte("call stack"),
			[]byte("undefined variable"),
			[]byte("undefined index"),
			[]byte("cannot read property"),
			[]byte("is not defined"),
			[]byte("nullpointerexception"),
			[]byte("stackoverflowerror"),
			[]byte("outofmemoryerror"),
		},
	}
}

// Tag returns the tag this matcher detects.
func (m *ErrorPageMatcher) Tag() Tag {
	return TagErrorPage
}

// Match returns true if error page indicators found in response body.
func (m *ErrorPageMatcher) Match(input *MatchInput) bool {
	// Only check response body (errors are in responses)
	if len(input.ResponseBody) == 0 {
		return false
	}

	body := input.ResponseBody

	// Fast path: check simple keywords first (case-insensitive)
	// Keywords are pre-lowercased in constructor - no allocation per keyword
	bodyLower := bytes.ToLower(body)
	for _, keyword := range m.errorKeywords {
		if bytes.Contains(bodyLower, keyword) {
			return true
		}
	}

	// Regex patterns for stack traces
	for _, pattern := range m.stackTracePatterns {
		if pattern.Match(body) {
			return true
		}
	}

	return false
}

// Ensure ErrorPageMatcher implements TagMatcher
var _ TagMatcher = (*ErrorPageMatcher)(nil)
