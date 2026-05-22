package clicommon

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// ansiEscapeRe matches ANSI SGR color escape sequences.
var ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Truncate shortens s to maxLen characters, appending "..." when it overflows.
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// VisibleLen returns the length of s ignoring ANSI color escape sequences.
func VisibleLen(s string) int {
	return len(ansiEscapeRe.ReplaceAllString(s, ""))
}

// TruncateVisible shortens s to maxLen visible characters (ANSI escapes are not
// counted), appending "…" when it overflows.
func TruncateVisible(s string, maxLen int) string {
	if VisibleLen(s) <= maxLen {
		return s
	}
	plain := ansiEscapeRe.ReplaceAllString(s, "")
	if len(plain) <= maxLen {
		return s
	}
	return plain[:maxLen-1] + "…"
}

// ColorSeverity renders a severity label with its conventional color.
func ColorSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return terminal.BoldMagenta(sev)
	case "high":
		return terminal.BoldRed(sev)
	case "medium":
		return terminal.BoldYellow(sev)
	case "low":
		return terminal.Green(sev)
	case "info":
		return terminal.BoldBlue(sev)
	default:
		return sev
	}
}

// FormatSeverityWithSymbols renders a one-line summary of severity counts using
// per-severity symbols, omitting zero-count severities.
func FormatSeverityWithSymbols(counts map[string]int) string {
	type sevEntry struct {
		symbol string
		count  int
		label  string
	}
	entries := []sevEntry{
		{terminal.CriticalSymbol(), counts["critical"], "critical"},
		{terminal.HighSymbol(), counts["high"], "high"},
		{terminal.MediumSymbol(), counts["medium"], "medium"},
		{terminal.LowSymbol(), counts["low"], "low"},
		{terminal.SuspectSymbol(), counts["suspect"], "suspect"},
		{terminal.InfoSeveritySymbol(), counts["info"], "info"},
	}

	var parts []string
	for _, e := range entries {
		if e.count > 0 {
			parts = append(parts, fmt.Sprintf("%s %d %s", e.symbol, e.count, e.label))
		}
	}
	return strings.Join(parts, ", ")
}

// ValueOrNone returns s, or "(none)" when s is empty.
func ValueOrNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// ParseDate parses a date in YYYY-MM-DD or RFC3339 form.
func ParseDate(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02", s)
	if err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

// FormatTokenCount renders a numeric token count with K/M suffixes.
func FormatTokenCount(v interface{}) string {
	var n float64
	switch x := v.(type) {
	case float64:
		n = x
	case int:
		n = float64(x)
	case int64:
		n = float64(x)
	default:
		return fmt.Sprintf("%v", v)
	}
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", n/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", n/1_000)
	}
	return fmt.Sprintf("%d", int64(n))
}

// FormatFileSize renders a byte count with B/KB/MB units.
func FormatFileSize(bytes int64) string {
	switch {
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// PluralSuffix returns "" for a count of 1, otherwise "s".
func PluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

// SplitCSV splits a comma-separated string, trimming blanks. Empty input yields nil.
func SplitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// CSVEscape quotes and escapes s for CSV output when it contains commas,
// quotes, or newlines.
func CSVEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return fmt.Sprintf("\"%s\"", strings.ReplaceAll(s, "\"", "\"\""))
	}
	return s
}
