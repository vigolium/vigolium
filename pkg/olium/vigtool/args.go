package vigtool

import (
	"strings"
	"time"
)

// argsString reads a string argument, trimming whitespace. Returns empty
// when the key is missing or not a string.
func argsString(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return strings.TrimSpace(v)
}

// argsStringArray reads a []string from the JSON-decoded args map. Both
// concrete []string and the more common []any-of-strings (after JSON
// unmarshal) are accepted. Empty / non-string entries are dropped.
func argsStringArray(args map[string]any, key string) []string {
	switch raw := args[key].(type) {
	case []string:
		out := make([]string, 0, len(raw))
		for _, s := range raw {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(raw))
		for _, x := range raw {
			if s, ok := x.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	return nil
}

// argsBool reads a bool argument. Missing / wrong-typed = false.
func argsBool(args map[string]any, key string) bool {
	b, _ := args[key].(bool)
	return b
}

// argsInt reads an integer argument. JSON decoders surface numbers as
// float64 by default, so we unwrap whichever shape arrived.
func argsInt(args map[string]any, key string) int {
	switch n := args[key].(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}

// argsIntArray reads an []int from JSON-decoded args. Accepts []float64
// (JSON default), []int, and []any-of-numbers. Non-numeric entries are
// silently dropped.
func argsIntArray(args map[string]any, key string) []int {
	switch raw := args[key].(type) {
	case []int:
		out := make([]int, 0, len(raw))
		return append(out, raw...)
	case []float64:
		out := make([]int, 0, len(raw))
		for _, n := range raw {
			out = append(out, int(n))
		}
		return out
	case []any:
		out := make([]int, 0, len(raw))
		for _, x := range raw {
			switch n := x.(type) {
			case float64:
				out = append(out, int(n))
			case int:
				out = append(out, n)
			case int64:
				out = append(out, int(n))
			}
		}
		return out
	}
	return nil
}

// formatRFC3339 returns t in UTC RFC3339, or "" for the zero value. Used by
// every summarize* helper in this package — extracted so the IsZero guard
// isn't copy-pasted six times.
func formatRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
