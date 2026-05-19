package mcp

import (
	"encoding/json"
	"strings"
)

// GenerateSampleArgs generates a benign sample-arguments map from a tool's
// inputSchema, suitable for the first probing tools/call. Type-aware: respects
// integer, number, boolean, array, object, plus a small heuristic for common
// string parameter names.
func GenerateSampleArgs(schema json.RawMessage) map[string]any {
	if len(schema) == 0 {
		return map[string]any{}
	}
	var s JSONSchema
	if err := json.Unmarshal(schema, &s); err != nil {
		return map[string]any{}
	}
	args := make(map[string]any, len(s.Properties))
	for name, prop := range s.Properties {
		args[name] = SampleValue(name, prop)
	}
	return args
}

// SampleValue returns a benign sample value for a single JSON Schema property.
func SampleValue(name string, s JSONSchema) any {
	if len(s.Enum) > 0 {
		return s.Enum[0]
	}
	switch s.Type {
	case "string":
		return SampleString(name, s.Format)
	case "number", "float":
		return 42.0
	case "integer":
		return 1
	case "boolean":
		return true
	case "array":
		if s.Items != nil {
			return []any{SampleValue("item", *s.Items)}
		}
		return []any{"test"}
	case "object":
		obj := make(map[string]any)
		for k, v := range s.Properties {
			obj[k] = SampleValue(k, v)
		}
		if len(obj) == 0 {
			obj["key"] = "value"
		}
		return obj
	default:
		return "test"
	}
}

// SampleString picks a default-looking value for a string property based on
// its JSON-Schema format and a name heuristic.
func SampleString(name, format string) string {
	switch format {
	case "date-time":
		return "2025-01-01T00:00:00Z"
	case "date":
		return "2025-01-01"
	case "time":
		return "12:00:00"
	case "email":
		return "test@example.com"
	case "uri", "url":
		return "https://example.com"
	case "uuid":
		return "00000000-0000-0000-0000-000000000000"
	case "ipv4":
		return "127.0.0.1"
	case "ipv6":
		return "::1"
	}
	n := strings.ToLower(name)
	switch {
	case containsAny(n, "email"):
		return "test@example.com"
	case containsAny(n, "url", "uri", "link", "href"):
		return "https://example.com"
	case containsAny(n, "date"):
		return "2025-01-01"
	case containsAny(n, "time"):
		return "2025-01-01T00:00:00Z"
	case containsAny(n, "id", "uuid"):
		return "1"
	case containsAny(n, "name"):
		return "test"
	case containsAny(n, "query", "search"):
		return "test"
	case containsAny(n, "path", "file", "dir"):
		return "/tmp/test"
	case containsAny(n, "host", "domain"):
		return "example.com"
	case containsAny(n, "port"):
		return "8080"
	case containsAny(n, "ip", "address"):
		return "127.0.0.1"
	case containsAny(n, "password", "secret", "token", "key"):
		return "test-token-value"
	case containsAny(n, "count", "limit", "offset", "page", "size"):
		return "10"
	case containsAny(n, "city", "location"):
		return "London"
	case containsAny(n, "country"):
		return "US"
	case containsAny(n, "lang", "language", "locale"):
		return "en"
	default:
		return "test"
	}
}

// PropertyTypeMap returns a flat name→type map for the top-level properties of
// a tool's inputSchema. Used by fuzzers to filter which parameters to mutate.
func PropertyTypeMap(schema json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(schema) == 0 {
		return out
	}
	var s JSONSchema
	if err := json.Unmarshal(schema, &s); err != nil {
		return out
	}
	for name, prop := range s.Properties {
		t := prop.Type
		if t == "" {
			t = "string"
		}
		out[name] = t
	}
	return out
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
