package mcp_server_probe

import "encoding/json"

// generateSampleArgs generates sample argument values for a tool based on its inputSchema.
func generateSampleArgs(schema json.RawMessage) map[string]any {
	if len(schema) == 0 {
		return map[string]any{}
	}

	var s jsonSchema
	if err := json.Unmarshal(schema, &s); err != nil {
		return map[string]any{}
	}

	args := make(map[string]any)
	for name, prop := range s.Properties {
		args[name] = sampleValue(name, prop)
	}
	return args
}

func sampleValue(name string, s jsonSchema) any {
	if len(s.Enum) > 0 {
		return s.Enum[0]
	}

	switch s.Type {
	case "string":
		return sampleString(name, s.Format)
	case "number", "float":
		return 42.0
	case "integer":
		return 1
	case "boolean":
		return true
	case "array":
		if s.Items != nil {
			return []any{sampleValue("item", *s.Items)}
		}
		return []any{"test"}
	case "object":
		obj := make(map[string]any)
		for k, v := range s.Properties {
			obj[k] = sampleValue(k, v)
		}
		if len(obj) == 0 {
			obj["key"] = "value"
		}
		return obj
	default:
		return "test"
	}
}

func sampleString(name, format string) string {
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

	// Heuristic by parameter name
	nameLower := name
	switch {
	case contains(nameLower, "email"):
		return "test@example.com"
	case contains(nameLower, "url", "uri", "link", "href"):
		return "https://example.com"
	case contains(nameLower, "date"):
		return "2025-01-01"
	case contains(nameLower, "time"):
		return "2025-01-01T00:00:00Z"
	case contains(nameLower, "id", "uuid"):
		return "1"
	case contains(nameLower, "name"):
		return "test"
	case contains(nameLower, "query", "search", "q"):
		return "test"
	case contains(nameLower, "path", "file", "dir"):
		return "/tmp/test"
	case contains(nameLower, "host", "domain"):
		return "example.com"
	case contains(nameLower, "port"):
		return "8080"
	case contains(nameLower, "ip", "address"):
		return "127.0.0.1"
	case contains(nameLower, "password", "secret", "token", "key"):
		return "test-token-value"
	case contains(nameLower, "count", "limit", "offset", "page", "size"):
		return "10"
	case contains(nameLower, "city", "location"):
		return "London"
	case contains(nameLower, "country"):
		return "US"
	case contains(nameLower, "lang", "language", "locale"):
		return "en"
	default:
		return "test"
	}
}

func contains(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
