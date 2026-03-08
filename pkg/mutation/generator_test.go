package mutation

import (
	"strings"
	"testing"
)

func TestGenerate_Integer(t *testing.T) {
	ms := Generate("123", TypeInteger, nil)
	if ms.DetectedType != TypeInteger {
		t.Errorf("DetectedType = %v, want TypeInteger", ms.DetectedType)
	}
	if len(ms.Mutations) == 0 {
		t.Fatal("expected mutations for integer")
	}

	assertContainsValue(t, ms.Mutations, "124", "increment by 1")
	assertContainsValue(t, ms.Mutations, "122", "decrement by 1")
	assertContainsValue(t, ms.Mutations, "0", "zero")
	assertContainsValue(t, ms.Mutations, "2147483647", "MAX_INT32")
	assertContainsValue(t, ms.Mutations, "-2147483648", "MIN_INT32")
}

func TestGenerate_Integer_SchemaHintBounds(t *testing.T) {
	max := 1000.0
	min := 0.0
	ms := Generate("500", TypeInteger, &GenerateOptions{
		Intents:      []MutationIntent{IntentBoundary},
		MaxPerIntent: 10,
		SchemaHint:   &SchemaHint{Maximum: &max, Minimum: &min},
	})
	assertContainsValue(t, ms.Mutations, "1001", "above schema max")
	assertContainsValue(t, ms.Mutations, "-1", "below schema min")
}

func TestGenerate_Float(t *testing.T) {
	ms := Generate("9.99", TypeFloat, nil)
	if len(ms.Mutations) == 0 {
		t.Fatal("expected mutations for float")
	}
	assertContainsValue(t, ms.Mutations, "10", "increment by 0.01 (~10.0)")
	assertContainsValue(t, ms.Mutations, "0.0", "zero")
	assertContainsValue(t, ms.Mutations, "Infinity", "infinity")
}

func TestGenerate_Boolean(t *testing.T) {
	ms := Generate("true", TypeBoolean, nil)
	assertContainsValue(t, ms.Mutations, "false", "opposite value")
	assertContainsValue(t, ms.Mutations, "0", "numeric false")
	assertContainsValue(t, ms.Mutations, "no", "no")

	ms2 := Generate("false", TypeBoolean, nil)
	assertContainsValue(t, ms2.Mutations, "true", "opposite value")
	assertContainsValue(t, ms2.Mutations, "1", "numeric true")
}

func TestGenerate_UUID(t *testing.T) {
	ms := Generate("550e8400-e29b-41d4-a716-446655440000", TypeUUID, nil)
	assertContainsValue(t, ms.Mutations, "00000000-0000-0000-0000-000000000000", "nil UUID")

	// Check that no-dashes variant exists
	found := false
	for _, m := range ms.Mutations {
		if !strings.Contains(m.Value, "-") && len(m.Value) == 32 && m.Intent == IntentFormat {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected without-dashes UUID variant")
	}
}

func TestGenerate_Email(t *testing.T) {
	ms := Generate("john@example.com", TypeEmail, nil)
	assertContainsValue(t, ms.Mutations, "john+1@example.com", "plus addressing")
	assertContainsValue(t, ms.Mutations, "admin@example.com", "admin email")
	assertContainsValue(t, ms.Mutations, "root@example.com", "root email")
}

func TestGenerate_Timestamp(t *testing.T) {
	ms := Generate("2026-01-15T10:30:00Z", TypeTimestamp, nil)
	assertContainsValue(t, ms.Mutations, "1970-01-01T00:00:00Z", "epoch")
	assertContainsValue(t, ms.Mutations, "2099-12-31T23:59:59Z", "far future")
	// Check neighbor days
	assertContainsValue(t, ms.Mutations, "2026-01-14T10:30:00Z", "minus 1 day")
	assertContainsValue(t, ms.Mutations, "2026-01-16T10:30:00Z", "plus 1 day")
}

func TestGenerate_Date(t *testing.T) {
	ms := Generate("2026-01-15", TypeDate, nil)
	assertContainsValue(t, ms.Mutations, "2026-01-14", "minus 1 day")
	assertContainsValue(t, ms.Mutations, "2026-01-16", "plus 1 day")
	assertContainsValue(t, ms.Mutations, "1970-01-01", "epoch date")
}

func TestGenerate_IPv4(t *testing.T) {
	ms := Generate("192.168.1.10", TypeIPv4, nil)
	assertContainsValue(t, ms.Mutations, "192.168.1.11", "last octet +1")
	assertContainsValue(t, ms.Mutations, "192.168.1.9", "last octet -1")
	assertContainsValue(t, ms.Mutations, "127.0.0.1", "localhost")
	assertContainsValue(t, ms.Mutations, "10.0.0.1", "internal")
	assertContainsValue(t, ms.Mutations, "255.255.255.255", "broadcast")
}

func TestGenerate_Path(t *testing.T) {
	ms := Generate("/api/v1/users", TypePath, nil)
	assertContainsValue(t, ms.Mutations, "/api/v1/users/", "trailing slash")
	assertContainsValue(t, ms.Mutations, "/api/v1/users.json", "JSON extension")
	assertContainsValue(t, ms.Mutations, "/api/v1/users/..", "path traversal")
	assertContainsValue(t, ms.Mutations, "/api/v2/users", "version increment")
}

func TestGenerate_SequentialID(t *testing.T) {
	ms := Generate("1001", TypeSequentialID, nil)
	assertContainsValue(t, ms.Mutations, "1002", "increment by 1")
	assertContainsValue(t, ms.Mutations, "1000", "decrement by 1")
	assertContainsValue(t, ms.Mutations, "1", "ID=1 (often admin)")
	assertContainsValue(t, ms.Mutations, "0", "ID=0")
	assertContainsValue(t, ms.Mutations, "2147483647", "MAX_INT32")
}

func TestGenerate_StructuredCode(t *testing.T) {
	ms := Generate("ORD-00042", TypeStructuredCode, nil)
	assertContainsValue(t, ms.Mutations, "ORD-00041", "decrement")
	assertContainsValue(t, ms.Mutations, "ORD-00043", "increment")
	assertContainsValue(t, ms.Mutations, "ORD-00000", "zeroed")
}

func TestGenerate_Enum(t *testing.T) {
	ms := Generate("user", TypeEnum, &GenerateOptions{
		SchemaHint: &SchemaHint{
			Enum: []string{"viewer", "user", "editor", "admin"},
		},
	})
	assertContainsValue(t, ms.Mutations, "editor", "next enum")
	assertContainsValue(t, ms.Mutations, "viewer", "prev enum")
	assertContainsValue(t, ms.Mutations, "admin", "escalation")
}

func TestGenerate_Enum_CommonEscalation(t *testing.T) {
	ms := Generate("viewer", TypeEnum, nil)
	assertContainsValue(t, ms.Mutations, "admin", "escalation")
}

func TestGenerate_URL(t *testing.T) {
	ms := Generate("https://example.com/callback", TypeURL, nil)
	assertContainsValue(t, ms.Mutations, "http://127.0.0.1/", "localhost")
	assertContainsValue(t, ms.Mutations, "http://169.254.169.254/", "cloud metadata")
	assertContainsValue(t, ms.Mutations, "http://example.com/callback", "protocol downgrade")
}

func TestGenerate_JWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	ms := Generate(jwt, TypeJWT, nil)
	// Should have alg:none variant
	found := false
	for _, m := range ms.Mutations {
		if strings.Contains(m.Label, "alg:none") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected alg:none JWT variant")
	}
}

func TestGenerate_JSON(t *testing.T) {
	ms := Generate(`{"role":"user"}`, TypeJSON, nil)
	// admin:true injected
	found := false
	for _, m := range ms.Mutations {
		if strings.Contains(m.Value, "admin") && m.Intent == IntentFormat {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected admin:true injected JSON variant")
	}
	assertContainsValue(t, ms.Mutations, "{}", "empty object")
	assertContainsValue(t, ms.Mutations, "[]", "empty array")
}

func TestGenerate_Empty(t *testing.T) {
	ms := Generate("", TypeEmpty, &GenerateOptions{MaxPerIntent: 10})
	if len(ms.Mutations) == 0 {
		t.Fatal("expected mutations for empty")
	}
	assertContainsValue(t, ms.Mutations, "null", "null")
	assertContainsValue(t, ms.Mutations, "undefined", "undefined")
	assertContainsValue(t, ms.Mutations, "0", "zero")
}

func TestGenerate_Unknown(t *testing.T) {
	ms := Generate("randomvalue", TypeUnknown, &GenerateOptions{MaxPerIntent: 10})
	assertContainsValue(t, ms.Mutations, "null", "null")
	assertContainsValue(t, ms.Mutations, "0", "zero")
}

func TestGenerate_MaxPerIntent(t *testing.T) {
	ms := Generate("123", TypeInteger, &GenerateOptions{MaxPerIntent: 2})
	intentCounts := make(map[MutationIntent]int)
	for _, m := range ms.Mutations {
		intentCounts[m.Intent]++
	}
	for intent, count := range intentCounts {
		if count > 2 {
			t.Errorf("intent %v has %d mutations, expected max 2", intent, count)
		}
	}
}

func TestGenerate_FilteredIntents(t *testing.T) {
	ms := Generate("123", TypeInteger, &GenerateOptions{
		Intents: []MutationIntent{IntentNeighbor},
	})
	for _, m := range ms.Mutations {
		if m.Intent != IntentNeighbor {
			t.Errorf("got intent %v, expected only IntentNeighbor", m.Intent)
		}
	}
}

func TestGenerate_NoOriginalValueInResults(t *testing.T) {
	ms := Generate("123", TypeInteger, nil)
	for _, m := range ms.Mutations {
		if m.Value == "123" {
			t.Errorf("mutation set should not contain original value '123'")
		}
	}
}

func TestGenerate_Slug(t *testing.T) {
	ms := Generate("my-blog-post", TypeSlug, nil)
	assertContainsValue(t, ms.Mutations, "my-blog-post-2", "appended -2")
	assertContainsValue(t, ms.Mutations, "admin", "admin slug")
}

func TestGenerate_HexEncoded(t *testing.T) {
	ms := Generate("4a6f686e446f6531", TypeHexEncoded, nil)
	if len(ms.Mutations) == 0 {
		t.Fatal("expected mutations for hex")
	}
	// uppercase variant
	found := false
	for _, m := range ms.Mutations {
		if m.Value == "4A6F686E446F6531" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected uppercase hex variant")
	}
}

// assertContainsValue checks that at least one mutation has the given value.
func assertContainsValue(t *testing.T, mutations []Mutation, value string, description string) {
	t.Helper()
	for _, m := range mutations {
		if m.Value == value {
			return
		}
	}
	t.Errorf("expected mutation with value %q (%s) not found in %d mutations", value, description, len(mutations))
}
