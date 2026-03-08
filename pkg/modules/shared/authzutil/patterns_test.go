package authzutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHighSignalNames(t *testing.T) {
	for _, name := range []string{"id", "uid", "user_id", "account_id", "order_id", "session_id"} {
		_, ok := HighSignalNames[name]
		assert.True(t, ok, "expected %q in HighSignalNames", name)
	}
	// camelCase lowered forms
	for _, name := range []string{"userid", "accountid", "orderid"} {
		_, ok := HighSignalNames[name]
		assert.True(t, ok, "expected %q in HighSignalNames", name)
	}
}

func TestMediumSignalNames(t *testing.T) {
	for _, name := range []string{"num", "number", "ref", "key", "token", "uuid", "guid"} {
		_, ok := MediumSignalNames[name]
		assert.True(t, ok, "expected %q in MediumSignalNames", name)
	}
}

func TestSequentialIntPattern(t *testing.T) {
	assert.True(t, SequentialIntPattern.MatchString("1"))
	assert.True(t, SequentialIntPattern.MatchString("42"))
	assert.True(t, SequentialIntPattern.MatchString("1234567890"))
	assert.False(t, SequentialIntPattern.MatchString("12345678901")) // 11 digits
	assert.False(t, SequentialIntPattern.MatchString("abc"))
	assert.False(t, SequentialIntPattern.MatchString(""))
}

func TestStructuredCodePattern(t *testing.T) {
	assert.True(t, StructuredCodePattern.MatchString("ORD-12345"))
	assert.True(t, StructuredCodePattern.MatchString("INV-001-2"))
	assert.True(t, StructuredCodePattern.MatchString("A-123"))
	assert.False(t, StructuredCodePattern.MatchString("12345"))
	assert.False(t, StructuredCodePattern.MatchString("TOOLONG-12"))
	assert.False(t, StructuredCodePattern.MatchString("ORD-12"))
}

func TestUUIDPatterns(t *testing.T) {
	assert.True(t, UUIDv1Pattern.MatchString("550e8400-e29b-11d4-a716-446655440000"))
	assert.False(t, UUIDv1Pattern.MatchString("550e8400-e29b-41d4-a716-446655440000"))

	assert.True(t, UUIDv4Pattern.MatchString("550e8400-e29b-41d4-a716-446655440000"))
	assert.False(t, UUIDv4Pattern.MatchString("550e8400-e29b-11d4-a716-446655440000"))
}

func TestHexPattern(t *testing.T) {
	assert.True(t, HexPattern.MatchString("0123456789abcdef"))  // 16 chars
	assert.True(t, HexPattern.MatchString("abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567")) // 62 chars (within 16-64)
	assert.False(t, HexPattern.MatchString("0123456789abcde"))  // 15 chars
	assert.False(t, HexPattern.MatchString("xyz123456789abcd")) // non-hex chars
}

func TestEmailPattern(t *testing.T) {
	assert.True(t, EmailPattern.MatchString("user@example.com"))
	assert.True(t, EmailPattern.MatchString("test.user+tag@sub.domain.org"))
	assert.False(t, EmailPattern.MatchString("notanemail"))
	assert.False(t, EmailPattern.MatchString("@missing.com"))
}

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"userId", "user_id"},
		{"user-id", "user_id"},
		{"user_id", "user_id"},
		{"USER_ID", "user_id"},
		{"accountId", "account_id"},
		{"OrderID", "order_id"},
		{"id", "id"},
		{"ID", "id"},
		{"simpleword", "simpleword"},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.expected, NormalizeName(tc.input), "NormalizeName(%q)", tc.input)
	}
}

func TestNameSignalString(t *testing.T) {
	assert.Equal(t, "high", HighSignal.String())
	assert.Equal(t, "medium", MediumSignal.String())
	assert.Equal(t, "none", NoSignal.String())
}

func TestIDTypeString(t *testing.T) {
	assert.Equal(t, "sequential-int", SequentialInt.String())
	assert.Equal(t, "uuid-v4", UUIDv4.String())
	assert.Equal(t, "hex", Hex.String())
	assert.Equal(t, "unknown", Unknown.String())
	assert.Equal(t, "email", Email.String())
	assert.Equal(t, "structured-code", StructuredCode.String())
	assert.Equal(t, "base64-int", Base64Int.String())
}

func TestPredictabilityString(t *testing.T) {
	assert.Equal(t, "very-high", PredictVeryHigh.String())
	assert.Equal(t, "high", PredictHigh.String())
	assert.Equal(t, "medium", PredictMedium.String())
	assert.Equal(t, "low", PredictLow.String())
	assert.Equal(t, "none", PredictNone.String())
}

func TestResourceNouns(t *testing.T) {
	for _, noun := range []string{"users", "accounts", "orders", "profiles", "files", "posts"} {
		_, ok := ResourceNouns[noun]
		assert.True(t, ok, "expected %q in ResourceNouns", noun)
	}
}

func TestSensitiveResponseFields(t *testing.T) {
	for _, field := range []string{"password_hash", "ssn", "is_admin", "permissions"} {
		_, ok := SensitiveResponseFields[field]
		assert.True(t, ok, "expected %q in SensitiveResponseFields", field)
	}
}
