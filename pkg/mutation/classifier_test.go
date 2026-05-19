package mutation

import (
	"testing"
)

func TestClassify_Empty(t *testing.T) {
	if got := Classify("", nil); got != TypeEmpty {
		t.Errorf("Classify('') = %v, want TypeEmpty", got)
	}
}

func TestClassify_Boolean(t *testing.T) {
	tests := []string{"true", "false", "True", "FALSE", "yes", "no", "on", "off"}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeBoolean {
			t.Errorf("Classify(%q) = %v, want TypeBoolean", v, got)
		}
	}
}

func TestClassify_UUID(t *testing.T) {
	tests := []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		"F47AC10B-58CC-4372-A567-0E02B2C3D479",
	}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeUUID {
			t.Errorf("Classify(%q) = %v, want TypeUUID", v, got)
		}
	}
}

func TestClassify_JWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	if got := Classify(jwt, nil); got != TypeJWT {
		t.Errorf("Classify(jwt) = %v, want TypeJWT", got)
	}
}

func TestClassify_Email(t *testing.T) {
	tests := []string{"user@example.com", "admin@test.org", "john.doe@sub.domain.co.uk"}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeEmail {
			t.Errorf("Classify(%q) = %v, want TypeEmail", v, got)
		}
	}
}

func TestClassify_IPv4(t *testing.T) {
	tests := []string{"192.168.1.10", "10.0.0.1", "127.0.0.1", "255.255.255.255"}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeIPv4 {
			t.Errorf("Classify(%q) = %v, want TypeIPv4", v, got)
		}
	}
	// Invalid
	if got := Classify("999.999.999.999", nil); got == TypeIPv4 {
		t.Errorf("Classify('999.999.999.999') = TypeIPv4, want something else")
	}
}

func TestClassify_IPv6(t *testing.T) {
	tests := []string{"::1", "fe80::1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeIPv6 {
			t.Errorf("Classify(%q) = %v, want TypeIPv6", v, got)
		}
	}
}

func TestClassify_Timestamp(t *testing.T) {
	tests := []string{
		"2026-01-15T10:30:00Z",
		"2026-01-15T10:30:00+05:30",
		"2026-01-15 10:30:00",
	}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeTimestamp {
			t.Errorf("Classify(%q) = %v, want TypeTimestamp", v, got)
		}
	}
}

func TestClassify_Date(t *testing.T) {
	tests := []string{"2026-01-15", "2025-12-31", "2000-01-01"}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeDate {
			t.Errorf("Classify(%q) = %v, want TypeDate", v, got)
		}
	}
}

func TestClassify_StructuredCode(t *testing.T) {
	tests := []string{"ORD-00042", "INV-2024-001", "REF-12345"}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeStructuredCode {
			t.Errorf("Classify(%q) = %v, want TypeStructuredCode", v, got)
		}
	}
}

func TestClassify_PhoneNumber(t *testing.T) {
	tests := []string{"+1-555-123-4567", "+44 20 7946 0958", "15551234567"}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypePhoneNumber {
			t.Errorf("Classify(%q) = %v, want TypePhoneNumber", v, got)
		}
	}
}

func TestClassify_CreditCard(t *testing.T) {
	// Valid Luhn numbers
	tests := []string{"4532015112830366", "5425233430109903"}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeCreditCard {
			t.Errorf("Classify(%q) = %v, want TypeCreditCard", v, got)
		}
	}
}

func TestClassify_Float(t *testing.T) {
	tests := []string{"3.14", "0.001", "-9.99", "123.456"}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeFloat {
			t.Errorf("Classify(%q) = %v, want TypeFloat", v, got)
		}
	}
}

func TestClassify_Integer(t *testing.T) {
	tests := []string{"123", "0", "-5", "999999"}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeInteger {
			t.Errorf("Classify(%q) = %v, want TypeInteger", v, got)
		}
	}
}

func TestClassify_SequentialID(t *testing.T) {
	hint := &SchemaHint{ParamName: "user_id"}
	if got := Classify("1001", hint); got != TypeSequentialID {
		t.Errorf("Classify('1001', user_id) = %v, want TypeSequentialID", got)
	}

	hint2 := &SchemaHint{ParamName: "id"}
	if got := Classify("42", hint2); got != TypeSequentialID {
		t.Errorf("Classify('42', id) = %v, want TypeSequentialID", got)
	}

	hint3 := &SchemaHint{ParamName: "accountId"}
	if got := Classify("100", hint3); got != TypeSequentialID {
		t.Errorf("Classify('100', accountId) = %v, want TypeSequentialID", got)
	}
}

func TestClassify_URL(t *testing.T) {
	tests := []string{
		"https://example.com/callback",
		"http://localhost:8080/api",
	}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeURL {
			t.Errorf("Classify(%q) = %v, want TypeURL", v, got)
		}
	}
}

func TestClassify_JSON(t *testing.T) {
	tests := []string{
		`{"key":"value"}`,
		`[1,2,3]`,
		`{"nested":{"a":1}}`,
	}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeJSON {
			t.Errorf("Classify(%q) = %v, want TypeJSON", v, got)
		}
	}
}

func TestClassify_Path(t *testing.T) {
	tests := []string{"/api/v1/users", "/test/path", "/admin/dashboard"}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypePath {
			t.Errorf("Classify(%q) = %v, want TypePath", v, got)
		}
	}
}

func TestClassify_Slug(t *testing.T) {
	tests := []string{"my-blog-post", "user_profile_page", "test-item-123"}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeSlug {
			t.Errorf("Classify(%q) = %v, want TypeSlug", v, got)
		}
	}
}

func TestClassify_Enum_WithHint(t *testing.T) {
	hint := &SchemaHint{
		Enum: []string{"low", "medium", "high", "critical"},
	}
	if got := Classify("medium", hint); got != TypeEnum {
		t.Errorf("Classify('medium', enum hint) = %v, want TypeEnum", got)
	}
}

func TestClassify_Enum_FromParamName(t *testing.T) {
	hint := &SchemaHint{ParamName: "role"}
	if got := Classify("viewer", hint); got != TypeEnum {
		t.Errorf("Classify('viewer', role) = %v, want TypeEnum", got)
	}

	hint2 := &SchemaHint{ParamName: "status"}
	if got := Classify("active", hint2); got != TypeEnum {
		t.Errorf("Classify('active', status) = %v, want TypeEnum", got)
	}
}

func TestClassify_SchemaHint_FormatOverride(t *testing.T) {
	tests := []struct {
		format string
		want   ValueType
	}{
		{"uuid", TypeUUID},
		{"email", TypeEmail},
		{"date-time", TypeTimestamp},
		{"date", TypeDate},
		{"uri", TypeURL},
		{"ipv4", TypeIPv4},
		{"ipv6", TypeIPv6},
	}
	for _, tt := range tests {
		hint := &SchemaHint{Format: tt.format}
		if got := Classify("anything", hint); got != tt.want {
			t.Errorf("Classify with format=%q: got %v, want %v", tt.format, got, tt.want)
		}
	}
}

func TestClassify_SchemaHint_TypeOverride(t *testing.T) {
	hint := &SchemaHint{Type: "integer"}
	if got := Classify("not-a-number", hint); got != TypeInteger {
		t.Errorf("Classify with type=integer: got %v, want TypeInteger", got)
	}

	hint2 := &SchemaHint{Type: "boolean"}
	if got := Classify("maybe", hint2); got != TypeBoolean {
		t.Errorf("Classify with type=boolean: got %v, want TypeBoolean", got)
	}
}

func TestClassify_Unknown(t *testing.T) {
	tests := []string{"foobar", "random string here", "x"}
	for _, v := range tests {
		if got := Classify(v, nil); got != TypeUnknown {
			t.Errorf("Classify(%q) = %v, want TypeUnknown", v, got)
		}
	}
}

func TestClassify_HexEncoded(t *testing.T) {
	// 16+ hex chars, even length
	hex := "4a6f686e446f6531"
	if got := Classify(hex, nil); got != TypeHexEncoded {
		t.Errorf("Classify(%q) = %v, want TypeHexEncoded", hex, got)
	}
}

func TestLuhnCheck(t *testing.T) {
	if !luhnCheck("4532015112830366") {
		t.Error("luhnCheck should pass for valid card number")
	}
	if luhnCheck("1234567890123456") {
		t.Error("luhnCheck should fail for invalid card number")
	}
}
