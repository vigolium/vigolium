package form

import (
	"strconv"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

func newTestHandler(mode config.FormFillMode) *Handler {
	return NewHandler(&config.Config{FormFillMode: mode})
}

func detectedInput(t action.InputType, name string) *DetectedInput {
	d := NewDetectedInputWithType(t, action.NewIdentification(action.HowName, name))
	d.Name = name
	return d
}

func TestParseHow(t *testing.T) {
	tests := []struct {
		in   string
		want action.How
	}{
		{"id", action.HowID},
		{"name", action.HowName},
		{"xpath", action.HowXPath},
		{"unknown", action.HowID}, // default
	}
	for _, tt := range tests {
		if got := parseHow(tt.in); got != tt.want {
			t.Errorf("parseHow(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestIdentificationKey(t *testing.T) {
	if got := identificationKey("id", "user"); got != "id:user" {
		t.Errorf("identificationKey = %q, want %q", got, "id:user")
	}
}

func TestNewHandlerLoadsFormInputConfigs(t *testing.T) {
	cfg := &config.Config{
		FormFillMode: config.FormFillNormal,
		FormInputs: []config.FormInputConfig{
			{How: "id", Value: "user", Type: "text", Values: []string{"alice", "1"}},
		},
	}
	h := NewHandler(cfg)
	if len(h.inputConfigs) != 1 {
		t.Fatalf("inputConfigs len = %d, want 1", len(h.inputConfigs))
	}
	cfgInput := h.inputConfigs["id:user"]
	if cfgInput == nil {
		t.Fatal("expected input config keyed id:user")
	}
	if len(cfgInput.InputValues) != 2 {
		t.Errorf("InputValues len = %d, want 2", len(cfgInput.InputValues))
	}
	// "1" is treated as a checked value.
	if !cfgInput.InputValues[1].Checked {
		t.Error("value \"1\" should be marked checked")
	}
}

func TestGetSmartValue(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)
	tests := []struct {
		name string
		want string
	}{
		{"email", FixedEmail},
		{"user_email", FixedEmail},
		{"password", FixedPassword},
		{"username", FixedUsername},
		{"phone", "+15551234567"},
		{"firstname", "Crawl"},
		{"lastname", "Tester"},
		{"city", "New York"},
		{"zipcode", "10001"},
		{"age", "30"},
		{"website", "https://example.com/test"},
		{"cvv", "123"},
		{"comment", "Test message for form submission"},
		{"q", "a"},
		{"title", "Test Title"},
		{"totally_unmatched_field", "a"}, // fallback
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := detectedInput(action.InputTypeText, tt.name)
			if got := h.getSmartValue(d); got != tt.want {
				t.Errorf("getSmartValue(name=%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestGetDefaultValue(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)
	tests := []struct {
		typ  action.InputType
		want string
	}{
		{action.InputTypeText, "a"},
		{action.InputTypePassword, "Password123!"},
		{action.InputTypeEmail, "test@example.com"},
		{action.InputTypeNumber, "42"},
		{action.InputTypeCheckbox, "true"},
		{action.InputTypeSelect, ""},
		{action.InputTypeFile, ""},
	}
	for _, tt := range tests {
		d := NewDetectedInputWithType(tt.typ, action.NewIdentification(action.HowID, "x"))
		if got := h.getDefaultValue(d); got != tt.want {
			t.Errorf("getDefaultValue(%q) = %q, want %q", tt.typ, got, tt.want)
		}
	}

	// nil FormInput falls back to "a".
	bare := &DetectedInput{}
	if got := h.getDefaultValue(bare); got != "a" {
		t.Errorf("getDefaultValue(nil FormInput) = %q, want a", got)
	}
}

func TestGenerateRandomValue(t *testing.T) {
	h := newTestHandler(config.FormFillRandom)

	text := h.generateRandomValue(detectedInput(action.InputTypeText, "x"))
	if len(text) != RandomStringLength {
		t.Errorf("random text len = %d, want %d", len(text), RandomStringLength)
	}

	email := h.generateRandomValue(detectedInput(action.InputTypeEmail, "x"))
	if !strings.HasSuffix(email, "@example.com") {
		t.Errorf("random email = %q, want @example.com suffix", email)
	}

	pwd := h.generateRandomValue(detectedInput(action.InputTypePassword, "x"))
	if !strings.HasSuffix(pwd, "A1!") {
		t.Errorf("random password = %q, want A1! suffix", pwd)
	}

	num := h.generateRandomValue(detectedInput(action.InputTypeNumber, "x"))
	if n, err := strconv.Atoi(num); err != nil || n < 0 || n >= MaxRandomInt {
		t.Errorf("random number = %q, want integer in [0, %d)", num, MaxRandomInt)
	}

	// Select and File inputs yield empty.
	if h.generateRandomValue(detectedInput(action.InputTypeSelect, "x")) != "" {
		t.Error("random select should be empty")
	}
	if h.generateRandomValue(detectedInput(action.InputTypeFile, "x")) != "" {
		t.Error("random file should be empty")
	}

	// nil FormInput yields a random string.
	if got := h.generateRandomValue(&DetectedInput{}); len(got) != RandomStringLength {
		t.Errorf("random value for nil FormInput len = %d, want %d", len(got), RandomStringLength)
	}
}

func TestRandomString(t *testing.T) {
	h := newTestHandler(config.FormFillRandom)
	s := h.randomString(20)
	if len(s) != 20 {
		t.Fatalf("randomString len = %d, want 20", len(s))
	}
	for _, c := range s {
		if !strings.ContainsRune(randomChars, c) {
			t.Errorf("randomString produced unexpected char %q", c)
		}
	}
}

func TestGenerateNumberInRange(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)

	// max <= min returns min.
	if got := h.generateNumberInRange("10", "5", "1"); got != "10" {
		t.Errorf("generateNumberInRange(10,5,1) = %q, want 10", got)
	}

	// Value within [0, 10], stepped by 2.
	got := h.generateNumberInRange("0", "10", "2")
	n, err := strconv.Atoi(got)
	if err != nil || n < 0 || n > 10 || n%2 != 0 {
		t.Errorf("generateNumberInRange(0,10,2) = %q, want even integer in [0,10]", got)
	}
}

func TestGenerateStringWithLength(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)

	// Fixed length when min == max.
	s := h.generateStringWithLength(5, 5)
	if len(s) != 5 {
		t.Errorf("generateStringWithLength(5,5) len = %d, want 5", len(s))
	}

	// Range honoured.
	for i := 0; i < 20; i++ {
		s := h.generateStringWithLength(3, 8)
		if len(s) < 3 || len(s) > 8 {
			t.Fatalf("generateStringWithLength(3,8) len = %d, out of range", len(s))
		}
	}
}

func TestGenerateConstrainedValuePattern(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)
	d := detectedInput(action.InputTypeText, "code")
	d.Pattern = "[0-9]{3}"

	got := h.generateConstrainedValue(d)
	if got == "" {
		t.Fatal("expected a value generated from the pattern")
	}
	for _, c := range got {
		if c < '0' || c > '9' {
			t.Errorf("pattern value %q contains non-digit", got)
		}
	}
}

func TestGenerateConstrainedValueNoConstraints(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)
	// No pattern, no min/max, no length constraints => empty (caller falls back).
	d := detectedInput(action.InputTypeText, "x")
	if got := h.generateConstrainedValue(d); got != "" {
		t.Errorf("generateConstrainedValue with no constraints = %q, want empty", got)
	}
}

func TestGetValueForInputPriority(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)

	// Configured values take priority.
	withValues := detectedInput(action.InputTypeText, "x")
	withValues.SetValues([]string{"configured"})
	if got := h.getValueForInput(withValues); got != "configured" {
		t.Errorf("getValueForInput should prefer configured value, got %q", got)
	}

	// Smart value by name.
	email := detectedInput(action.InputTypeEmail, "email")
	if got := h.getValueForInput(email); got != FixedEmail {
		t.Errorf("getValueForInput(email) = %q, want %q", got, FixedEmail)
	}
}

func TestParseFloatOrDefault(t *testing.T) {
	if got := parseFloatOrDefault("", 7); got != 7 {
		t.Errorf("empty string => %v, want default 7", got)
	}
	if got := parseFloatOrDefault("bad", 3); got != 3 {
		t.Errorf("invalid string => %v, want default 3", got)
	}
	if got := parseFloatOrDefault("2.5", 0); got != 2.5 {
		t.Errorf("valid string => %v, want 2.5", got)
	}
}

func TestFormatNumber(t *testing.T) {
	// Integer step => no decimals.
	if got := formatNumber(3.0, 1); got != "3" {
		t.Errorf("formatNumber(3,1) = %q, want 3", got)
	}
	// Fractional step => %g formatting.
	if got := formatNumber(2.5, 0.5); got != "2.5" {
		t.Errorf("formatNumber(2.5,0.5) = %q, want 2.5", got)
	}
}

func TestContainsAny(t *testing.T) {
	targets := []string{"login_email", "user-id"}
	if !containsAny(targets, "email") {
		t.Error("containsAny should match email")
	}
	if !containsAny(targets, "missing", "user") {
		t.Error("containsAny should match user via second pattern")
	}
	if containsAny(targets, "zzz") {
		t.Error("containsAny should not match zzz")
	}
}
