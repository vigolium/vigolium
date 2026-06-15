//go:build integration

package form

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// Test helper types and constants - aliased for convenience
type InputType = action.InputType

const (
	InputText     = action.InputTypeText
	InputEmail    = action.InputTypeEmail
	InputPassword = action.InputTypePassword
	InputNumber   = action.InputTypeNumber
	InputTel      = action.InputTypeTel
	InputURL      = action.InputTypeURL
	InputCheckbox = action.InputTypeCheckbox
	InputRadio    = action.InputTypeRadio
	InputSelect   = action.InputTypeSelect
	InputDate     = action.InputTypeDate
	InputTime     = action.InputTypeTime
)

// FormInput is an alias for DetectedInput in tests
type FormInput = DetectedInput

// NewFormInput creates a DetectedInput for testing.
// Accepts CSS selector (e.g., "#name") and converts to Identification.
// This is a test helper - production code uses XPath.
func NewFormInput(inputType action.InputType, selector string) *DetectedInput {
	var identification *action.Identification

	// Parse CSS selector to create Identification
	if strings.HasPrefix(selector, "#") {
		// ID selector: #name -> HowID
		identification = action.NewIdentification(action.HowID, selector[1:])
	} else if strings.HasPrefix(selector, ".") {
		// Class selector not directly supported, use XPath
		identification = action.NewIdentification(action.HowXPath, "//*[contains(@class,'"+selector[1:]+"')]")
	} else if strings.HasPrefix(selector, "[name=") {
		// Attribute selector: [name="x"] -> HowName
		name := strings.TrimPrefix(selector, "[name=")
		name = strings.TrimSuffix(name, "]")
		name = strings.Trim(name, "\"'")
		identification = action.NewIdentification(action.HowName, name)
	} else {
		// Default: treat as XPath or tag
		identification = action.NewIdentification(action.HowXPath, selector)
	}

	detected := NewDetectedInput(action.NewFormInput(inputType, identification))
	// Set ID/Name for test convenience
	if strings.HasPrefix(selector, "#") {
		detected.ID = selector[1:]
	}
	return detected
}

// WithValues sets values on a DetectedInput (fluent API for tests).
func (d *DetectedInput) WithValues(values ...string) *DetectedInput {
	d.SetValues(values)
	return d
}

// Test helper variables for smart value matching
var (
	firstNames = []string{"John", "Jane", "Bob", "Alice", "Charlie"}
	lastNames  = []string{"Smith", "Doe", "Johnson", "Williams", "Brown"}
)

// parseTimeToMinutes parses time string (HH:MM) to minutes since midnight.
// Returns defaultVal if parsing fails.
func parseTimeToMinutes(timeStr string, defaultVal int) int {
	parts := strings.Split(timeStr, ":")
	if len(parts) != 2 {
		return defaultVal
	}
	hours := 0
	minutes := 0
	fmt.Sscanf(parts[0], "%d", &hours)
	fmt.Sscanf(parts[1], "%d", &minutes)
	return hours*60 + minutes
}

// setupTestServer creates a test server serving formhandler testdata.
func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.FileServer(http.Dir("../browser/testdata")))
}

// setupBrowser creates a browser for testing.
func setupBrowser(t *testing.T, serverURL string) *browser.Browser {
	t.Helper()
	cfg, err := config.New(serverURL)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true

	b, err := browser.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create browser: %v", err)
	}

	t.Cleanup(func() {
		b.Close()
	})

	return b
}

// TestHandlerSetValueIntoTextField tests setting a value into a text field.
func TestHandlerSetValueIntoTextField(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillNormal
	cfg.FormInputs = []config.FormInputConfig{
		{How: "id", Value: "name", Type: "text", Values: []string{"Some Name"}},
	}

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Verify field is initially empty
	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	initialValue, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}
	if initialValue != "" {
		t.Errorf("Expected initial value to be empty, got %q", initialValue)
	}

	// Create handler and fill input
	handler := NewHandler(cfg)
	inputs, err := handler.DetectInputs(page)
	if err != nil {
		t.Fatalf("DetectInputs() failed: %v", err)
	}

	// Should detect exactly 1 input
	expectedInputs := 1
	if len(inputs) != expectedInputs {
		t.Errorf("Expected %d input, got %d", expectedInputs, len(inputs))
	}

	// Configure the input with our value
	if len(inputs) > 0 {
		inputs[0].SetValues([]string{"Some Name"})
	}

	result := handler.FillInputs(page, inputs)
	if result.Failed > 0 {
		t.Errorf("FillInputs had %d failures", result.Failed)
	}

	// Wait for value to be set
	time.Sleep(100 * time.Millisecond)

	// Verify value was set - exact match
	finalValue, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	expectedValue := "Some Name"
	if finalValue != expectedValue {
		t.Errorf("Expected value %q, got %q", expectedValue, finalValue)
	}
}

// TestHandlerSetFirstValueEvenIfManyValuesSpecified tests that first value is used.
func TestHandlerSetFirstValueEvenIfManyValuesSpecified(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillNormal

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Verify initially empty
	initialValue, _ := elem.Property("value")
	if initialValue != "" {
		t.Errorf("Expected initial value to be empty, got %q", initialValue)
	}

	// Create handler and fill with multiple values
	handler := NewHandler(cfg)

	// Create input with multiple values
	input := NewFormInput(InputText, "#name").
		WithValues("Some Name", "another value", "...")

	result := handler.FillInputs(page, []*FormInput{input})
	if result.Failed > 0 {
		t.Errorf("FillInputs had %d failures", result.Failed)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify first value was used - exact match
	finalValue, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	expectedValue := "Some Name"
	if finalValue != expectedValue {
		t.Errorf("Expected first value %q, got %q", expectedValue, finalValue)
	}
}

// TestHandlerClearTextFieldBeforeSettingValue tests clearing before fill.
func TestHandlerClearTextFieldBeforeSettingValue(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillNormal

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Set initial value manually - exact value "Not Empty"
	if err := elem.Input("Not Empty"); err != nil {
		t.Fatalf("Input() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Verify "Not Empty" was set
	preValue, _ := elem.Property("value")
	expectedPreValue := "Not Empty"
	if preValue != expectedPreValue {
		t.Errorf("Expected pre-value %q, got %q", expectedPreValue, preValue)
	}

	// Create handler and fill with new value
	handler := NewHandler(cfg)
	input := NewFormInput(InputText, "#name").WithValues("Some Name")

	result := handler.FillInputs(page, []*FormInput{input})
	if result.Failed > 0 {
		t.Errorf("FillInputs had %d failures", result.Failed)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify old value was cleared and new value set - exact match
	finalValue, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	expectedValue := "Some Name"
	if finalValue != expectedValue {
		t.Errorf("Expected value %q (not 'Not EmptySome Name'), got %q", expectedValue, finalValue)
	}
}

// TestHandlerNotSetValueIfNotFoundAndRandomDisabled tests no fill when field not found.
func TestHandlerNotSetValueIfNotFoundAndRandomDisabled(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillNormal // Random disabled

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Get the existing #name field
	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Verify initially empty
	initialValue, _ := elem.Property("value")
	if initialValue != "" {
		t.Errorf("Expected initial value to be empty, got %q", initialValue)
	}

	// Create handler and try to fill a field that doesn't exist
	handler := NewHandler(cfg)

	// This input targets a non-existent field
	nonExistentInput := NewFormInput(InputText, "#fieldNotFound").WithValues("value")

	// This should fail to find the element
	result := handler.FillInputs(page, []*FormInput{nonExistentInput})

	// Re-get the element since the previous reference may be stale after timeout
	elem, err = page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed after FillInputs: %v", err)
	}

	// The existing #name field should still be empty
	finalValue, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	expectedValue := ""
	if finalValue != expectedValue {
		t.Errorf("Expected #name field to remain empty %q, got %q", expectedValue, finalValue)
	}

	// The fill operation should have failed
	expectedFailed := 1
	if result.Failed != expectedFailed {
		t.Errorf("Expected %d failed fill, got %d", expectedFailed, result.Failed)
	}
}

// TestHandlerSetRandomValueWhenNotFoundAndRandomEnabled tests random fill.
func TestHandlerSetRandomValueWhenNotFoundAndRandomEnabled(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillRandom // Random enabled

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Get the existing #name field
	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Verify initially empty
	initialValue, _ := elem.Property("value")
	if initialValue != "" {
		t.Errorf("Expected initial value to be empty, got %q", initialValue)
	}

	// Create handler with random mode
	handler := NewHandler(cfg)

	// Detect inputs and fill with random values
	inputs, err := handler.DetectInputs(page)
	if err != nil {
		t.Fatalf("DetectInputs() failed: %v", err)
	}

	result := handler.FillInputs(page, inputs)
	if result.Failed > 0 {
		t.Errorf("FillInputs had %d failures", result.Failed)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify a random value was set (not empty)
	finalValue, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	if finalValue == "" {
		t.Error("Expected random value to be set, but field is still empty")
	}
}

// TestHandlerDetectInputsSimple tests input detection on simple page.
func TestHandlerDetectInputsSimple(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)
	inputs, err := handler.DetectInputs(page)
	if err != nil {
		t.Fatalf("DetectInputs() failed: %v", err)
	}

	// formhandler/index.html has exactly 1 input: #name
	expectedCount := 1
	if len(inputs) != expectedCount {
		t.Errorf("Expected exactly %d input, got %d", expectedCount, len(inputs))
	}

	if len(inputs) > 0 {
		if inputs[0].ID != "name" {
			t.Errorf("Expected input ID 'name', got %q", inputs[0].ID)
		}
		if inputs[0].Type != InputText {
			t.Errorf("Expected input type 'text', got %q", inputs[0].Type)
		}
	}
}

// TestHandlerFillInputsResult tests FillInputsResult structure.
func TestHandlerFillInputsResult(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Create mix of valid and invalid inputs
	inputs := []*FormInput{
		NewFormInput(InputText, "#name").WithValues("Test Value"),
		NewFormInput(InputText, "#nonexistent").WithValues("Should Fail"),
	}

	result := handler.FillInputs(page, inputs)

	// Verify result counts
	expectedSucceeded := 1
	expectedFailed := 1
	if result.Succeeded != expectedSucceeded {
		t.Errorf("Expected %d succeeded, got %d", expectedSucceeded, result.Succeeded)
	}
	if result.Failed != expectedFailed {
		t.Errorf("Expected %d failed, got %d", expectedFailed, result.Failed)
	}

	// Verify HasErrors
	if !result.HasErrors() {
		t.Error("Expected HasErrors() to be true")
	}

	// Verify Errors() returns the error
	errors := result.Errors()
	expectedErrorCount := 1
	if len(errors) != expectedErrorCount {
		t.Errorf("Expected %d error, got %d", expectedErrorCount, len(errors))
	}
}

// TestHandlerResetInputs tests resetting inputs.
func TestHandlerResetInputs(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Fill the input first
	input := NewFormInput(InputText, "#name").WithValues("Test Value")
	handler.FillInputs(page, []*FormInput{input})

	time.Sleep(100 * time.Millisecond)

	// Verify filled
	elem, _ := page.Element("#name")
	filledValue, _ := elem.Property("value")
	if filledValue != "Test Value" {
		t.Errorf("Expected filled value 'Test Value', got %q", filledValue)
	}

	// Reset
	handler.ResetInputs(page, []*FormInput{input})

	time.Sleep(100 * time.Millisecond)

	// Verify reset
	resetValue, _ := elem.Property("value")
	expectedResetValue := ""
	if resetValue != expectedResetValue {
		t.Errorf("Expected reset value %q, got %q", expectedResetValue, resetValue)
	}
}

// TestHandlerGetValueForInput tests value determination logic.
func TestHandlerGetValueForInput(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	cfg.FormFillMode = config.FormFillNormal

	handler := NewHandler(cfg)

	// Input with configured values
	inputWithValues := NewFormInput(InputText, "#field").WithValues("configured")
	value := handler.getValueForInput(inputWithValues)
	if value != "configured" {
		t.Errorf("Expected 'configured', got %q", value)
	}

	// Input without values (should use default). A bare text input with no
	// matching name falls back to the generic placeholder "a" (the canonical
	// behavior asserted by handler_value_unit_test.go); type-aware values apply
	// only to strict typed inputs (url/tel/date/time/...), covered below.
	inputWithoutValues := NewFormInput(InputText, "#field")
	defaultValue := handler.getValueForInput(inputWithoutValues)
	expectedDefault := "a"
	if defaultValue != expectedDefault {
		t.Errorf("Expected default %q, got %q", expectedDefault, defaultValue)
	}
}

// TestHandlerGetDefaultValue tests default values for different input types.
func TestHandlerGetDefaultValue(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	handler := NewHandler(cfg)

	tests := []struct {
		inputType InputType
		expected  string
	}{
		{InputText, "a"},
		{InputPassword, "Password123!"},
		{InputEmail, "test@example.com"},
		{InputNumber, "42"},
		{InputURL, "https://example.com"},
		{InputTel, "+15555555555"},
		{InputCheckbox, "true"},
	}

	for _, tc := range tests {
		t.Run(string(tc.inputType), func(t *testing.T) {
			input := NewFormInput(tc.inputType, "#field")
			value := handler.getDefaultValue(input)
			if value != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, value)
			}
		})
	}
}

// TestHandlerGenerateRandomValue tests random value generation.
func TestHandlerGenerateRandomValue(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	cfg.FormFillMode = config.FormFillRandom

	handler := NewHandler(cfg)

	tests := []struct {
		inputType   InputType
		minLen      int
		containsStr string
		description string
	}{
		{InputText, RandomStringLength, "", "random text"},
		{InputPassword, 12, "A1!", "password with special chars"},
		{InputEmail, 1, "@example.com", "email format"},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			input := NewFormInput(tc.inputType, "#field")
			value := handler.generateRandomValue(input)

			if len(value) < tc.minLen {
				t.Errorf("Expected min length %d, got %d", tc.minLen, len(value))
			}

			if tc.containsStr != "" && !containsString(value, tc.containsStr) {
				t.Errorf("Expected value to contain %q, got %q", tc.containsStr, value)
			}
		})
	}
}

// TestHandlerRandomValuesAreUnique tests uniqueness of random values.
func TestHandlerRandomValuesAreUnique(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	handler := NewHandler(cfg)

	const numChecks = 1000
	seen := make(map[string]bool)

	for i := 0; i < numChecks; i++ {
		value := handler.randomString(15)
		if seen[value] {
			t.Errorf("Duplicate random value found: %q", value)
		}
		seen[value] = true
	}
}

// TestHandlerRandomStringLength tests random string length.
func TestHandlerRandomStringLength(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	handler := NewHandler(cfg)

	tests := []int{1, 15, 150}
	for _, length := range tests {
		t.Run("", func(t *testing.T) {
			value := handler.randomString(length)
			if len(value) != length {
				t.Errorf("Expected length %d, got %d", length, len(value))
			}
		})
	}
}

// Helper function
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// =============================================================================

// setupSmartFormServer creates a test server serving smart form testdata.
func setupSmartFormServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.FileServer(http.Dir("testdata")))
}

// TestSmartValueEmail tests intelligent email detection by name/id.
func TestSmartValueEmail(t *testing.T) {
	server := setupSmartFormServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillNormal

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/smart_form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Test fields with email-related names
	emailFields := []string{"#email", "#user_mail", "#correo"}

	for _, selector := range emailFields {
		t.Run(selector, func(t *testing.T) {
			elem, err := page.Element(selector)
			if err != nil {
				t.Fatalf("Element(%s) failed: %v", selector, err)
			}

			input := NewFormInput(InputText, selector)
			input.Name = selector[1:] // Remove # prefix
			input.ID = selector[1:]

			result := handler.FillInputs(page, []*FormInput{input})
			if result.Failed > 0 {
				t.Errorf("FillInputs failed for %s", selector)
			}

			time.Sleep(50 * time.Millisecond)

			value, _ := elem.Property("value")
			valueStr, _ := value.(string)

			// Should match FixedEmail
			if valueStr != FixedEmail {
				t.Errorf("Expected %q for %s, got %q", FixedEmail, selector, valueStr)
			}
		})
	}
}

// TestSmartValuePhone tests intelligent phone detection by name/id.
func TestSmartValuePhone(t *testing.T) {
	server := setupSmartFormServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillNormal

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/smart_form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Test fields with phone-related names
	phoneFields := []string{"#phone", "#mobile", "#telefono"}

	for _, selector := range phoneFields {
		t.Run(selector, func(t *testing.T) {
			elem, err := page.Element(selector)
			if err != nil {
				t.Fatalf("Element(%s) failed: %v", selector, err)
			}

			input := NewFormInput(InputText, selector)
			input.Name = selector[1:]
			input.ID = selector[1:]

			result := handler.FillInputs(page, []*FormInput{input})
			if result.Failed > 0 {
				t.Errorf("FillInputs failed for %s", selector)
			}

			time.Sleep(50 * time.Millisecond)

			value, _ := elem.Property("value")
			valueStr, _ := value.(string)

			// Should start with +1 (phone format)
			if !containsString(valueStr, "+1") {
				t.Errorf("Expected phone format for %s, got %q", selector, valueStr)
			}
		})
	}
}

// TestSmartValueNames tests intelligent name detection (firstname, lastname, etc.).
func TestSmartValueNames(t *testing.T) {
	server := setupSmartFormServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillNormal

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/smart_form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Test name fields
	tests := []struct {
		selector    string
		shouldMatch []string // Any of these should match
	}{
		{"#firstname", firstNames},
		{"#first_name", firstNames},
		{"#lastname", lastNames},
		{"#surname", lastNames},
	}

	for _, tc := range tests {
		t.Run(tc.selector, func(t *testing.T) {
			elem, err := page.Element(tc.selector)
			if err != nil {
				t.Fatalf("Element(%s) failed: %v", tc.selector, err)
			}

			input := NewFormInput(InputText, tc.selector)
			input.Name = tc.selector[1:]
			input.ID = tc.selector[1:]

			result := handler.FillInputs(page, []*FormInput{input})
			if result.Failed > 0 {
				t.Errorf("FillInputs failed for %s", tc.selector)
			}

			time.Sleep(50 * time.Millisecond)

			value, _ := elem.Property("value")
			valueStr, _ := value.(string)

			// Should be one of the expected names
			found := false
			for _, name := range tc.shouldMatch {
				if valueStr == name {
					found = true
					break
				}
			}

			if !found && valueStr == "" {
				t.Errorf("Expected a name for %s, got empty", tc.selector)
			}
		})
	}
}

// TestSmartValueAddress tests intelligent address detection.
func TestSmartValueAddress(t *testing.T) {
	server := setupSmartFormServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillNormal

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/smart_form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Test address field - should have number and "St"
	elem, err := page.Element("#address")
	if err != nil {
		t.Fatalf("Element(#address) failed: %v", err)
	}

	input := NewFormInput(InputText, "#address")
	input.Name = "address"
	input.ID = "address"

	handler.FillInputs(page, []*FormInput{input})
	time.Sleep(50 * time.Millisecond)

	value, _ := elem.Property("value")
	valueStr, _ := value.(string)

	// Should contain "St" for street
	if !containsString(valueStr, "St") {
		t.Errorf("Expected address format with 'St', got %q", valueStr)
	}
}

// TestSmartValueCreditCard tests intelligent credit card detection (fake test data).
func TestSmartValueCreditCard(t *testing.T) {
	server := setupSmartFormServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillNormal

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/smart_form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)

	tests := []struct {
		selector string
		expected string
	}{
		{"#cardnumber", "4111111111111111"},
		{"#cvv", "123"},
		{"#expiry", "12/25"},
	}

	for _, tc := range tests {
		t.Run(tc.selector, func(t *testing.T) {
			elem, err := page.Element(tc.selector)
			if err != nil {
				t.Fatalf("Element(%s) failed: %v", tc.selector, err)
			}

			input := NewFormInput(InputText, tc.selector)
			input.Name = tc.selector[1:]
			input.ID = tc.selector[1:]

			handler.FillInputs(page, []*FormInput{input})
			time.Sleep(50 * time.Millisecond)

			value, _ := elem.Property("value")
			valueStr, _ := value.(string)

			if valueStr != tc.expected {
				t.Errorf("Expected %q for %s, got %q", tc.expected, tc.selector, valueStr)
			}
		})
	}
}

// TestSelectRandomOption tests random option selection for SELECT elements.
func TestSelectRandomOption(t *testing.T) {
	server := setupSmartFormServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillNormal

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/smart_form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Test select_color which has no placeholder (all options are valid)
	validOptions := []string{"red", "green", "blue", "yellow"}

	elem, err := page.Element("#select_color")
	if err != nil {
		t.Fatalf("Element(#select_color) failed: %v", err)
	}

	// Initial value should be "red" (first option)
	initialValue, _ := elem.Property("value")
	if initialValue != "red" {
		t.Logf("Initial value: %q", initialValue)
	}

	// Create input WITHOUT configured values - should trigger random selection
	input := NewFormInput(InputSelect, "#select_color")
	input.Name = "select_color"
	input.ID = "select_color"
	// Note: NO Values set - this triggers random selection

	result := handler.FillInputs(page, []*FormInput{input})
	if result.Failed > 0 {
		t.Errorf("FillInputs failed: %v", result.Errors())
	}

	time.Sleep(100 * time.Millisecond)

	value, _ := elem.Property("value")
	valueStr, _ := value.(string)

	// Should be one of the valid options
	found := false
	for _, opt := range validOptions {
		if valueStr == opt {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected one of %v, got %q", validOptions, valueStr)
	}
}

// TestSelectWithPlaceholder tests that placeholder option is skipped.
func TestSelectWithPlaceholder(t *testing.T) {
	server := setupSmartFormServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillNormal

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/smart_form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// select_country has placeholder with empty value ""
	validOptions := []string{"us", "uk", "ca", "au", "de"}

	elem, err := page.Element("#select_country")
	if err != nil {
		t.Fatalf("Element(#select_country) failed: %v", err)
	}

	input := NewFormInput(InputSelect, "#select_country")
	input.Name = "select_country"
	input.ID = "select_country"

	result := handler.FillInputs(page, []*FormInput{input})
	if result.Failed > 0 {
		t.Errorf("FillInputs failed: %v", result.Errors())
	}

	time.Sleep(100 * time.Millisecond)

	value, _ := elem.Property("value")
	valueStr, _ := value.(string)

	// Should NOT be empty (placeholder should be skipped)
	if valueStr == "" {
		t.Error("Placeholder option should have been skipped, but empty value was selected")
	}

	// Should be one of the valid options
	found := false
	for _, opt := range validOptions {
		if valueStr == opt {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected one of %v, got %q", validOptions, valueStr)
	}
}

// TestSelectWithDisabledOptions tests that disabled options are skipped.
func TestSelectWithDisabledOptions(t *testing.T) {
	server := setupSmartFormServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillNormal

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/smart_form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// select_size has disabled options: xs and xl
	validOptions := []string{"s", "m", "l"} // Only enabled options
	disabledOptions := []string{"xs", "xl"}

	// Run multiple times to increase chance of catching disabled selection
	for i := 0; i < 10; i++ {
		elem, err := page.Element("#select_size")
		if err != nil {
			t.Fatalf("Element(#select_size) failed: %v", err)
		}

		input := NewFormInput(InputSelect, "#select_size")
		input.Name = "select_size"
		input.ID = "select_size"

		handler.FillInputs(page, []*FormInput{input})
		time.Sleep(50 * time.Millisecond)

		value, _ := elem.Property("value")
		valueStr, _ := value.(string)

		// Should NOT be a disabled option
		for _, disabled := range disabledOptions {
			if valueStr == disabled {
				t.Errorf("Disabled option %q was selected", disabled)
			}
		}

		// Should be a valid enabled option (or empty placeholder)
		if valueStr != "" {
			found := false
			for _, opt := range validOptions {
				if valueStr == opt {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Unexpected option %q selected", valueStr)
			}
		}
	}
}

// TestCheckboxBinaryValues tests checkbox with "1"/"0" values.
func TestCheckboxBinaryValues(t *testing.T) {
	server := setupSmartFormServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillRandom

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/smart_form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Generate random checkbox value - should be "1" or "0"
	input := NewFormInput(InputCheckbox, "#checkbox_agree")
	randomValue := handler.generateRandomValue(input)

	if randomValue != "1" && randomValue != "0" {
		t.Errorf("Expected '1' or '0' for checkbox, got %q", randomValue)
	}
}

// TestRadioBinaryValues tests radio with "1"/"0" values.
func TestRadioBinaryValues(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	cfg.FormFillMode = config.FormFillRandom

	handler := NewHandler(cfg)

	// Generate random radio value - should be "1" or "0"
	input := NewFormInput(InputRadio, "#radio_male")
	randomValue := handler.generateRandomValue(input)

	if randomValue != "1" && randomValue != "0" {
		t.Errorf("Expected '1' or '0' for radio, got %q", randomValue)
	}
}

// TestRandomStringLength tests random string length matches the constant.
func TestRandomStringLength(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	cfg.FormFillMode = config.FormFillRandom

	handler := NewHandler(cfg)

	// Random text should be 8 chars (RandomStringLength constant)
	input := NewFormInput(InputText, "#field")
	randomValue := handler.generateRandomValue(input)

	if len(randomValue) != RandomStringLength {
		t.Errorf("Expected random string length %d, got %d", RandomStringLength, len(randomValue))
	}
}

// TestRandomStringCharset tests random string uses only letters.
func TestRandomStringCharset(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	handler := NewHandler(cfg)

	// Generate many random strings and verify charset
	for i := 0; i < 100; i++ {
		value := handler.randomString(50)

		for _, c := range value {
			isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			if !isLetter {
				t.Errorf("Random string contains non-letter character: %q in %q", string(c), value)
			}
		}
	}
}

// TestRandomNumber tests random number range matches MaxRandomInt.
func TestRandomNumber(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	cfg.FormFillMode = config.FormFillRandom

	handler := NewHandler(cfg)

	input := NewFormInput(InputNumber, "#field")

	// Generate many random numbers and verify range
	for i := 0; i < 100; i++ {
		randomValue := handler.generateRandomValue(input)

		var num int
		_, err := fmt.Sscanf(randomValue, "%d", &num)
		if err != nil {
			t.Errorf("Random number is not a valid integer: %q", randomValue)
			continue
		}

		if num < 0 || num >= MaxRandomInt {
			t.Errorf("Random number %d outside range [0, %d)", num, MaxRandomInt)
		}
	}
}

// TestGetSelectAllOptions tests GetSelectAllOptions function.
func TestGetSelectAllOptions(t *testing.T) {
	server := setupSmartFormServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/smart_form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Test select with placeholder (empty value should be excluded)
	elem, err := page.Element("#select_country")
	if err != nil {
		t.Fatalf("Element failed: %v", err)
	}

	options, err := GetSelectAllOptions(elem)
	if err != nil {
		t.Fatalf("GetSelectAllOptions failed: %v", err)
	}

	// Should have 5 options (us, uk, ca, au, de) - NOT the empty placeholder
	expectedCount := 5
	if len(options) != expectedCount {
		t.Errorf("Expected %d options, got %d: %v", expectedCount, len(options), options)
	}

	// Verify no empty values
	for _, opt := range options {
		if opt == "" {
			t.Error("Empty option should not be included")
		}
	}
}

// TestGetSelectAllOptionsWithDisabled tests that disabled options are excluded.
func TestGetSelectAllOptionsWithDisabled(t *testing.T) {
	server := setupSmartFormServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/smart_form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// select_size has disabled options
	elem, err := page.Element("#select_size")
	if err != nil {
		t.Fatalf("Element failed: %v", err)
	}

	options, err := GetSelectAllOptions(elem)
	if err != nil {
		t.Fatalf("GetSelectAllOptions failed: %v", err)
	}

	// Should have 3 options (s, m, l) - NOT disabled ones (xs, xl) or empty placeholder
	expectedCount := 3
	if len(options) != expectedCount {
		t.Errorf("Expected %d options, got %d: %v", expectedCount, len(options), options)
	}

	// Verify disabled options are not included
	for _, opt := range options {
		if opt == "xs" || opt == "xl" {
			t.Errorf("Disabled option %q should not be included", opt)
		}
	}
}

// TestCompleteFormFill tests filling a complete form with various input types.
func TestCompleteFormFill(t *testing.T) {
	server := setupSmartFormServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.FormFillMode = config.FormFillNormal

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/smart_form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Create inputs for the complete form section
	inputs := []*FormInput{
		func() *FormInput {
			i := NewFormInput(InputText, "#form_firstname")
			i.Name = "firstname"
			i.ID = "form_firstname"
			return i
		}(),
		func() *FormInput {
			i := NewFormInput(InputText, "#form_lastname")
			i.Name = "lastname"
			i.ID = "form_lastname"
			return i
		}(),
		func() *FormInput {
			i := NewFormInput(InputEmail, "#form_email")
			i.Name = "email"
			i.ID = "form_email"
			return i
		}(),
		func() *FormInput {
			i := NewFormInput(InputPassword, "#form_password")
			i.Name = "password"
			i.ID = "form_password"
			return i
		}(),
		func() *FormInput {
			i := NewFormInput(InputTel, "#form_phone")
			i.Name = "phone"
			i.ID = "form_phone"
			return i
		}(),
		func() *FormInput {
			i := NewFormInput(InputSelect, "#form_country")
			i.Name = "country"
			i.ID = "form_country"
			return i
		}(),
		func() *FormInput {
			i := NewFormInput(InputCheckbox, "#form_agree")
			i.Name = "agree"
			i.ID = "form_agree"
			i.SetValues([]string{"1"}) // Check it
			return i
		}(),
	}

	result := handler.FillInputs(page, inputs)

	time.Sleep(200 * time.Millisecond)

	// All should succeed
	if result.Failed > 0 {
		t.Errorf("Expected 0 failures, got %d: %v", result.Failed, result.Errors())
	}

	// Verify some values
	verifications := []struct {
		selector  string
		checkFunc func(string) bool
		desc      string
	}{
		{"#form_firstname", func(v string) bool { return v != "" }, "firstname should not be empty"},
		{"#form_email", func(v string) bool { return containsString(v, "@") }, "email should contain @"},
		{"#form_password", func(v string) bool { return len(v) > 10 }, "password should be long"},
		{"#form_phone", func(v string) bool { return containsString(v, "+1") }, "phone should start with +1"},
		{"#form_country", func(v string) bool { return v != "" }, "country should be selected"},
	}

	for _, v := range verifications {
		elem, _ := page.Element(v.selector)
		value, _ := elem.Property("value")
		valueStr, _ := value.(string)

		if !v.checkFunc(valueStr) {
			t.Errorf("%s: got %q", v.desc, valueStr)
		}
	}

	// Verify checkbox is checked
	checkElem, _ := page.Element("#form_agree")
	checked, _ := checkElem.Property("checked")
	if checked != true {
		t.Error("Checkbox should be checked")
	}
}

// TestProbabilityCheck tests that checkbox/radio use ~50% probability.
func TestProbabilityCheck(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	cfg.FormFillMode = config.FormFillRandom

	handler := NewHandler(cfg)

	ones := 0
	zeros := 0
	iterations := 1000

	for i := 0; i < iterations; i++ {
		input := NewFormInput(InputCheckbox, "#cb")
		value := handler.generateRandomValue(input)
		if value == "1" {
			ones++
		} else {
			zeros++
		}
	}

	// Should be roughly 50/50 (allow 10% variance)
	ratio := float64(ones) / float64(iterations)
	if ratio < 0.4 || ratio > 0.6 {
		t.Errorf("Probability check not ~50%%: ones=%d, zeros=%d, ratio=%.2f", ones, zeros, ratio)
	}
}

// =============================================================================
// CONSTRAINT-AWARE GENERATION TESTS
// =============================================================================

// TestConstrainedPatternGeneration tests pattern-based value generation.
func TestConstrainedPatternGeneration(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	handler := NewHandler(cfg)

	tests := []struct {
		name        string
		pattern     string
		minLen      int
		maxLen      int
		validateFn  func(string) bool
		description string
	}{
		{
			name:       "uppercase_3_letters",
			pattern:    "[A-Z]{3}",
			minLen:     3,
			maxLen:     3,
			validateFn: func(s string) bool { return len(s) == 3 && isAllUppercase(s) },
		},
		{
			name:       "digits_10",
			pattern:    "[0-9]{10}",
			minLen:     10,
			maxLen:     10,
			validateFn: func(s string) bool { return len(s) == 10 && isAllDigits(s) },
		},
		{
			name:       "alphanumeric",
			pattern:    "[A-Za-z0-9]+",
			minLen:     1,
			maxLen:     0, // no max
			validateFn: func(s string) bool { return len(s) >= 1 },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := NewFormInput(InputText, "#field")
			input.Pattern = tc.pattern
			input.MinLength = tc.minLen
			input.MaxLength = tc.maxLen

			// Run multiple times to ensure consistency
			for i := 0; i < 10; i++ {
				value := handler.generateConstrainedValue(input)
				if value == "" {
					t.Fatalf("Expected value for pattern %q, got empty", tc.pattern)
				}
				if !tc.validateFn(value) {
					t.Errorf("Value %q does not match pattern %q", value, tc.pattern)
				}
			}
		})
	}
}

// TestConstrainedNumberRange tests number range generation.
func TestConstrainedNumberRange(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	handler := NewHandler(cfg)

	tests := []struct {
		name   string
		min    string
		max    string
		step   string
		minVal float64
		maxVal float64
	}{
		{"basic_range", "1", "100", "", 1, 100},
		{"with_step", "0", "100", "10", 0, 100},
		{"float_range", "0.01", "999.99", "0.01", 0.01, 999.99},
		{"negative_to_positive", "-50", "50", "", -50, 50},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := NewFormInput(InputNumber, "#field")
			input.Min = tc.min
			input.Max = tc.max
			input.Step = tc.step

			for i := 0; i < 20; i++ {
				value := handler.generateConstrainedValue(input)
				if value == "" {
					t.Fatalf("Expected value, got empty")
				}

				numVal := parseFloatOrDefault(value, -99999)
				if numVal < tc.minVal || numVal > tc.maxVal {
					t.Errorf("Value %s (%.2f) out of range [%.2f, %.2f]", value, numVal, tc.minVal, tc.maxVal)
				}
			}
		})
	}
}

// TestConstrainedStringLength tests string length constraints.
func TestConstrainedStringLength(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	handler := NewHandler(cfg)

	tests := []struct {
		name      string
		minLength int
		maxLength int
	}{
		{"min_only", 5, 0},
		{"max_only", 0, 20},
		{"both", 5, 20},
		{"exact", 10, 10},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := NewFormInput(InputText, "#field")
			input.MinLength = tc.minLength
			input.MaxLength = tc.maxLength

			for i := 0; i < 20; i++ {
				value := handler.generateConstrainedValue(input)
				if value == "" {
					t.Fatalf("Expected value, got empty")
				}

				minCheck := tc.minLength
				if minCheck == 0 {
					minCheck = 1
				}
				maxCheck := tc.maxLength
				if maxCheck == 0 || maxCheck < minCheck {
					maxCheck = minCheck + RandomStringLength
				}

				if len(value) < minCheck || len(value) > maxCheck {
					t.Errorf("Value length %d not in [%d, %d]", len(value), minCheck, maxCheck)
				}
			}
		})
	}
}

// TestConstrainedDateRange tests date range generation.
func TestConstrainedDateRange(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	handler := NewHandler(cfg)

	input := NewFormInput(InputDate, "#field")
	input.Min = "2024-01-01"
	input.Max = "2024-12-31"

	minDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	maxDate := time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 20; i++ {
		value := handler.generateConstrainedValue(input)
		if value == "" {
			t.Fatalf("Expected value, got empty")
		}

		parsed, err := time.Parse("2006-01-02", value)
		if err != nil {
			t.Errorf("Invalid date format: %s", value)
			continue
		}

		if parsed.Before(minDate) || parsed.After(maxDate) {
			t.Errorf("Date %s out of range [%s, %s]", value, input.Min, input.Max)
		}
	}
}

// TestConstrainedTimeRange tests time range generation.
func TestConstrainedTimeRange(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	handler := NewHandler(cfg)

	input := NewFormInput(InputTime, "#field")
	input.Min = "09:00"
	input.Max = "17:00"

	for i := 0; i < 20; i++ {
		value := handler.generateConstrainedValue(input)
		if value == "" {
			t.Fatalf("Expected value, got empty")
		}

		mins := parseTimeToMinutes(value, -1)
		minMins := parseTimeToMinutes(input.Min, 0)
		maxMins := parseTimeToMinutes(input.Max, 0)

		if mins < minMins || mins > maxMins {
			t.Errorf("Time %s (%d mins) out of range [%s, %s]", value, mins, input.Min, input.Max)
		}
	}
}

// TestLabelDetection tests that label text is used for smart value detection.
func TestLabelDetection(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	handler := NewHandler(cfg)

	tests := []struct {
		label         string
		expectedValue string
	}{
		{"Your Email Address", FixedEmail},
		{"Contact Email", FixedEmail},
		{"Phone Number", "+15551234567"},
		{"Mobile Phone", "+15551234567"},
		{"Username", FixedUsername},
		{"Password", FixedPassword},
	}

	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			input := NewFormInput(InputText, "#field")
			input.Label = tc.label

			value := handler.getSmartValue(input)

			if value != tc.expectedValue {
				t.Errorf("Expected %q for label %q, got %q", tc.expectedValue, tc.label, value)
			}
		})
	}
}

// TestPlaceholderDetection tests that placeholder text is used for smart value detection.
func TestPlaceholderDetection(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	handler := NewHandler(cfg)

	tests := []struct {
		placeholder   string
		expectedValue string
	}{
		{"Enter your email address", FixedEmail},
		{"your.email@example.com", FixedEmail},
		{"Enter password", FixedPassword},
	}

	for _, tc := range tests {
		t.Run(tc.placeholder, func(t *testing.T) {
			input := NewFormInput(InputText, "#field")
			input.Placeholder = tc.placeholder

			value := handler.getSmartValue(input)

			if value != tc.expectedValue {
				t.Errorf("Expected %q for placeholder %q, got %q", tc.expectedValue, tc.placeholder, value)
			}
		})
	}
}

// TestConstraintPriorityOverSmart tests that constraints take priority over smart detection.
func TestConstraintPriorityOverSmart(t *testing.T) {
	cfg, _ := config.New("http://example.com")
	handler := NewHandler(cfg)

	// Email field with pattern constraint should use pattern, not email format
	input := NewFormInput(InputText, "#email")
	input.Name = "email"
	input.Pattern = "[A-Z]{5}"

	value := handler.getValueForInput(input)

	// Should be 5 uppercase letters (from pattern), not an email
	if containsString(value, "@") {
		t.Errorf("Expected pattern value, got email format: %s", value)
	}
	if len(value) != 5 {
		t.Errorf("Expected 5 chars from pattern, got %d: %s", len(value), value)
	}
}

// Helper functions for tests

func isAllUppercase(s string) bool {
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
