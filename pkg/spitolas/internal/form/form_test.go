//go:build !integration

package form

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

// TestGetTypeFromStr tests input type parsing.
// CRAWLJAX PARITY: Tests action.GetTypeFromStr which matches Java FormInput.getTypeFromStr()
func TestGetTypeFromStr(t *testing.T) {
	tests := []struct {
		input    string
		expected action.InputType
	}{
		{"text", action.InputTypeText},
		{"", action.InputTypeText}, // Empty defaults to text
		{"textarea", action.InputTypeTextarea},
		{"password", action.InputTypePassword},
		{"email", action.InputTypeEmail},
		{"number", action.InputTypeNumber},
		{"hidden", action.InputTypeHidden},
		{"checkbox", action.InputTypeCheckbox},
		{"radio", action.InputTypeRadio},
		{"select", action.InputTypeSelect},
		{"select-one", action.InputTypeSelect},
		{"select-multiple", action.InputTypeSelect},
		{"unknown", action.InputTypeText}, // Unknown defaults to text
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := action.GetTypeFromStr(tc.input)
			if result != tc.expected {
				t.Errorf("GetTypeFromStr(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

// TestFormInputIsTextLike tests IsTextLike method.
// CRAWLJAX PARITY: Tests action.FormInput.IsTextLike()
func TestFormInputIsTextLike(t *testing.T) {
	textLikeTypes := []action.InputType{
		action.InputTypeText, action.InputTypeTextarea, action.InputTypePassword,
		action.InputTypeEmail, action.InputTypeNumber, action.InputTypeInput,
	}

	notTextLikeTypes := []action.InputType{
		action.InputTypeHidden, action.InputTypeCheckbox, action.InputTypeRadio, action.InputTypeSelect,
	}

	for _, it := range textLikeTypes {
		input := action.NewFormInput(it, nil)
		if !input.IsTextLike() {
			t.Errorf("%q should be text-like", it)
		}
	}

	for _, it := range notTextLikeTypes {
		input := action.NewFormInput(it, nil)
		if input.IsTextLike() {
			t.Errorf("%q should not be text-like", it)
		}
	}
}

// TestNewDetectedInput tests DetectedInput creation.
func TestNewDetectedInput(t *testing.T) {
	identification := action.NewIdentification(action.HowID, "test-input")
	formInput := action.NewFormInput(action.InputTypeText, identification)
	input := NewDetectedInput(formInput)

	if input.FormInput != formInput {
		t.Error("Expected FormInput to be set")
	}
	if input.Type != action.InputTypeText {
		t.Errorf("Expected Type InputTypeText, got %q", input.Type)
	}
	if input.Identification.Value != "test-input" {
		t.Errorf("Expected Identification.Value 'test-input', got %q", input.Identification.Value)
	}
}

// TestDetectedInputWithMetadata tests DetectedInput with detection metadata.
func TestDetectedInputWithMetadata(t *testing.T) {
	identification := action.NewIdentification(action.HowName, "username")
	formInput := action.NewFormInput(action.InputTypeText, identification)
	formInput.SetInputValues("value1", "value2", "value3")

	input := NewDetectedInput(formInput)
	input.Name = "username"
	input.ID = "user-field"
	input.XPath = "//input[@id='user-field']"

	if input.Name != "username" {
		t.Errorf("Expected Name 'username', got %q", input.Name)
	}
	if input.ID != "user-field" {
		t.Errorf("Expected ID 'user-field', got %q", input.ID)
	}
	if input.XPath != "//input[@id='user-field']" {
		t.Errorf("Expected XPath //input[@id='user-field'], got %q", input.XPath)
	}
	expectedValues := 3
	if len(input.InputValues) != expectedValues {
		t.Errorf("Expected %d values, got %d", expectedValues, len(input.InputValues))
	}
}

// TestDetectedInputNextValue tests value rotation.
// Crawljax parity: FormInput uses first value when multiple values specified.
func TestDetectedInputNextValue(t *testing.T) {
	formInput := action.NewFormInput(action.InputTypeText, nil)
	formInput.SetInputValues("first", "second", "third")
	input := NewDetectedInput(formInput)

	// First call returns first value
	v1 := input.NextValue()
	if v1 != "first" {
		t.Errorf("Expected 'first', got %q", v1)
	}

	// Second call returns second value
	v2 := input.NextValue()
	if v2 != "second" {
		t.Errorf("Expected 'second', got %q", v2)
	}

	// Third call returns third value
	v3 := input.NextValue()
	if v3 != "third" {
		t.Errorf("Expected 'third', got %q", v3)
	}

	// Fourth call wraps around to first
	v4 := input.NextValue()
	if v4 != "first" {
		t.Errorf("Expected 'first' (wrap around), got %q", v4)
	}
}

// TestDetectedInputNextValueEmpty tests NextValue with no values.
func TestDetectedInputNextValueEmpty(t *testing.T) {
	formInput := action.NewFormInput(action.InputTypeText, nil)
	input := NewDetectedInput(formInput)

	v := input.NextValue()
	if v != "" {
		t.Errorf("Expected empty string, got %q", v)
	}
}

// TestDetectedInputCurrentValue tests CurrentValue without advancing.
func TestDetectedInputCurrentValue(t *testing.T) {
	formInput := action.NewFormInput(action.InputTypeText, nil)
	formInput.SetInputValues("first", "second")
	input := NewDetectedInput(formInput)

	// CurrentValue returns first without advancing
	v1 := input.CurrentValue()
	if v1 != "first" {
		t.Errorf("Expected 'first', got %q", v1)
	}

	// Still returns first
	v2 := input.CurrentValue()
	if v2 != "first" {
		t.Errorf("Expected 'first', got %q", v2)
	}

	// Now advance
	input.NextValue()

	// CurrentValue returns second
	v3 := input.CurrentValue()
	if v3 != "second" {
		t.Errorf("Expected 'second', got %q", v3)
	}
}

// TestDetectedInputResetValueIndex tests index reset.
func TestDetectedInputResetValueIndex(t *testing.T) {
	formInput := action.NewFormInput(action.InputTypeText, nil)
	formInput.SetInputValues("first", "second", "third")
	input := NewDetectedInput(formInput)

	// Advance to third
	input.NextValue() // first
	input.NextValue() // second
	input.NextValue() // third

	// Reset
	input.ResetValueIndex()

	// Should be back to first
	v := input.CurrentValue()
	if v != "first" {
		t.Errorf("Expected 'first' after reset, got %q", v)
	}
}

// TestDetectedInputHasValues tests HasValues.
func TestDetectedInputHasValues(t *testing.T) {
	formInputWithValues := action.NewFormInput(action.InputTypeText, nil)
	formInputWithValues.SetInputValues("value")
	withValues := NewDetectedInput(formInputWithValues)

	formInputWithoutValues := action.NewFormInput(action.InputTypeText, nil)
	withoutValues := NewDetectedInput(formInputWithoutValues)

	if !withValues.HasValues() {
		t.Error("Expected HasValues to be true")
	}
	if withoutValues.HasValues() {
		t.Error("Expected HasValues to be false")
	}
}

// TestDetectedInputCanInteract tests CanInteract.
func TestDetectedInputCanInteract(t *testing.T) {
	normal := NewDetectedInput(action.NewFormInput(action.InputTypeText, nil))
	disabled := NewDetectedInput(action.NewFormInput(action.InputTypeText, nil))
	disabled.Disabled = true
	readonly := NewDetectedInput(action.NewFormInput(action.InputTypeText, nil))
	readonly.ReadOnly = true

	if !normal.CanInteract() {
		t.Error("Normal input should be interactable")
	}
	if disabled.CanInteract() {
		t.Error("Disabled input should not be interactable")
	}
	if readonly.CanInteract() {
		t.Error("ReadOnly input should not be interactable")
	}
}

// TestNewForm tests Form creation.
func TestNewForm(t *testing.T) {
	form := NewForm("/HTML[1]/BODY[1]/FORM[1]")

	if form.XPath != "/HTML[1]/BODY[1]/FORM[1]" {
		t.Errorf("Expected XPath /HTML[1]/BODY[1]/FORM[1], got %q", form.XPath)
	}
	if form.Method != "GET" {
		t.Errorf("Expected Method GET, got %q", form.Method)
	}
	if len(form.Inputs) != 0 {
		t.Errorf("Expected empty Inputs, got %v", form.Inputs)
	}
}

// TestFormAddInput tests adding inputs to form.
func TestFormAddInput(t *testing.T) {
	form := NewForm("/HTML[1]/BODY[1]/FORM[1]")
	input1 := NewDetectedInput(action.NewFormInput(action.InputTypeText, action.NewIdentification(action.HowName, "name")))
	input1.Name = "name"
	input2 := NewDetectedInput(action.NewFormInput(action.InputTypePassword, action.NewIdentification(action.HowName, "password")))
	input2.Name = "password"

	form.AddInput(input1).AddInput(input2)

	expectedCount := 2
	if len(form.Inputs) != expectedCount {
		t.Errorf("Expected %d inputs, got %d", expectedCount, len(form.Inputs))
	}
}

// TestFormGetInput tests finding input by name.
func TestFormGetInput(t *testing.T) {
	form := NewForm("/HTML[1]/BODY[1]/FORM[1]")
	input := NewDetectedInput(action.NewFormInput(action.InputTypeText, action.NewIdentification(action.HowName, "username")))
	input.Name = "username"
	form.AddInput(input)

	found := form.GetInput("username")
	if found == nil {
		t.Fatal("Expected to find input by name")
	}
	if found.Identification.Value != "username" {
		t.Errorf("Expected Identification.Value 'username', got %q", found.Identification.Value)
	}

	notFound := form.GetInput("nonexistent")
	if notFound != nil {
		t.Error("Expected nil for nonexistent input")
	}
}

// TestFormGetInputByID tests finding input by ID.
func TestFormGetInputByID(t *testing.T) {
	form := NewForm("/HTML[1]/BODY[1]/FORM[1]")
	input := NewDetectedInput(action.NewFormInput(action.InputTypeText, action.NewIdentification(action.HowID, "email")))
	input.ID = "email"
	form.AddInput(input)

	found := form.GetInputByID("email")
	if found == nil {
		t.Fatal("Expected to find input by ID")
	}
	if found.Identification.Value != "email" {
		t.Errorf("Expected Identification.Value 'email', got %q", found.Identification.Value)
	}

	notFound := form.GetInputByID("nonexistent")
	if notFound != nil {
		t.Error("Expected nil for nonexistent ID")
	}
}

// TestFormTextInputs tests filtering text-like inputs.
func TestFormTextInputs(t *testing.T) {
	form := NewForm("/HTML[1]/BODY[1]/FORM[1]")
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypeText, nil)))
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypeEmail, nil)))
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypePassword, nil)))
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypeCheckbox, nil)))
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypeSelect, nil)))

	textInputs := form.TextInputs()
	expectedCount := 3
	if len(textInputs) != expectedCount {
		t.Errorf("Expected %d text inputs, got %d", expectedCount, len(textInputs))
	}
}

// TestFormSelectInputs tests filtering select inputs.
func TestFormSelectInputs(t *testing.T) {
	form := NewForm("/HTML[1]/BODY[1]/FORM[1]")
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypeText, nil)))
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypeSelect, nil)))
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypeSelect, nil)))

	selectInputs := form.SelectInputs()
	expectedCount := 2
	if len(selectInputs) != expectedCount {
		t.Errorf("Expected %d select inputs, got %d", expectedCount, len(selectInputs))
	}
}

// TestFormCheckboxInputs tests filtering checkbox inputs.
func TestFormCheckboxInputs(t *testing.T) {
	form := NewForm("/HTML[1]/BODY[1]/FORM[1]")
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypeText, nil)))
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypeCheckbox, nil)))
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypeCheckbox, nil)))

	checkboxInputs := form.CheckboxInputs()
	expectedCount := 2
	if len(checkboxInputs) != expectedCount {
		t.Errorf("Expected %d checkbox inputs, got %d", expectedCount, len(checkboxInputs))
	}
}

// TestFormRadioInputs tests filtering radio inputs.
func TestFormRadioInputs(t *testing.T) {
	form := NewForm("/HTML[1]/BODY[1]/FORM[1]")
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypeText, nil)))
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypeRadio, nil)))
	form.AddInput(NewDetectedInput(action.NewFormInput(action.InputTypeRadio, nil)))

	radioInputs := form.RadioInputs()
	expectedCount := 2
	if len(radioInputs) != expectedCount {
		t.Errorf("Expected %d radio inputs, got %d", expectedCount, len(radioInputs))
	}
}

// TestDetectedInputThreadSafety tests thread safety of value rotation.
func TestDetectedInputThreadSafety(t *testing.T) {
	formInput := action.NewFormInput(action.InputTypeText, nil)
	formInput.SetInputValues("a", "b", "c", "d", "e")
	input := NewDetectedInput(formInput)

	done := make(chan bool)
	iterations := 100

	// Run multiple goroutines accessing values
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < iterations; j++ {
				_ = input.NextValue()
				_ = input.CurrentValue()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// If we get here without panic, thread safety is working
}

// TestEscapeXPathString tests XPath string escaping for quotes.
// GO IMPROVEMENT: Uses double quotes when string only has single quotes (simpler than concat).
func TestEscapeXPathString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// No quotes - use single quotes
		{"simple", "'simple'"},
		{"username", "'username'"},
		{"Test String", "'Test String'"},

		// Single quotes only - use double quotes (simpler than concat!)
		{"father's day", "\"father's day\""},
		{"mother's day", "\"mother's day\""},
		{"I'm Feeling Lucky", "\"I'm Feeling Lucky\""},
		{"o'brien", "\"o'brien\""},

		// Double quotes only - use single quotes
		{"say \"hello\"", "'say \"hello\"'"},
		{"with \"quotes\"", "'with \"quotes\"'"},

		// Both quotes - use concat()
		{"it's \"complex\"", "concat('it', \"'\", 's \"complex\"')"},
		{"say 'hi' and \"bye\"", "concat('say ', \"'\", 'hi', \"'\", ' and \"bye\"')"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := escapeXPathString(tc.input)
			if result != tc.expected {
				t.Errorf("escapeXPathString(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

// TestToFormInputs tests converting DetectedInput slice to FormInput slice.
func TestToFormInputs(t *testing.T) {
	inputs := []*DetectedInput{
		NewDetectedInput(action.NewFormInput(action.InputTypeText, action.NewIdentification(action.HowID, "id1"))),
		NewDetectedInput(action.NewFormInput(action.InputTypePassword, action.NewIdentification(action.HowName, "pass"))),
		nil, // Should be skipped
	}

	formInputs := ToFormInputs(inputs)

	expectedCount := 2
	if len(formInputs) != expectedCount {
		t.Errorf("Expected %d form inputs, got %d", expectedCount, len(formInputs))
	}
}
