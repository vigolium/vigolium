//go:build integration

package form

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// setupFormTestServer creates a test server serving form testdata.
func setupFormTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.FileServer(http.Dir("testdata")))
}

// setupFormBrowser creates a browser for form testing.
func setupFormBrowser(t *testing.T, serverURL string) *browser.Browser {
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

// TestFillText tests filling text inputs.
// Crawljax parity: handleText()
func TestFillText(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Test filling text
	expectedValue := "John Doe"
	if err := FillText(elem, expectedValue); err != nil {
		t.Fatalf("FillText() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	value, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	if value != expectedValue {
		t.Errorf("Expected %q, got %q", expectedValue, value)
	}
}

// TestFillTextEmail tests filling email inputs.
func TestFillTextEmail(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#email")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	expectedValue := "test@example.com"
	if err := FillText(elem, expectedValue); err != nil {
		t.Fatalf("FillText() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	value, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	if value != expectedValue {
		t.Errorf("Expected %q, got %q", expectedValue, value)
	}
}

// TestFillTextPassword tests filling password inputs.
func TestFillTextPassword(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#password")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	expectedValue := "SecurePass123!"
	if err := FillText(elem, expectedValue); err != nil {
		t.Fatalf("FillText() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	value, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	if value != expectedValue {
		t.Errorf("Expected %q, got %q", expectedValue, value)
	}
}

// TestFillTextClearsExisting tests that FillText clears existing content.
// Crawljax parity: shouldClearTextFieldBeforeSettingValue()
func TestFillTextClearsExisting(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Fill with initial value
	if err := elem.Input("Initial Value"); err != nil {
		t.Fatalf("Input() failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Verify initial value
	initialValue, _ := elem.Property("value")
	if initialValue != "Initial Value" {
		t.Errorf("Expected initial 'Initial Value', got %q", initialValue)
	}

	// Fill with new value - should clear old
	expectedValue := "New Value"
	if err := FillText(elem, expectedValue); err != nil {
		t.Fatalf("FillText() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	value, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	// Should be "New Value", not "Initial ValueNew Value"
	if value != expectedValue {
		t.Errorf("Expected %q (cleared), got %q", expectedValue, value)
	}
}

// TestFillHidden tests filling hidden inputs.
// Crawljax parity: handleHidden()
func TestFillHidden(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#hidden_field")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	expectedValue := "hidden_value_123"
	if err := FillHidden(elem, expectedValue); err != nil {
		t.Fatalf("FillHidden() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	value, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	if value != expectedValue {
		t.Errorf("Expected %q, got %q", expectedValue, value)
	}
}

// TestFillCheckboxCheck tests checking a checkbox.
// Crawljax parity: handleCheckBoxes()
func TestFillCheckboxCheck(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#agree")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Verify initially unchecked
	initialChecked, _ := IsChecked(elem)
	if initialChecked {
		t.Error("Expected checkbox to be initially unchecked")
	}

	// Check the checkbox
	if err := FillCheckbox(elem, true); err != nil {
		t.Fatalf("FillCheckbox() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Verify checked
	checked, err := IsChecked(elem)
	if err != nil {
		t.Fatalf("IsChecked() failed: %v", err)
	}

	if !checked {
		t.Error("Expected checkbox to be checked")
	}
}

// TestFillCheckboxUncheck tests unchecking a checkbox.
func TestFillCheckboxUncheck(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#agree")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// First check it
	if err := FillCheckbox(elem, true); err != nil {
		t.Fatalf("FillCheckbox(true) failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Verify checked
	checked, _ := IsChecked(elem)
	if !checked {
		t.Error("Expected checkbox to be checked first")
	}

	// Then uncheck it
	if err := FillCheckbox(elem, false); err != nil {
		t.Fatalf("FillCheckbox(false) failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Verify unchecked
	unchecked, err := IsChecked(elem)
	if err != nil {
		t.Fatalf("IsChecked() failed: %v", err)
	}

	if unchecked {
		t.Error("Expected checkbox to be unchecked")
	}
}

// TestFillRadio tests selecting a radio button.
// CRAWLJAX PARITY: handleRadioSwitches() - clicks radio if value="1"
func TestFillRadio(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#gender_m")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Crawljax: value "1" means checked
	if err := FillRadio(elem, "1"); err != nil {
		t.Fatalf("FillRadio() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Verify male is selected
	maleChecked, _ := IsChecked(elem)
	if !maleChecked {
		t.Error("Expected male radio to be selected")
	}

	// Verify female is not selected
	femaleElem, _ := page.Element("#gender_f")
	femaleChecked, _ := IsChecked(femaleElem)
	if femaleChecked {
		t.Error("Expected female radio to not be selected")
	}
}

// TestFillRadioSwitchValue tests switching radio values between elements.
// CRAWLJAX PARITY: Each radio is identified individually and clicked separately.
func TestFillRadioSwitchValue(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	maleElem, err := page.Element("#gender_m")
	if err != nil {
		t.Fatalf("Element(#gender_m) failed: %v", err)
	}

	femaleElem, err := page.Element("#gender_f")
	if err != nil {
		t.Fatalf("Element(#gender_f) failed: %v", err)
	}

	// First select male
	if err := FillRadio(maleElem, "1"); err != nil {
		t.Fatalf("FillRadio(male) failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Verify male is selected
	maleChecked, _ := IsChecked(maleElem)
	if !maleChecked {
		t.Error("Expected male radio to be selected after first click")
	}

	// Then select female - should deselect male (browser behavior)
	if err := FillRadio(femaleElem, "1"); err != nil {
		t.Fatalf("FillRadio(female) failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Verify female is now selected
	femaleChecked, _ := IsChecked(femaleElem)
	if !femaleChecked {
		t.Error("Expected female radio to be selected")
	}

	// Verify male is no longer selected (browser auto-deselects same-name radios)
	maleChecked, _ = IsChecked(maleElem)
	if maleChecked {
		t.Error("Expected male radio to be deselected")
	}
}

// TestFillRadioWithoutName tests radio buttons without name attribute.
// CRAWLJAX PARITY: Radio is identified by id/xpath, name not required.
func TestFillRadioWithoutName(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Get radio without name attribute
	elem, err := page.Element("#option_a")
	if err != nil {
		t.Fatalf("Element(#option_a) failed: %v", err)
	}

	// Should work without error - no name attribute required
	if err := FillRadio(elem, "1"); err != nil {
		t.Fatalf("FillRadio() failed for radio without name: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Verify radio is selected
	checked, _ := IsChecked(elem)
	if !checked {
		t.Error("Expected radio without name to be selected")
	}
}

// TestFillRadioAlreadyChecked tests that already-checked radio doesn't get double-clicked.
// CRAWLJAX PARITY: Only clicks if not already selected.
func TestFillRadioAlreadyChecked(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#gender_m")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// First click to check
	if err := FillRadio(elem, "1"); err != nil {
		t.Fatalf("First FillRadio() failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Second call should succeed without error (no double-click)
	if err := FillRadio(elem, "1"); err != nil {
		t.Fatalf("Second FillRadio() failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Should still be checked
	checked, _ := IsChecked(elem)
	if !checked {
		t.Error("Expected radio to remain checked")
	}
}

// TestFillRadioValueZero tests that value "0" does nothing.
// CRAWLJAX PARITY: Value "0" means unchecked - do nothing.
func TestFillRadioValueZero(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#gender_m")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Value "0" should do nothing - radio stays unchecked
	if err := FillRadio(elem, "0"); err != nil {
		t.Fatalf("FillRadio(0) failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Should remain unchecked
	checked, _ := IsChecked(elem)
	if checked {
		t.Error("Expected radio to remain unchecked with value '0'")
	}
}

// TestFillSelect tests selecting a dropdown option.
// Crawljax parity: handleSelectBoxes()
func TestFillSelect(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#country")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Select by value
	if err := FillSelect(elem, "us"); err != nil {
		t.Fatalf("FillSelect() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	value, err := GetInputValue(elem)
	if err != nil {
		t.Fatalf("GetInputValue() failed: %v", err)
	}

	expectedValue := "us"
	if value != expectedValue {
		t.Errorf("Expected %q, got %q", expectedValue, value)
	}
}

// TestFillSelectByText tests selecting by option text.
func TestFillSelectByText(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#country")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Select by text content
	if err := FillSelect(elem, "United Kingdom"); err != nil {
		t.Fatalf("FillSelect() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	value, err := GetInputValue(elem)
	if err != nil {
		t.Fatalf("GetInputValue() failed: %v", err)
	}

	expectedValue := "uk"
	if value != expectedValue {
		t.Errorf("Expected %q, got %q", expectedValue, value)
	}
}

// TestFillSelectMultiple tests selecting multiple options.
func TestFillSelectMultiple(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#languages")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Select multiple values
	if err := FillSelectMultiple(elem, []string{"en", "es"}); err != nil {
		t.Fatalf("FillSelectMultiple() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	selected, err := GetSelectedOptions(elem)
	if err != nil {
		t.Fatalf("GetSelectedOptions() failed: %v", err)
	}

	expectedCount := 2
	if len(selected) != expectedCount {
		t.Errorf("Expected %d selected options, got %d", expectedCount, len(selected))
	}
}

// TestFillDate tests filling date inputs.
func TestFillDate(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#birthdate")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	expectedValue := "2000-01-15"
	if err := FillDate(elem, expectedValue); err != nil {
		t.Fatalf("FillDate() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	value, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	if value != expectedValue {
		t.Errorf("Expected %q, got %q", expectedValue, value)
	}
}

// TestFillTime tests filling time inputs.
func TestFillTime(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#meeting_time")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	expectedValue := "14:30"
	if err := FillDate(elem, expectedValue); err != nil {
		t.Fatalf("FillDate() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	value, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	if value != expectedValue {
		t.Errorf("Expected %q, got %q", expectedValue, value)
	}
}

// TestClearInput tests clearing input values.
func TestClearInput(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Fill with value first
	if err := FillText(elem, "Test Value"); err != nil {
		t.Fatalf("FillText() failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Clear
	if err := ClearInput(elem); err != nil {
		t.Fatalf("ClearInput() failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	value, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	expectedValue := ""
	if value != expectedValue {
		t.Errorf("Expected empty string, got %q", value)
	}
}

// TestGetInputValue tests getting input values.
func TestGetInputValue(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Fill with value
	expectedValue := "Test Value"
	if err := FillText(elem, expectedValue); err != nil {
		t.Fatalf("FillText() failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Get value
	value, err := GetInputValue(elem)
	if err != nil {
		t.Fatalf("GetInputValue() failed: %v", err)
	}

	if value != expectedValue {
		t.Errorf("Expected %q, got %q", expectedValue, value)
	}
}

// TestIsChecked tests checkbox/radio checked state.
func TestIsChecked(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#agree")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Initially unchecked
	checked, err := IsChecked(elem)
	if err != nil {
		t.Fatalf("IsChecked() failed: %v", err)
	}
	if checked {
		t.Error("Expected initially unchecked")
	}

	// Check it
	FillCheckbox(elem, true)
	time.Sleep(50 * time.Millisecond)

	// Now checked
	checked, err = IsChecked(elem)
	if err != nil {
		t.Fatalf("IsChecked() failed: %v", err)
	}
	if !checked {
		t.Error("Expected checked after FillCheckbox(true)")
	}
}

// TestGetSelectedOptions tests getting selected options from select.
func TestGetSelectedOptions(t *testing.T) {
	server := setupFormTestServer(t)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#languages")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Select options
	FillSelectMultiple(elem, []string{"en", "fr"})
	time.Sleep(50 * time.Millisecond)

	// Get selected
	selected, err := GetSelectedOptions(elem)
	if err != nil {
		t.Fatalf("GetSelectedOptions() failed: %v", err)
	}

	expectedCount := 2
	if len(selected) != expectedCount {
		t.Errorf("Expected %d selected, got %d", expectedCount, len(selected))
	}
}

// TestFillTextNilElement tests nil element handling.
func TestFillTextNilElement(t *testing.T) {
	err := FillText(nil, "value")
	if err == nil {
		t.Error("Expected error for nil element")
	}
}

// TestFillHiddenNilElement tests nil element handling.
func TestFillHiddenNilElement(t *testing.T) {
	err := FillHidden(nil, "value")
	if err == nil {
		t.Error("Expected error for nil element")
	}
}

// TestFillCheckboxNilElement tests nil element handling.
func TestFillCheckboxNilElement(t *testing.T) {
	err := FillCheckbox(nil, true)
	if err == nil {
		t.Error("Expected error for nil element")
	}
}

// TestFillRadioNilElement tests nil element handling.
func TestFillRadioNilElement(t *testing.T) {
	err := FillRadio(nil, "value")
	if err == nil {
		t.Error("Expected error for nil element")
	}
}

// TestFillSelectNilElement tests nil element handling.
func TestFillSelectNilElement(t *testing.T) {
	err := FillSelect(nil, "value")
	if err == nil {
		t.Error("Expected error for nil element")
	}
}

// TestFillSelectMultipleNilElement tests nil element handling.
func TestFillSelectMultipleNilElement(t *testing.T) {
	err := FillSelectMultiple(nil, []string{"value"})
	if err == nil {
		t.Error("Expected error for nil element")
	}
}

// TestFillDateNilElement tests nil element handling.
func TestFillDateNilElement(t *testing.T) {
	err := FillDate(nil, "2000-01-01")
	if err == nil {
		t.Error("Expected error for nil element")
	}
}

// TestFillFileNilElement tests nil element handling.
func TestFillFileNilElement(t *testing.T) {
	err := FillFile(nil, []string{"/path/to/file"})
	if err == nil {
		t.Error("Expected error for nil element")
	}
}

// TestClearInputNilElement tests nil element handling.
func TestClearInputNilElement(t *testing.T) {
	err := ClearInput(nil)
	if err == nil {
		t.Error("Expected error for nil element")
	}
}

// TestGetInputValueNilElement tests nil element handling.
func TestGetInputValueNilElement(t *testing.T) {
	_, err := GetInputValue(nil)
	if err == nil {
		t.Error("Expected error for nil element")
	}
}

// TestIsCheckedNilElement tests nil element handling.
func TestIsCheckedNilElement(t *testing.T) {
	_, err := IsChecked(nil)
	if err == nil {
		t.Error("Expected error for nil element")
	}
}

// TestGetSelectedOptionsNilElement tests nil element handling.
func TestGetSelectedOptionsNilElement(t *testing.T) {
	_, err := GetSelectedOptions(nil)
	if err == nil {
		t.Error("Expected error for nil element")
	}
}
