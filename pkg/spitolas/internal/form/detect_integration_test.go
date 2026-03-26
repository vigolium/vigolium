//go:build integration

package form

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// setupDetectTestServer creates a test server for detection tests.
func setupDetectTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.FileServer(http.Dir("testdata")))
}

// setupDetectBrowser creates a browser for detection tests.
func setupDetectBrowser(t *testing.T, serverURL string) *browser.Browser {
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

// TestDetectorHasForms tests form detection on page.
func TestDetectorHasForms(t *testing.T) {
	server := setupDetectTestServer(t)
	defer server.Close()

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	detector := NewDetector()

	// form_test.html has exactly 1 form
	if !detector.HasForms(page) {
		t.Error("Expected HasForms() to return true")
	}
}

// TestDetectorHasFormsNone tests HasForms on page without forms.
func TestDetectorHasFormsNone(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("../browser/testdata")))
	defer server.Close()

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// simple.html has no forms
	if err := page.Navigate(server.URL + "/simple.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	detector := NewDetector()

	if detector.HasForms(page) {
		t.Error("Expected HasForms() to return false for simple.html")
	}
}

// TestDetectorHasInputs tests input detection on page.
func TestDetectorHasInputs(t *testing.T) {
	server := setupDetectTestServer(t)
	defer server.Close()

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	detector := NewDetector()

	// form_test.html has many inputs
	if !detector.HasInputs(page) {
		t.Error("Expected HasInputs() to return true")
	}
}

// TestDetectorCountForms tests form counting.
func TestDetectorCountForms(t *testing.T) {
	server := setupDetectTestServer(t)
	defer server.Close()

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	detector := NewDetector()

	// form_test.html has exactly 1 form
	count := detector.CountForms(page)
	expectedCount := 1
	if count != expectedCount {
		t.Errorf("Expected %d form, got %d", expectedCount, count)
	}
}

// TestDetectorCountInputs tests input counting.
func TestDetectorCountInputs(t *testing.T) {
	server := setupDetectTestServer(t)
	defer server.Close()

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	detector := NewDetector()

	// form_test.html has exactly 23 inputs:
	// text(4: name, disabled, readonly, standalone), email(1), password(1), number(1), tel(1), url(1), search(1),
	// textarea(1), hidden(1), checkbox(2), radio(5), select(2),
	// date(1), time(1), color(1), range(1), file(4)
	count := detector.CountInputs(page)
	expectedCount := 29
	if count != expectedCount {
		t.Errorf("Expected %d inputs, got %d", expectedCount, count)
	}
}

// TestDetectorGetLoginForm tests login form detection.
func TestDetectorGetLoginForm(t *testing.T) {
	// Create a simple login page
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<form id="loginForm" action="/login" method="POST">
    <input type="text" id="username" name="username" placeholder="Username">
    <input type="password" id="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
</form>
</body>
</html>`))
	}))
	defer server.Close()

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	detector := NewDetector()
	loginForm := detector.GetLoginForm(page)

	if loginForm == nil {
		t.Fatal("Expected to detect login form")
	}

	// Should have exactly 2 inputs (username and password)
	expectedInputs := 2
	if len(loginForm.Inputs) != expectedInputs {
		t.Errorf("Expected %d inputs, got %d", expectedInputs, len(loginForm.Inputs))
	}
}

// TestDetectorGetLoginFormNone tests when no login form exists.
func TestDetectorGetLoginFormNone(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("../browser/testdata")))
	defer server.Close()

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// simple.html has no login form
	if err := page.Navigate(server.URL + "/simple.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	detector := NewDetector()
	loginForm := detector.GetLoginForm(page)

	if loginForm != nil {
		t.Error("Expected no login form on simple.html")
	}
}

// TestDetectorGetSearchForm tests search form detection.
func TestDetectorGetSearchForm(t *testing.T) {
	// Create a simple page with search
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Search</title></head>
<body>
<form id="searchForm" action="/search" method="GET">
    <input type="search" id="q" name="q" placeholder="Search...">
    <button type="submit">Search</button>
</form>
</body>
</html>`))
	}))
	defer server.Close()

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	detector := NewDetector()
	searchForm := detector.GetSearchForm(page)

	if searchForm == nil {
		t.Fatal("Expected to detect search form")
	}

	// Should have exactly 1 input (search)
	expectedInputs := 1
	if len(searchForm.Inputs) != expectedInputs {
		t.Errorf("Expected %d input, got %d", expectedInputs, len(searchForm.Inputs))
	}
}

// TestDetectorGetSearchFormByName tests search detection by input name.
func TestDetectorGetSearchFormByName(t *testing.T) {
	// Search input with name="q" (common pattern)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Search</title></head>
<body>
<input type="text" name="q" placeholder="Search">
</body>
</html>`))
	}))
	defer server.Close()

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	detector := NewDetector()
	searchForm := detector.GetSearchForm(page)

	if searchForm == nil {
		t.Fatal("Expected to detect search form by name='q'")
	}
}

// TestDetectorGetSelectOptions tests getting select options.
func TestDetectorGetSelectOptions(t *testing.T) {
	server := setupDetectTestServer(t)
	defer server.Close()

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	detector := NewDetector()

	// Get options from country select (use XPath)
	options, err := detector.GetSelectOptions(page, "//*[@id='country']")
	if err != nil {
		t.Fatalf("GetSelectOptions() failed: %v", err)
	}

	// form_test.html #country has 5 options (including empty first option)
	expectedCount := 5
	if len(options) != expectedCount {
		t.Errorf("Expected %d options, got %d", expectedCount, len(options))
	}
}

// TestDetectorGetRadioOptions tests getting radio button options.
func TestDetectorGetRadioOptions(t *testing.T) {
	server := setupDetectTestServer(t)
	defer server.Close()

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	detector := NewDetector()

	// Get options from gender radio group
	options, err := detector.GetRadioOptions(page, "gender")
	if err != nil {
		t.Fatalf("GetRadioOptions() failed: %v", err)
	}

	// form_test.html has exactly 3 gender radio buttons
	expectedCount := 3
	if len(options) != expectedCount {
		t.Errorf("Expected %d radio options, got %d", expectedCount, len(options))
	}

	// Verify exact values
	expectedValues := map[string]bool{"male": true, "female": true, "other": true}
	for _, opt := range options {
		if !expectedValues[opt] {
			t.Errorf("Unexpected radio option: %q", opt)
		}
	}
}

// TestHandlerDetectForms tests Handler's form detection.
func TestHandlerDetectForms(t *testing.T) {
	server := setupDetectTestServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)
	forms, err := handler.DetectForms(page)
	if err != nil {
		t.Fatalf("DetectForms() failed: %v", err)
	}

	// form_test.html has exactly 1 form
	expectedForms := 1
	if len(forms) != expectedForms {
		t.Errorf("Expected %d form, got %d", expectedForms, len(forms))
	}

	if len(forms) > 0 {
		form := forms[0]

		// Verify form has action
		if form.Action == "" {
			t.Error("Expected form to have action")
		}

		// Verify form has method
		if form.Method == "" {
			t.Error("Expected form to have method")
		}

		// Form should have many inputs (excluding standalone)
		// Form has: text(3 - name, disabled, readonly), email(1), password(1), number(1), tel(1), url(1), search(1),
		// textarea(1), hidden(1), checkbox(2), radio(5), select(2),
		// date(1), time(1), color(1), range(1), file(4) = 28 inputs
		expectedInputs := 28
		if len(form.Inputs) != expectedInputs {
			t.Errorf("Expected %d form inputs, got %d", expectedInputs, len(form.Inputs))
		}
	}
}

// TestHandlerDetectInputs tests Handler's input detection.
func TestHandlerDetectInputs(t *testing.T) {
	server := setupDetectTestServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)
	inputs, err := handler.DetectInputs(page)
	if err != nil {
		t.Fatalf("DetectInputs() failed: %v", err)
	}

	// form_test.html has exactly 29 total inputs (28 in form + 1 standalone)
	expectedInputs := 29
	if len(inputs) != expectedInputs {
		t.Errorf("Expected %d inputs, got %d", expectedInputs, len(inputs))
	}
}

// TestHandlerDetectInputTypes tests correct input type detection.
func TestHandlerDetectInputTypes(t *testing.T) {
	server := setupDetectTestServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)
	inputs, err := handler.DetectInputs(page)
	if err != nil {
		t.Fatalf("DetectInputs() failed: %v", err)
	}

	// Count input types
	typeCounts := make(map[action.InputType]int)
	for _, input := range inputs {
		typeCounts[input.FormInput.Type]++
	}

	// Verify expected counts for each type
	expectedCounts := map[action.InputType]int{
		action.InputTypeText:     4, // name, disabled_field, readonly_field, standalone
		action.InputTypeEmail:    1,
		action.InputTypePassword: 1,
		action.InputTypeNumber:   1,
		action.InputTypeTel:      1,
		action.InputTypeURL:      1,
		action.InputTypeSearch:   1,
		action.InputTypeTextarea: 1,
		action.InputTypeHidden:   1,
		action.InputTypeCheckbox: 2,
		action.InputTypeRadio:    5,
		action.InputTypeSelect:   2,
		action.InputTypeDate:     1,
		action.InputTypeTime:     1,
		action.InputTypeColor:    1,
		action.InputTypeRange:    1,
	}

	for inputType, expectedCount := range expectedCounts {
		if typeCounts[inputType] != expectedCount {
			t.Errorf("Expected %d %s inputs, got %d", expectedCount, inputType, typeCounts[inputType])
		}
	}
}

// TestHandlerDetectInputAttributes tests attribute detection.
func TestHandlerDetectInputAttributes(t *testing.T) {
	server := setupDetectTestServer(t)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true

	b := setupDetectBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	handler := NewHandler(cfg)
	inputs, err := handler.DetectInputs(page)
	if err != nil {
		t.Fatalf("DetectInputs() failed: %v", err)
	}

	// Find specific inputs and verify attributes
	var disabledInput, readonlyInput *DetectedInput
	for _, input := range inputs {
		if input.ID == "disabled_field" {
			disabledInput = input
		}
		if input.ID == "readonly_field" {
			readonlyInput = input
		}
	}

	if disabledInput == nil {
		t.Fatal("Expected to find disabled_field input")
	}
	if !disabledInput.Disabled {
		t.Error("Expected disabled_field to have Disabled=true")
	}

	if readonlyInput == nil {
		t.Fatal("Expected to find readonly_field input")
	}
	if !readonlyInput.ReadOnly {
		t.Error("Expected readonly_field to have ReadOnly=true")
	}
}
