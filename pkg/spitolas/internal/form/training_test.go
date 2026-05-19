//go:build !integration

package form

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNewFormTrainer tests FormTrainer creation.
func TestNewFormTrainer(t *testing.T) {
	trainer := NewFormTrainer(FillRandom, "/tmp/test")

	if trainer.Mode != FillRandom {
		t.Errorf("Expected Mode FillRandom, got %v", trainer.Mode)
	}
	if trainer.OutputDir != "/tmp/test" {
		t.Errorf("Expected OutputDir /tmp/test, got %q", trainer.OutputDir)
	}
	if trainer.Data == nil {
		t.Error("Expected Data to be initialized")
	}
	if trainer.Data.Version != "1.0" {
		t.Errorf("Expected Version '1.0', got %q", trainer.Data.Version)
	}
}

// TestFormTrainerSetMode tests mode changes.
func TestFormTrainerSetMode(t *testing.T) {
	trainer := NewFormTrainer(FillRandom, "")

	trainer.SetMode(FillTraining)
	if trainer.GetMode() != FillTraining {
		t.Errorf("Expected FillTraining, got %v", trainer.GetMode())
	}

	trainer.SetMode(FillReplay)
	if trainer.GetMode() != FillReplay {
		t.Errorf("Expected FillReplay, got %v", trainer.GetMode())
	}
}

// TestFormTrainerRecordInput tests input recording.
func TestFormTrainerRecordInput(t *testing.T) {
	trainer := NewFormTrainer(FillTraining, "")

	input := &TrainedInput{
		XPath:    "//input[@id='name']",
		Selector: "#name",
		Type:     "text",
		Name:     "name",
		ID:       "name",
		Value:    "John Doe",
	}

	trainer.RecordInput(input)

	// Verify XPath index
	if trainer.GetInputByXPath(input.XPath) == nil {
		t.Error("Expected input to be indexed by XPath")
	}

	// Verify name index
	nameInputs := trainer.GetInputByName(input.Name)
	expectedNameInputs := 1
	if len(nameInputs) != expectedNameInputs {
		t.Errorf("Expected %d input by name, got %d", expectedNameInputs, len(nameInputs))
	}

	// Verify type index
	typeInputs := trainer.GetInputByType(input.Type)
	expectedTypeInputs := 1
	if len(typeInputs) != expectedTypeInputs {
		t.Errorf("Expected %d input by type, got %d", expectedTypeInputs, len(typeInputs))
	}

	// Verify global inputs
	expectedGlobal := 1
	if len(trainer.Data.GlobalInputs) != expectedGlobal {
		t.Errorf("Expected %d global input, got %d", expectedGlobal, len(trainer.Data.GlobalInputs))
	}
}

// TestFormTrainerRecordForm tests form recording.
func TestFormTrainerRecordForm(t *testing.T) {
	trainer := NewFormTrainer(FillTraining, "")

	form := &TrainedForm{
		ID:     "loginForm",
		Action: "/login",
		Method: "POST",
		XPath:  "//form[@id='loginForm']",
		URL:    "http://example.com/login",
		Inputs: []*TrainedInput{
			{XPath: "//input[@id='user']", Name: "username", Type: "text", Value: "test"},
			{XPath: "//input[@id='pass']", Name: "password", Type: "password", Value: "secret"},
		},
	}

	trainer.RecordForm(form)

	// Verify form was recorded
	expectedForms := 1
	if len(trainer.Data.Forms) != expectedForms {
		t.Errorf("Expected %d form, got %d", expectedForms, len(trainer.Data.Forms))
	}

	// Verify form inputs were indexed
	if trainer.GetInputByXPath("//input[@id='user']") == nil {
		t.Error("Expected form input to be indexed by XPath")
	}
}

// TestFormTrainerMatchInput tests priority-based input matching.
func TestFormTrainerMatchInput(t *testing.T) {
	trainer := NewFormTrainer(FillReplay, "")

	// Record inputs with different identifiers
	xpathInput := &TrainedInput{XPath: "//input[@id='specific']", Value: "xpath_match"}
	idInput := &TrainedInput{ID: "myid", Value: "id_match"}
	nameInput := &TrainedInput{Name: "myname", Type: "text", Value: "name_match"}
	typeInput := &TrainedInput{Type: "email", Value: "type_match"}

	trainer.RecordInput(xpathInput)
	trainer.RecordInput(idInput)
	trainer.RecordInput(nameInput)
	trainer.RecordInput(typeInput)

	// Test XPath priority (highest)
	match := trainer.MatchInput("//input[@id='specific']", "", "", "")
	if match == nil || match.Value != "xpath_match" {
		t.Errorf("Expected xpath_match, got %v", match)
	}

	// Test ID priority
	match = trainer.MatchInput("", "myid", "", "")
	if match == nil || match.Value != "id_match" {
		t.Errorf("Expected id_match, got %v", match)
	}

	// Test name priority (with type preference)
	match = trainer.MatchInput("", "", "myname", "text")
	if match == nil || match.Value != "name_match" {
		t.Errorf("Expected name_match, got %v", match)
	}

	// Test type priority (lowest)
	match = trainer.MatchInput("", "", "", "email")
	if match == nil || match.Value != "type_match" {
		t.Errorf("Expected type_match, got %v", match)
	}
}

// TestFormTrainerGetFormByAction tests finding form by action.
func TestFormTrainerGetFormByAction(t *testing.T) {
	trainer := NewFormTrainer(FillReplay, "")

	form := &TrainedForm{Action: "/submit", Method: "POST"}
	trainer.RecordForm(form)

	found := trainer.GetFormByAction("/submit")
	if found == nil {
		t.Error("Expected to find form by action")
	}

	notFound := trainer.GetFormByAction("/nonexistent")
	if notFound != nil {
		t.Error("Expected nil for nonexistent action")
	}
}

// TestFormTrainerGetFormByXPath tests finding form by XPath.
func TestFormTrainerGetFormByXPath(t *testing.T) {
	trainer := NewFormTrainer(FillReplay, "")

	form := &TrainedForm{XPath: "//form[@id='myform']"}
	trainer.RecordForm(form)

	found := trainer.GetFormByXPath("//form[@id='myform']")
	if found == nil {
		t.Error("Expected to find form by XPath")
	}

	notFound := trainer.GetFormByXPath("//form[@id='other']")
	if notFound != nil {
		t.Error("Expected nil for nonexistent XPath")
	}
}

// TestFormTrainerSaveLoad tests persistence.
func TestFormTrainerSaveLoad(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "form_training_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create trainer and record data
	trainer := NewFormTrainer(FillTraining, tmpDir)
	trainer.RecordInput(&TrainedInput{
		XPath: "//input[@id='test']",
		Name:  "test",
		Type:  "text",
		Value: "test_value",
	})
	trainer.RecordForm(&TrainedForm{
		Action: "/test",
		XPath:  "//form",
		Inputs: []*TrainedInput{
			{Name: "field1", Value: "value1"},
		},
	})

	// Save
	if err := trainer.Save(); err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Verify file exists
	filePath := filepath.Join(tmpDir, "form_training.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Error("Expected training file to exist")
	}

	// Create new trainer and load
	trainer2 := NewFormTrainer(FillReplay, tmpDir)
	if err := trainer2.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify data was loaded
	expectedGlobal := 1
	if len(trainer2.Data.GlobalInputs) != expectedGlobal {
		t.Errorf("Expected %d global input, got %d", expectedGlobal, len(trainer2.Data.GlobalInputs))
	}

	expectedForms := 1
	if len(trainer2.Data.Forms) != expectedForms {
		t.Errorf("Expected %d form, got %d", expectedForms, len(trainer2.Data.Forms))
	}

	// Verify indexes were rebuilt
	if trainer2.GetInputByXPath("//input[@id='test']") == nil {
		t.Error("Expected XPath index to be rebuilt")
	}
}

// TestFormTrainerLoadNoFile tests loading when no file exists.
func TestFormTrainerLoadNoFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "form_training_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	trainer := NewFormTrainer(FillReplay, tmpDir)

	// Load should succeed even if file doesn't exist
	if err := trainer.Load(); err != nil {
		t.Errorf("Load() should succeed with no file: %v", err)
	}
}

// TestFormTrainerSaveNoDir tests save error without directory.
func TestFormTrainerSaveNoDir(t *testing.T) {
	trainer := NewFormTrainer(FillTraining, "")

	err := trainer.Save()
	if err == nil {
		t.Error("Expected error when OutputDir is empty")
	}
}

// TestFormTrainerClear tests clearing data.
func TestFormTrainerClear(t *testing.T) {
	trainer := NewFormTrainer(FillTraining, "")

	trainer.RecordInput(&TrainedInput{XPath: "//test", Name: "test", Type: "text"})
	trainer.RecordForm(&TrainedForm{Action: "/test"})

	// Verify data exists
	if len(trainer.Data.GlobalInputs) == 0 {
		t.Error("Expected data before clear")
	}

	// Clear
	trainer.Clear()

	// Verify cleared
	if len(trainer.Data.GlobalInputs) != 0 {
		t.Error("Expected no global inputs after clear")
	}
	if len(trainer.Data.Forms) != 0 {
		t.Error("Expected no forms after clear")
	}
	if trainer.GetInputByXPath("//test") != nil {
		t.Error("Expected XPath index to be cleared")
	}
}

// TestFormTrainerStats tests statistics.
func TestFormTrainerStats(t *testing.T) {
	trainer := NewFormTrainer(FillTraining, "")

	// Record varied data
	trainer.RecordInput(&TrainedInput{XPath: "//a", Name: "name1", Type: "text"})
	trainer.RecordInput(&TrainedInput{XPath: "//b", Name: "name2", Type: "email"})
	trainer.RecordForm(&TrainedForm{
		Inputs: []*TrainedInput{
			{Name: "f1"},
			{Name: "f2"},
			{Name: "f3"},
		},
	})

	stats := trainer.Stats()

	expectedForms := 1
	if stats.TotalForms != expectedForms {
		t.Errorf("Expected %d forms, got %d", expectedForms, stats.TotalForms)
	}

	expectedGlobal := 2
	if stats.TotalGlobalInputs != expectedGlobal {
		t.Errorf("Expected %d global inputs, got %d", expectedGlobal, stats.TotalGlobalInputs)
	}

	expectedFormInputs := 3
	if stats.TotalFormInputs != expectedFormInputs {
		t.Errorf("Expected %d form inputs, got %d", expectedFormInputs, stats.TotalFormInputs)
	}

	expectedXPaths := 2
	if stats.UniqueXPaths != expectedXPaths {
		t.Errorf("Expected %d unique XPaths, got %d", expectedXPaths, stats.UniqueXPaths)
	}

	// UniqueNames = 5 (name1, name2, f1, f2, f3) - all are indexed
	expectedNames := 5
	if stats.UniqueNames != expectedNames {
		t.Errorf("Expected %d unique names, got %d", expectedNames, stats.UniqueNames)
	}

	// UniqueTypes = 2 (text, email) - form inputs have no type set so not indexed
	expectedTypes := 2
	if stats.UniqueTypes != expectedTypes {
		t.Errorf("Expected %d unique types, got %d", expectedTypes, stats.UniqueTypes)
	}
}

// TestFormTrainerExportToCSV tests CSV export.
func TestFormTrainerExportToCSV(t *testing.T) {
	trainer := NewFormTrainer(FillTraining, "")

	trainer.RecordInput(&TrainedInput{
		XPath:      "//input",
		Selector:   "#test",
		Type:       "text",
		Name:       "test",
		ID:         "test",
		Value:      "value",
		FormID:     "form1",
		FormAction: "/submit",
	})

	csv, err := trainer.ExportToCSV()
	if err != nil {
		t.Fatalf("ExportToCSV() failed: %v", err)
	}

	// Verify header
	if !containsSubstring(csv, "xpath,selector,type,name,id,value,form_id,form_action") {
		t.Error("Expected CSV to contain header")
	}

	// Verify data row
	if !containsSubstring(csv, "//input") {
		t.Error("Expected CSV to contain XPath")
	}
}

// TestFormTrainerImportFromCSV tests CSV import.
func TestFormTrainerImportFromCSV(t *testing.T) {
	trainer := NewFormTrainer(FillReplay, "")

	csv := `xpath,selector,type,name,id,value,form_id,form_action
"//input[@id='test']","#test","text","test","test","value","form1","/submit"
`

	if err := trainer.ImportFromCSV(csv); err != nil {
		t.Fatalf("ImportFromCSV() failed: %v", err)
	}

	// Verify data was imported
	expectedGlobal := 1
	if len(trainer.Data.GlobalInputs) != expectedGlobal {
		t.Errorf("Expected %d global input, got %d", expectedGlobal, len(trainer.Data.GlobalInputs))
	}

	// Verify indexes
	if trainer.GetInputByXPath("//input[@id='test']") == nil {
		t.Error("Expected XPath index to be created")
	}
}

// TestFormTrainerImportFromCSVInvalid tests invalid CSV handling.
func TestFormTrainerImportFromCSVInvalid(t *testing.T) {
	trainer := NewFormTrainer(FillReplay, "")

	// Only header, no data
	csv := "xpath,selector,type,name,id,value"

	err := trainer.ImportFromCSV(csv)
	if err == nil {
		t.Error("Expected error for CSV with only header")
	}
}

// TestTrainingModeConstants tests training mode values.
func TestTrainingModeConstants(t *testing.T) {
	tests := []struct {
		mode     TrainingMode
		expected int
	}{
		{FillRandom, 0},
		{FillTraining, 1},
		{FillXPathTraining, 2},
		{FillReplay, 3},
	}

	for _, tc := range tests {
		if int(tc.mode) != tc.expected {
			t.Errorf("Expected %d, got %d", tc.expected, tc.mode)
		}
	}
}

// TestTrainedInputFields tests TrainedInput structure.
func TestTrainedInputFields(t *testing.T) {
	input := &TrainedInput{
		XPath:      "//input[@id='test']",
		Selector:   "#test",
		Type:       "text",
		Name:       "test",
		ID:         "test",
		FormID:     "form1",
		FormAction: "/submit",
		Value:      "value",
		Values:     []string{"v1", "v2"},
		Checked:    true,
		Priority:   10,
	}

	if input.XPath != "//input[@id='test']" {
		t.Errorf("XPath mismatch: %q", input.XPath)
	}
	if input.Selector != "#test" {
		t.Errorf("Selector mismatch: %q", input.Selector)
	}
	if input.Type != "text" {
		t.Errorf("Type mismatch: %q", input.Type)
	}
	if input.Name != "test" {
		t.Errorf("Name mismatch: %q", input.Name)
	}
	if input.ID != "test" {
		t.Errorf("ID mismatch: %q", input.ID)
	}
	if input.FormID != "form1" {
		t.Errorf("FormID mismatch: %q", input.FormID)
	}
	if input.FormAction != "/submit" {
		t.Errorf("FormAction mismatch: %q", input.FormAction)
	}
	if input.Value != "value" {
		t.Errorf("Value mismatch: %q", input.Value)
	}
	expectedValuesLen := 2
	if len(input.Values) != expectedValuesLen {
		t.Errorf("Values length mismatch: expected %d, got %d", expectedValuesLen, len(input.Values))
	}
	if !input.Checked {
		t.Error("Checked mismatch")
	}
	if input.Priority != 10 {
		t.Errorf("Priority mismatch: %d", input.Priority)
	}
}

// TestTrainedFormFields tests TrainedForm structure.
func TestTrainedFormFields(t *testing.T) {
	form := &TrainedForm{
		ID:     "testForm",
		Name:   "test",
		Action: "/submit",
		Method: "POST",
		XPath:  "//form",
		URL:    "http://example.com",
		Inputs: []*TrainedInput{
			{Name: "field1"},
		},
	}

	if form.ID != "testForm" {
		t.Errorf("ID mismatch: %q", form.ID)
	}
	if form.Name != "test" {
		t.Errorf("Name mismatch: %q", form.Name)
	}
	if form.Action != "/submit" {
		t.Errorf("Action mismatch: %q", form.Action)
	}
	if form.Method != "POST" {
		t.Errorf("Method mismatch: %q", form.Method)
	}
	if form.XPath != "//form" {
		t.Errorf("XPath mismatch: %q", form.XPath)
	}
	if form.URL != "http://example.com" {
		t.Errorf("URL mismatch: %q", form.URL)
	}
	expectedInputsLen := 1
	if len(form.Inputs) != expectedInputsLen {
		t.Errorf("Inputs length mismatch: expected %d, got %d", expectedInputsLen, len(form.Inputs))
	}
}

// TestFormTrainerThreadSafety tests concurrent access.
func TestFormTrainerThreadSafety(t *testing.T) {
	trainer := NewFormTrainer(FillTraining, "")

	done := make(chan bool)
	iterations := 100

	// Concurrent writers
	for i := 0; i < 5; i++ {
		go func(id int) {
			for j := 0; j < iterations; j++ {
				trainer.RecordInput(&TrainedInput{
					XPath: "//test",
					Name:  "test",
					Type:  "text",
				})
			}
			done <- true
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < iterations; j++ {
				_ = trainer.GetInputByXPath("//test")
				_ = trainer.GetInputByName("test")
				_ = trainer.GetMode()
				_ = trainer.Stats()
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

// Helper function
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
