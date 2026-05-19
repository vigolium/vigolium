//go:build integration

package form

import (
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// TestFillFileWithGeneratedPNG tests uploading the generated default PNG file.
// GO EXTENSION: File upload support via CDP DOM.setFileInputFiles.
func TestFillFileWithGeneratedPNG(t *testing.T) {
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

	elem, err := page.Element("#avatar")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Get default file path
	filePath, err := GetDefaultFilePath()
	if err != nil {
		t.Fatalf("GetDefaultFilePath() failed: %v", err)
	}

	// Upload file
	if err := FillFile(elem, []string{filePath}); err != nil {
		t.Fatalf("FillFile() failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify file was uploaded by checking files property
	result, err := elem.EvalWithResult(`() => {
		if (this.files && this.files.length > 0) {
			return {
				count: this.files.length,
				name: this.files[0].name,
				type: this.files[0].type,
				size: this.files[0].size
			};
		}
		return { count: 0 };
	}`)
	if err != nil {
		t.Fatalf("EvalWithResult() failed: %v", err)
	}

	fileInfo, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}

	count, _ := fileInfo["count"].(float64)
	if count != 1 {
		t.Errorf("Expected 1 file, got %v", count)
	}

	name, _ := fileInfo["name"].(string)
	expectedName := DefaultPNGName
	if name != expectedName {
		t.Errorf("Expected file name %q, got %q", expectedName, name)
	}

	fileType, _ := fileInfo["type"].(string)
	expectedType := "image/png"
	if fileType != expectedType {
		t.Errorf("Expected file type %q, got %q", expectedType, fileType)
	}

	// Verify file size is reasonable (800x600 PNG should be > 1KB)
	size, _ := fileInfo["size"].(float64)
	if size < 1000 {
		t.Errorf("Expected file size > 1000 bytes, got %v", size)
	}
}

// TestFillFileWithCustomPath tests uploading a custom file path.
func TestFillFileWithCustomPath(t *testing.T) {
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

	elem, err := page.Element("#avatar")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Use the generated default file as custom path
	customPath, err := GetDefaultFilePath()
	if err != nil {
		t.Fatalf("GetDefaultFilePath() failed: %v", err)
	}

	// Upload file
	if err := FillFile(elem, []string{customPath}); err != nil {
		t.Fatalf("FillFile() failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify file was uploaded
	result, err := elem.EvalWithResult(`() => this.files ? this.files.length : 0`)
	if err != nil {
		t.Fatalf("EvalWithResult() failed: %v", err)
	}

	count, _ := result.(float64)
	if count != 1 {
		t.Errorf("Expected 1 file, got %v", count)
	}
}

// TestHandlerFillInputFile tests the full form handler flow for file inputs.
func TestHandlerFillInputFile(t *testing.T) {
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

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Create a DetectedInput for file type
	fileInput := &DetectedInput{
		FormInput: action.NewFormInput(
			action.InputTypeFile,
			action.NewIdentification(action.HowID, "avatar"),
		),
		ID:    "avatar",
		XPath: "/HTML[1]/BODY[1]/FORM[1]/INPUT[14]",
	}

	// Fill the input using handler
	if err := handler.FillInput(page, fileInput); err != nil {
		t.Fatalf("FillInput() failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify file was uploaded
	elem, err := page.Element("#avatar")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	result, err := elem.EvalWithResult(`() => {
		if (this.files && this.files.length > 0) {
			return { count: this.files.length, name: this.files[0].name };
		}
		return { count: 0 };
	}`)
	if err != nil {
		t.Fatalf("EvalWithResult() failed: %v", err)
	}

	fileInfo, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}

	count, _ := fileInfo["count"].(float64)
	if count != 1 {
		t.Errorf("Expected 1 file uploaded via handler, got %v", count)
	}

	name, _ := fileInfo["name"].(string)
	if name != DefaultPNGName {
		t.Errorf("Expected file name %q, got %q", DefaultPNGName, name)
	}
}

// TestHandlerFillInputFileWithConfiguredPath tests file upload with configured path.
func TestHandlerFillInputFileWithConfiguredPath(t *testing.T) {
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

	// Get default file path to use as configured value
	configuredPath, err := GetDefaultFilePath()
	if err != nil {
		t.Fatalf("GetDefaultFilePath() failed: %v", err)
	}

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Create a DetectedInput for file type with configured value
	identification := action.NewIdentification(action.HowID, "avatar")
	formInput := action.NewFormInput(action.InputTypeFile, identification)
	formInput.InputValues = []action.InputValue{{Value: configuredPath, Checked: true}}

	fileInput := &DetectedInput{
		FormInput: formInput,
		ID:        "avatar",
		XPath:     "/HTML[1]/BODY[1]/FORM[1]/INPUT[14]",
	}

	// Fill the input using handler
	if err := handler.FillInput(page, fileInput); err != nil {
		t.Fatalf("FillInput() failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify file was uploaded
	elem, err := page.Element("#avatar")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	result, err := elem.EvalWithResult(`() => this.files ? this.files.length : 0`)
	if err != nil {
		t.Fatalf("EvalWithResult() failed: %v", err)
	}

	count, _ := result.(float64)
	if count != 1 {
		t.Errorf("Expected 1 file uploaded with configured path, got %v", count)
	}
}

// TestDetectInputsFileType tests that file inputs are correctly detected.
func TestDetectInputsFileType(t *testing.T) {
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

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New() failed: %v", err)
	}

	handler := NewHandler(cfg)

	inputs, err := handler.DetectInputs(page)
	if err != nil {
		t.Fatalf("DetectInputs() failed: %v", err)
	}

	// Find file inputs
	var fileInputs []*DetectedInput
	for _, input := range inputs {
		if input.Type == action.InputTypeFile {
			fileInputs = append(fileInputs, input)
		}
	}

	// We added 4 file inputs: #avatar, #documents, #hidden_upload, #labeled_upload
	expectedFileInputCount := 4
	if len(fileInputs) != expectedFileInputCount {
		t.Errorf("Expected %d file inputs, got %d", expectedFileInputCount, len(fileInputs))
	}

	// Verify avatar input
	var avatarFound bool
	for _, input := range fileInputs {
		if input.ID == "avatar" {
			avatarFound = true
			if input.Type != action.InputTypeFile {
				t.Errorf("avatar input type = %q, want %q", input.Type, action.InputTypeFile)
			}
		}
	}
	if !avatarFound {
		t.Error("Expected to find avatar file input")
	}
}

// TestFillInputsWithFileType tests FillInputs with file type in the mix.
func TestFillInputsWithFileType(t *testing.T) {
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

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Create mixed inputs including file type
	inputs := []*DetectedInput{
		{
			FormInput: action.NewFormInput(
				action.InputTypeText,
				action.NewIdentification(action.HowID, "name"),
			),
			ID: "name",
		},
		{
			FormInput: action.NewFormInput(
				action.InputTypeFile,
				action.NewIdentification(action.HowID, "avatar"),
			),
			ID: "avatar",
		},
	}

	// Fill all inputs
	result := handler.FillInputs(page, inputs)

	if result.Failed > 0 {
		t.Errorf("Expected 0 failed inputs, got %d. Errors: %v", result.Failed, result.Errors())
	}

	expectedSucceeded := 2
	if result.Succeeded != expectedSucceeded {
		t.Errorf("Expected %d succeeded inputs, got %d", expectedSucceeded, result.Succeeded)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify file was uploaded
	elem, err := page.Element("#avatar")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	fileResult, err := elem.EvalWithResult(`() => this.files ? this.files.length : 0`)
	if err != nil {
		t.Fatalf("EvalWithResult() failed: %v", err)
	}

	count, _ := fileResult.(float64)
	if count != 1 {
		t.Errorf("Expected 1 file uploaded, got %v", count)
	}
}

// TestGetTypeFromStrFileIntegration verifies file type detection end-to-end.
func TestGetTypeFromStrFileIntegration(t *testing.T) {
	tests := []struct {
		input string
		want  action.InputType
	}{
		{"file", action.InputTypeFile},
		{"FILE", action.InputTypeFile},
		{"File", action.InputTypeFile},
		{"FiLe", action.InputTypeFile},
	}

	for _, tt := range tests {
		got := action.GetTypeFromStr(tt.input)
		if got != tt.want {
			t.Errorf("GetTypeFromStr(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestSmartFileSelectionWithAccept tests that file inputs with accept attribute
// get appropriate file types selected automatically.
func TestSmartFileSelectionWithAccept(t *testing.T) {
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

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Test 1: Image input with accept="image/*" should get PNG
	imageInput := &DetectedInput{
		FormInput: action.NewFormInput(
			action.InputTypeFile,
			action.NewIdentification(action.HowID, "avatar"),
		),
		ID:     "avatar",
		Accept: "image/*",
	}

	if err := handler.FillInput(page, imageInput); err != nil {
		t.Fatalf("FillInput(avatar) failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	elem, err := page.Element("#avatar")
	if err != nil {
		t.Fatalf("Element(#avatar) failed: %v", err)
	}

	result, err := elem.EvalWithResult(`() => {
		if (this.files && this.files.length > 0) {
			return { name: this.files[0].name, type: this.files[0].type };
		}
		return null;
	}`)
	if err != nil {
		t.Fatalf("EvalWithResult() failed: %v", err)
	}

	fileInfo, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("Expected map result for avatar, got %T", result)
	}

	fileType, _ := fileInfo["type"].(string)
	if fileType != "image/png" {
		t.Errorf("For accept=image/*, expected type image/png, got %q", fileType)
	}

	// Test 2: Document input with accept=".pdf,.doc,.docx" should get PDF
	if err := page.Navigate(server.URL + "/form_test.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	docInput := &DetectedInput{
		FormInput: action.NewFormInput(
			action.InputTypeFile,
			action.NewIdentification(action.HowID, "documents"),
		),
		ID:     "documents",
		Accept: ".pdf,.doc,.docx",
	}

	if err := handler.FillInput(page, docInput); err != nil {
		t.Fatalf("FillInput(documents) failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	docElem, err := page.Element("#documents")
	if err != nil {
		t.Fatalf("Element(#documents) failed: %v", err)
	}

	docResult, err := docElem.EvalWithResult(`() => {
		if (this.files && this.files.length > 0) {
			return this.files[0].name;
		}
		return null;
	}`)
	if err != nil {
		t.Fatalf("EvalWithResult() failed: %v", err)
	}

	fileName, ok := docResult.(string)
	if !ok {
		t.Fatalf("Expected string result for documents, got %T", docResult)
	}

	// Should end with .pdf since PDF is first in accept list
	if !strings.HasSuffix(fileName, ".pdf") {
		t.Errorf("For accept=.pdf,.doc,.docx, expected file ending with .pdf, got %q", fileName)
	}
}

// TestDetectInputsAcceptAttribute verifies accept attribute is captured during detection.
func TestDetectInputsAcceptAttribute(t *testing.T) {
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

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New() failed: %v", err)
	}

	handler := NewHandler(cfg)

	inputs, err := handler.DetectInputs(page)
	if err != nil {
		t.Fatalf("DetectInputs() failed: %v", err)
	}

	// Find avatar input and check accept attribute
	var avatarInput *DetectedInput
	var documentsInput *DetectedInput

	for _, input := range inputs {
		if input.ID == "avatar" {
			avatarInput = input
		}
		if input.ID == "documents" {
			documentsInput = input
		}
	}

	if avatarInput == nil {
		t.Fatal("Expected to find avatar input")
	}

	if avatarInput.Accept != "image/*" {
		t.Errorf("avatar.Accept = %q, want %q", avatarInput.Accept, "image/*")
	}

	if documentsInput == nil {
		t.Fatal("Expected to find documents input")
	}

	if documentsInput.Accept != ".pdf,.doc,.docx" {
		t.Errorf("documents.Accept = %q, want %q", documentsInput.Accept, ".pdf,.doc,.docx")
	}
}

// TestDetectHiddenFileInputs verifies hidden file inputs are detected with trigger elements.
func TestDetectHiddenFileInputs(t *testing.T) {
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

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New() failed: %v", err)
	}

	handler := NewHandler(cfg)

	inputs, err := handler.DetectInputs(page)
	if err != nil {
		t.Fatalf("DetectInputs() failed: %v", err)
	}

	// Find hidden file inputs
	var hiddenUpload *DetectedInput
	var labeledUpload *DetectedInput

	for _, input := range inputs {
		if input.ID == "hidden_upload" {
			hiddenUpload = input
		}
		if input.ID == "labeled_upload" {
			labeledUpload = input
		}
	}

	// Test hidden_upload (button trigger)
	if hiddenUpload == nil {
		t.Fatal("Expected to find hidden_upload input")
	}

	if !hiddenUpload.Hidden {
		t.Errorf("hidden_upload.Hidden = false, want true")
	}

	if hiddenUpload.TriggerXPath == "" {
		t.Errorf("hidden_upload.TriggerXPath is empty, expected trigger element XPath")
	} else {
		t.Logf("hidden_upload.TriggerXPath = %q", hiddenUpload.TriggerXPath)
	}

	if hiddenUpload.Accept != "image/*" {
		t.Errorf("hidden_upload.Accept = %q, want %q", hiddenUpload.Accept, "image/*")
	}

	// Test labeled_upload (label trigger)
	if labeledUpload == nil {
		t.Fatal("Expected to find labeled_upload input")
	}

	if !labeledUpload.Hidden {
		t.Errorf("labeled_upload.Hidden = false, want true")
	}

	if labeledUpload.TriggerXPath == "" {
		t.Errorf("labeled_upload.TriggerXPath is empty, expected trigger element XPath")
	} else {
		t.Logf("labeled_upload.TriggerXPath = %q", labeledUpload.TriggerXPath)
	}

	if labeledUpload.Accept != ".pdf" {
		t.Errorf("labeled_upload.Accept = %q, want %q", labeledUpload.Accept, ".pdf")
	}
}

// TestFillHiddenFileInputViaButtonTrigger tests filling hidden file input via button click.
func TestFillHiddenFileInputViaButtonTrigger(t *testing.T) {
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

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Create DetectedInput for hidden_upload with trigger
	hiddenInput := &DetectedInput{
		FormInput: action.NewFormInput(
			action.InputTypeFile,
			action.NewIdentification(action.HowID, "hidden_upload"),
		),
		ID:           "hidden_upload",
		Accept:       "image/*",
		Hidden:       true,
		TriggerXPath: "//BUTTON[@id='upload_btn']",
	}

	// Fill the hidden file input via trigger button
	if err := handler.FillInput(page, hiddenInput); err != nil {
		t.Fatalf("FillInput(hidden_upload) failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Verify file was uploaded to the hidden input
	elem, err := page.Element("#hidden_upload")
	if err != nil {
		t.Fatalf("Element(#hidden_upload) failed: %v", err)
	}

	result, err := elem.EvalWithResult(`() => {
		if (this.files && this.files.length > 0) {
			return { name: this.files[0].name, type: this.files[0].type };
		}
		return null;
	}`)
	if err != nil {
		t.Fatalf("EvalWithResult() failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected file to be uploaded, got nil")
	}

	fileInfo, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}

	fileName, _ := fileInfo["name"].(string)
	fileType, _ := fileInfo["type"].(string)

	t.Logf("Uploaded file: name=%q, type=%q", fileName, fileType)

	// Should be PNG since accept=image/*
	if fileType != "image/png" {
		t.Errorf("Expected image/png type, got %q", fileType)
	}
}

// TestFillHiddenFileInputViaLabelTrigger tests filling hidden file input via label click.
func TestFillHiddenFileInputViaLabelTrigger(t *testing.T) {
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

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Create DetectedInput for labeled_upload with trigger
	labeledInput := &DetectedInput{
		FormInput: action.NewFormInput(
			action.InputTypeFile,
			action.NewIdentification(action.HowID, "labeled_upload"),
		),
		ID:           "labeled_upload",
		Accept:       ".pdf",
		Hidden:       true,
		TriggerXPath: "//LABEL[@id='upload_label']",
	}

	// Fill the hidden file input via trigger label
	if err := handler.FillInput(page, labeledInput); err != nil {
		t.Fatalf("FillInput(labeled_upload) failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Verify file was uploaded to the hidden input
	elem, err := page.Element("#labeled_upload")
	if err != nil {
		t.Fatalf("Element(#labeled_upload) failed: %v", err)
	}

	result, err := elem.EvalWithResult(`() => {
		if (this.files && this.files.length > 0) {
			return this.files[0].name;
		}
		return null;
	}`)
	if err != nil {
		t.Fatalf("EvalWithResult() failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected file to be uploaded, got nil")
	}

	fileName, ok := result.(string)
	if !ok {
		t.Fatalf("Expected string result, got %T", result)
	}

	t.Logf("Uploaded file: name=%q", fileName)

	// Should be PDF since accept=.pdf
	if !strings.HasSuffix(fileName, ".pdf") {
		t.Errorf("Expected file ending with .pdf, got %q", fileName)
	}
}

// TestFillHiddenFileInputAutoDetectedTrigger tests full flow: detect + fill hidden input.
func TestFillHiddenFileInputAutoDetectedTrigger(t *testing.T) {
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

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New() failed: %v", err)
	}

	handler := NewHandler(cfg)

	// Detect all inputs
	inputs, err := handler.DetectInputs(page)
	if err != nil {
		t.Fatalf("DetectInputs() failed: %v", err)
	}

	// Find hidden_upload (auto-detected)
	var hiddenUpload *DetectedInput
	for _, input := range inputs {
		if input.ID == "hidden_upload" {
			hiddenUpload = input
			break
		}
	}

	if hiddenUpload == nil {
		t.Fatal("Expected to find hidden_upload input")
	}

	// Verify detection captured Hidden and TriggerXPath
	if !hiddenUpload.Hidden {
		t.Fatal("hidden_upload.Hidden should be true")
	}
	if hiddenUpload.TriggerXPath == "" {
		t.Fatal("hidden_upload.TriggerXPath should be set")
	}

	t.Logf("Auto-detected: Hidden=%v, TriggerXPath=%q, Accept=%q",
		hiddenUpload.Hidden, hiddenUpload.TriggerXPath, hiddenUpload.Accept)

	// Fill using auto-detected trigger
	if err := handler.FillInput(page, hiddenUpload); err != nil {
		t.Fatalf("FillInput(hidden_upload) failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Verify file was uploaded
	elem, err := page.Element("#hidden_upload")
	if err != nil {
		t.Fatalf("Element(#hidden_upload) failed: %v", err)
	}

	result, err := elem.EvalWithResult(`() => {
		if (this.files && this.files.length > 0) {
			return { name: this.files[0].name, type: this.files[0].type };
		}
		return null;
	}`)
	if err != nil {
		t.Fatalf("EvalWithResult() failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected file to be uploaded, got nil")
	}

	fileInfo, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}

	fileType, _ := fileInfo["type"].(string)
	t.Logf("Uploaded file type: %q", fileType)

	if fileType != "image/png" {
		t.Errorf("Expected image/png type (for accept=image/*), got %q", fileType)
	}
}
