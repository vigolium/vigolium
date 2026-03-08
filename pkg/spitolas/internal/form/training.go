package form

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// TrainingMode defines how form inputs are filled during crawling.
// This matches Java Crawljax's training capabilities.
type TrainingMode int

const (
	// FillRandom fills forms with random generated values.
	FillRandom TrainingMode = iota

	// FillTraining fills forms and saves inputs for replay.
	FillTraining

	// FillXPathTraining fills forms using XPath-matched saved inputs.
	FillXPathTraining

	// FillReplay replays previously saved inputs exactly.
	FillReplay
)

// TrainedInput represents a saved form input value.
type TrainedInput struct {
	// XPath is the XPath to the input element
	XPath string `json:"xpath"`

	// Selector is the CSS selector for the input
	Selector string `json:"selector"`

	// Type is the input type (text, password, email, etc.)
	Type string `json:"type"`

	// Name is the input name attribute
	Name string `json:"name"`

	// ID is the input id attribute
	ID string `json:"id"`

	// FormID is the ID of the containing form (if any)
	FormID string `json:"form_id,omitempty"`

	// FormAction is the action URL of the containing form
	FormAction string `json:"form_action,omitempty"`

	// Value is the value to fill
	Value string `json:"value"`

	// Values is for multi-value inputs (select, checkboxes)
	Values []string `json:"values,omitempty"`

	// Checked is for checkbox/radio inputs
	Checked bool `json:"checked,omitempty"`

	// Priority determines matching order (higher = better match)
	Priority int `json:"priority,omitempty"`
}

// TrainedForm represents a complete form with all its inputs.
type TrainedForm struct {
	// ID is the form id attribute
	ID string `json:"id,omitempty"`

	// Name is the form name attribute
	Name string `json:"name,omitempty"`

	// Action is the form action URL
	Action string `json:"action"`

	// Method is the form method (GET, POST)
	Method string `json:"method"`

	// XPath is the XPath to the form element
	XPath string `json:"xpath"`

	// URL is the page URL where this form was found
	URL string `json:"url"`

	// Inputs is the list of trained inputs for this form
	Inputs []*TrainedInput `json:"inputs"`
}

// TrainingData holds all trained forms and inputs.
type TrainingData struct {
	// Version for compatibility checking
	Version string `json:"version"`

	// CreatedAt is when training data was created
	CreatedAt string `json:"created_at"`

	// UpdatedAt is when training data was last modified
	UpdatedAt string `json:"updated_at"`

	// Forms is the list of trained forms
	Forms []*TrainedForm `json:"forms"`

	// GlobalInputs are inputs that match by name/type across all forms
	GlobalInputs []*TrainedInput `json:"global_inputs,omitempty"`
}

// FormTrainer manages form training data.
type FormTrainer struct {
	mu sync.RWMutex

	// Mode is the current training mode
	Mode TrainingMode

	// OutputDir is the directory to save training data
	OutputDir string

	// Data holds the current training data
	Data *TrainingData

	// inputsByXPath indexes inputs by XPath for fast lookup
	inputsByXPath map[string]*TrainedInput

	// inputsByName indexes inputs by name for fallback matching
	inputsByName map[string][]*TrainedInput

	// inputsByType indexes inputs by type for type-based matching
	inputsByType map[string][]*TrainedInput
}

// NewFormTrainer creates a new form trainer.
func NewFormTrainer(mode TrainingMode, outputDir string) *FormTrainer {
	return &FormTrainer{
		Mode:          mode,
		OutputDir:     outputDir,
		Data:          &TrainingData{Version: "1.0"},
		inputsByXPath: make(map[string]*TrainedInput),
		inputsByName:  make(map[string][]*TrainedInput),
		inputsByType:  make(map[string][]*TrainedInput),
	}
}

// SetMode changes the training mode.
func (t *FormTrainer) SetMode(mode TrainingMode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Mode = mode
}

// GetMode returns the current training mode.
func (t *FormTrainer) GetMode() TrainingMode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Mode
}

// RecordInput records an input value during training.
func (t *FormTrainer) RecordInput(input *TrainedInput) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Add to XPath index
	if input.XPath != "" {
		t.inputsByXPath[input.XPath] = input
	}

	// Add to name index
	if input.Name != "" {
		t.inputsByName[input.Name] = append(t.inputsByName[input.Name], input)
	}

	// Add to type index
	if input.Type != "" {
		t.inputsByType[input.Type] = append(t.inputsByType[input.Type], input)
	}

	// Add to global inputs
	t.Data.GlobalInputs = append(t.Data.GlobalInputs, input)
}

// RecordForm records a complete form during training.
func (t *FormTrainer) RecordForm(form *TrainedForm) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.Data.Forms = append(t.Data.Forms, form)

	// Index form inputs
	for _, input := range form.Inputs {
		if input.XPath != "" {
			t.inputsByXPath[input.XPath] = input
		}
		if input.Name != "" {
			t.inputsByName[input.Name] = append(t.inputsByName[input.Name], input)
		}
		if input.Type != "" {
			t.inputsByType[input.Type] = append(t.inputsByType[input.Type], input)
		}
	}
}

// GetInputByXPath finds a trained input by exact XPath match.
func (t *FormTrainer) GetInputByXPath(xpath string) *TrainedInput {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.inputsByXPath[xpath]
}

// GetInputByName finds trained inputs by name.
func (t *FormTrainer) GetInputByName(name string) []*TrainedInput {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.inputsByName[name]
}

// GetInputByType finds trained inputs by type.
func (t *FormTrainer) GetInputByType(inputType string) []*TrainedInput {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.inputsByType[inputType]
}

// MatchInput finds the best matching trained input for the given input.
// Uses priority-based matching: XPath > ID > Name > Type
func (t *FormTrainer) MatchInput(xpath, id, name, inputType string) *TrainedInput {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Priority 1: Exact XPath match
	if xpath != "" {
		if input := t.inputsByXPath[xpath]; input != nil {
			return input
		}
	}

	// Priority 2: Match by ID
	if id != "" {
		for _, input := range t.Data.GlobalInputs {
			if input.ID == id {
				return input
			}
		}
	}

	// Priority 3: Match by name (prefer same type)
	if name != "" {
		inputs := t.inputsByName[name]
		for _, input := range inputs {
			if input.Type == inputType {
				return input
			}
		}
		if len(inputs) > 0 {
			return inputs[0]
		}
	}

	// Priority 4: Match by type (last resort)
	if inputType != "" {
		inputs := t.inputsByType[inputType]
		if len(inputs) > 0 {
			return inputs[0]
		}
	}

	return nil
}

// GetFormByAction finds a trained form by action URL.
func (t *FormTrainer) GetFormByAction(action string) *TrainedForm {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, form := range t.Data.Forms {
		if form.Action == action {
			return form
		}
	}
	return nil
}

// GetFormByXPath finds a trained form by XPath.
func (t *FormTrainer) GetFormByXPath(xpath string) *TrainedForm {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, form := range t.Data.Forms {
		if form.XPath == xpath {
			return form
		}
	}
	return nil
}

// Save saves training data to file.
func (t *FormTrainer) Save() error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.OutputDir == "" {
		return fmt.Errorf("output directory not set")
	}

	// Ensure directory exists
	if err := os.MkdirAll(t.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Marshal data
	data, err := json.MarshalIndent(t.Data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal training data: %w", err)
	}

	// Write file
	filePath := filepath.Join(t.OutputDir, "form_training.json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write training data: %w", err)
	}

	return nil
}

// Load loads training data from file.
func (t *FormTrainer) Load() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.OutputDir == "" {
		return fmt.Errorf("output directory not set")
	}

	filePath := filepath.Join(t.OutputDir, "form_training.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No training data yet
		}
		return fmt.Errorf("failed to read training data: %w", err)
	}

	var trainingData TrainingData
	if err := json.Unmarshal(data, &trainingData); err != nil {
		return fmt.Errorf("failed to parse training data: %w", err)
	}

	t.Data = &trainingData

	// Rebuild indexes
	t.inputsByXPath = make(map[string]*TrainedInput)
	t.inputsByName = make(map[string][]*TrainedInput)
	t.inputsByType = make(map[string][]*TrainedInput)

	// Index global inputs
	for _, input := range t.Data.GlobalInputs {
		if input.XPath != "" {
			t.inputsByXPath[input.XPath] = input
		}
		if input.Name != "" {
			t.inputsByName[input.Name] = append(t.inputsByName[input.Name], input)
		}
		if input.Type != "" {
			t.inputsByType[input.Type] = append(t.inputsByType[input.Type], input)
		}
	}

	// Index form inputs
	for _, form := range t.Data.Forms {
		for _, input := range form.Inputs {
			if input.XPath != "" {
				t.inputsByXPath[input.XPath] = input
			}
			if input.Name != "" {
				t.inputsByName[input.Name] = append(t.inputsByName[input.Name], input)
			}
			if input.Type != "" {
				t.inputsByType[input.Type] = append(t.inputsByType[input.Type], input)
			}
		}
	}

	return nil
}

// Clear clears all training data.
func (t *FormTrainer) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.Data = &TrainingData{Version: "1.0"}
	t.inputsByXPath = make(map[string]*TrainedInput)
	t.inputsByName = make(map[string][]*TrainedInput)
	t.inputsByType = make(map[string][]*TrainedInput)
}

// Stats returns training data statistics.
func (t *FormTrainer) Stats() TrainingStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := TrainingStats{
		TotalForms:        len(t.Data.Forms),
		TotalGlobalInputs: len(t.Data.GlobalInputs),
		UniqueXPaths:      len(t.inputsByXPath),
		UniqueNames:       len(t.inputsByName),
		UniqueTypes:       len(t.inputsByType),
	}

	for _, form := range t.Data.Forms {
		stats.TotalFormInputs += len(form.Inputs)
	}

	return stats
}

// TrainingStats holds statistics about training data.
type TrainingStats struct {
	TotalForms        int
	TotalFormInputs   int
	TotalGlobalInputs int
	UniqueXPaths      int
	UniqueNames       int
	UniqueTypes       int
}

// ExportToCSV exports training data to CSV format for analysis.
func (t *FormTrainer) ExportToCSV() (string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var sb stringBuilder
	sb.WriteString("xpath,selector,type,name,id,value,form_id,form_action\n")

	for _, input := range t.Data.GlobalInputs {
		_, _ = fmt.Fprintf(&sb, "%q,%q,%q,%q,%q,%q,%q,%q\n",
			input.XPath,
			input.Selector,
			input.Type,
			input.Name,
			input.ID,
			input.Value,
			input.FormID,
			input.FormAction,
		)
	}

	return sb.String(), nil
}

type stringBuilder struct {
	data []byte
}

func (sb *stringBuilder) Write(p []byte) (int, error) {
	sb.data = append(sb.data, p...)
	return len(p), nil
}

func (sb *stringBuilder) WriteString(s string) {
	sb.data = append(sb.data, s...)
}

func (sb *stringBuilder) String() string {
	return string(sb.data)
}

// ImportFromCSV imports training data from CSV format.
func (t *FormTrainer) ImportFromCSV(csvData string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	lines := splitLines(csvData)
	if len(lines) < 2 {
		return fmt.Errorf("CSV must have header and at least one data row")
	}

	// Skip header
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}

		fields := parseCSVLine(line)
		if len(fields) < 5 {
			continue
		}

		input := &TrainedInput{
			XPath:      fields[0],
			Selector:   safeGet(fields, 1),
			Type:       safeGet(fields, 2),
			Name:       safeGet(fields, 3),
			ID:         safeGet(fields, 4),
			Value:      safeGet(fields, 5),
			FormID:     safeGet(fields, 6),
			FormAction: safeGet(fields, 7),
		}

		t.Data.GlobalInputs = append(t.Data.GlobalInputs, input)

		// Update indexes
		if input.XPath != "" {
			t.inputsByXPath[input.XPath] = input
		}
		if input.Name != "" {
			t.inputsByName[input.Name] = append(t.inputsByName[input.Name], input)
		}
		if input.Type != "" {
			t.inputsByType[input.Type] = append(t.inputsByType[input.Type], input)
		}
	}

	return nil
}

func splitLines(s string) []string {
	var lines []string
	var current []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, string(current))
			current = nil
		} else if s[i] != '\r' {
			current = append(current, s[i])
		}
	}
	if len(current) > 0 {
		lines = append(lines, string(current))
	}
	return lines
}

func parseCSVLine(line string) []string {
	var fields []string
	var current []byte
	inQuotes := false

	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '"' {
			if inQuotes && i+1 < len(line) && line[i+1] == '"' {
				current = append(current, '"')
				i++
			} else {
				inQuotes = !inQuotes
			}
		} else if ch == ',' && !inQuotes {
			fields = append(fields, string(current))
			current = nil
		} else {
			current = append(current, ch)
		}
	}
	fields = append(fields, string(current))
	return fields
}

func safeGet(slice []string, idx int) string {
	if idx < len(slice) {
		return slice[idx]
	}
	return ""
}
