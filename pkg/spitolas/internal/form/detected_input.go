// Package form provides form handling for web crawling.
// This file contains Go extension for detection metadata.
package form

import (
	"sync"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

// DetectedInput contains detection metadata for a form input.
// This struct adds detection metadata for smart value generation.
type DetectedInput struct {
	// Core FormInput
	*action.FormInput

	// Detection metadata
	Name        string // name attribute (for smart detection)
	ID          string // id attribute (for smart detection)
	XPath       string // skeleton XPath (cached for lookup)
	Required    bool   // Whether input is required
	Disabled    bool   // Whether input is disabled
	ReadOnly    bool   // Whether input is read-only
	Multiple    bool   // For select: allows multiple selections; for file: allows multiple files
	Pattern     string // pattern attribute (regex)
	MinLength   int    // minlength attribute
	MaxLength   int    // maxlength attribute
	Min         string // min attribute (for number/date/time)
	Max         string // max attribute (for number/date/time)
	Step        string // step attribute (for number/range)
	Placeholder string // placeholder attribute
	Label       string // text from associated <label> element
	Accept      string // accept attribute (for file inputs: MIME types or extensions)

	// Hidden file input detection (Go extension)
	Hidden       bool   // Whether input is visually hidden (display:none, hidden attr, etc.)
	TriggerXPath string // XPath of trigger element (button/label) for hidden file inputs

	// Orphan input detection (Go extension — pilot mode)
	SubmitXPath string // XPath of nearest submit-like element for inputs outside <form> tags

	// Value rotation state (Go extension)
	mu         sync.Mutex
	valueIndex int
}

// NewDetectedInput creates a new DetectedInput wrapping a FormInput.
func NewDetectedInput(formInput *action.FormInput) *DetectedInput {
	return &DetectedInput{
		FormInput: formInput,
	}
}

// NewDetectedInputWithType creates a new DetectedInput with type and identification.
func NewDetectedInputWithType(inputType action.InputType, identification *action.Identification) *DetectedInput {
	return &DetectedInput{
		FormInput: action.NewFormInput(inputType, identification),
	}
}

// CanInteract returns true if the input can be interacted with.
func (d *DetectedInput) CanInteract() bool {
	return !d.Disabled && !d.ReadOnly
}

// ToFormInput returns the underlying FormInput.
func (d *DetectedInput) ToFormInput() *action.FormInput {
	return d.FormInput
}

// NextValue returns the next value in the rotation.
// Thread-safe.
func (d *DetectedInput) NextValue() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.FormInput == nil || len(d.InputValues) == 0 {
		return ""
	}

	value := d.InputValues[d.valueIndex].Value
	d.valueIndex = (d.valueIndex + 1) % len(d.InputValues)
	return value
}

// CurrentValue returns the current value without advancing.
func (d *DetectedInput) CurrentValue() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.FormInput == nil || len(d.InputValues) == 0 {
		return ""
	}
	return d.InputValues[d.valueIndex].Value
}

// ResetValueIndex resets the value rotation to the beginning.
func (d *DetectedInput) ResetValueIndex() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.valueIndex = 0
}

// HasValues returns true if the input has configured values.
func (d *DetectedInput) HasValues() bool {
	return d.FormInput != nil && len(d.InputValues) > 0
}

// SetValues sets values for the underlying FormInput.
func (d *DetectedInput) SetValues(values []string) {
	if d.FormInput == nil {
		return
	}
	d.InputValues = make([]action.InputValue, 0, len(values))
	for _, v := range values {
		d.InputValues = append(d.InputValues, action.InputValue{Value: v, Checked: true})
	}
}

// GetValues returns values as string slice.
func (d *DetectedInput) GetValues() []string {
	if d.FormInput == nil {
		return nil
	}
	result := make([]string, 0, len(d.InputValues))
	for _, iv := range d.InputValues {
		result = append(result, iv.Value)
	}
	return result
}

// ToFormInputs converts a slice of DetectedInput to FormInput.
func ToFormInputs(inputs []*DetectedInput) []*action.FormInput {
	if inputs == nil {
		return nil
	}
	result := make([]*action.FormInput, 0, len(inputs))
	for _, di := range inputs {
		if di != nil && di.FormInput != nil {
			result = append(result, di.FormInput)
		}
	}
	return result
}

// FromFormInput creates a DetectedInput from an action.FormInput.
func FromFormInput(formInput *action.FormInput) *DetectedInput {
	if formInput == nil {
		return nil
	}
	detected := NewDetectedInput(formInput)
	// Extract Name and ID from Identification if available
	if formInput.Identification != nil {
		switch formInput.Identification.How {
		case action.HowID:
			detected.ID = formInput.Identification.Value
		case action.HowName:
			detected.Name = formInput.Identification.Value
		case action.HowXPath:
			detected.XPath = formInput.Identification.Value
		}
	}
	return detected
}

// FromFormInputs converts a slice of action.FormInput to DetectedInput.
func FromFormInputs(inputs []*action.FormInput) []*DetectedInput {
	if inputs == nil {
		return nil
	}
	result := make([]*DetectedInput, 0, len(inputs))
	for _, fi := range inputs {
		if di := FromFormInput(fi); di != nil {
			result = append(result, di)
		}
	}
	return result
}

// Form represents an HTML form.
// GO EXTENSION: Contains detected inputs with metadata.
type Form struct {
	XPath  string           // XPath for the form
	Action string           // form action URL
	Method string           // form method (GET/POST)
	Inputs []*DetectedInput // Detected form inputs with metadata
}

// NewForm creates a new form.
func NewForm(xpath string) *Form {
	return &Form{
		XPath:  xpath,
		Method: "GET",
		Inputs: []*DetectedInput{},
	}
}

// AddInput adds a detected input to the form.
func (f *Form) AddInput(input *DetectedInput) *Form {
	f.Inputs = append(f.Inputs, input)
	return f
}

// GetFormInputs returns the underlying FormInputs.
func (f *Form) GetFormInputs() []*action.FormInput {
	return ToFormInputs(f.Inputs)
}

// GetInput returns an input by name.
func (f *Form) GetInput(name string) *DetectedInput {
	for _, input := range f.Inputs {
		if input.FormInput != nil && input.Identification != nil {
			if input.Identification.How == action.HowName &&
				input.Identification.Value == name {
				return input
			}
		}
	}
	return nil
}

// GetInputByID returns an input by ID.
func (f *Form) GetInputByID(id string) *DetectedInput {
	for _, input := range f.Inputs {
		if input.FormInput != nil && input.Identification != nil {
			if input.Identification.How == action.HowID &&
				input.Identification.Value == id {
				return input
			}
		}
	}
	return nil
}

// TextInputs returns all text-like inputs.
func (f *Form) TextInputs() []*DetectedInput {
	result := make([]*DetectedInput, 0)
	for _, input := range f.Inputs {
		if input.FormInput != nil && input.IsTextLike() {
			result = append(result, input)
		}
	}
	return result
}

// SelectInputs returns all select inputs.
func (f *Form) SelectInputs() []*DetectedInput {
	result := make([]*DetectedInput, 0)
	for _, input := range f.Inputs {
		if input.FormInput != nil && input.Type == action.InputTypeSelect {
			result = append(result, input)
		}
	}
	return result
}

// CheckboxInputs returns all checkbox inputs.
func (f *Form) CheckboxInputs() []*DetectedInput {
	result := make([]*DetectedInput, 0)
	for _, input := range f.Inputs {
		if input.FormInput != nil && input.Type == action.InputTypeCheckbox {
			result = append(result, input)
		}
	}
	return result
}

// RadioInputs returns all radio inputs.
func (f *Form) RadioInputs() []*DetectedInput {
	result := make([]*DetectedInput, 0)
	for _, input := range f.Inputs {
		if input.FormInput != nil && input.Type == action.InputTypeRadio {
			result = append(result, input)
		}
	}
	return result
}
