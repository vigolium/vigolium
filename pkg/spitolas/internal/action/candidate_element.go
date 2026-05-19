// Package action provides web crawling action types and handling.
package action

import (
	"fmt"
	"strings"
	"sync"
)

// EventType defines event types for crawl actions.
type EventType string

const (
	// EventTypeClick click event
	EventTypeClick EventType = "click"
	// EventTypeHover hover/mouseover event
	EventTypeHover EventType = "hover"
	// EventTypeEnter enter key event
	EventTypeEnter EventType = "enter"
	// EventTypeReload page reload event (for backtracking)
	EventTypeReload EventType = "reload"
)

// InputType defines form input types.
// GO EXTENSION: Added HTML5 input types (Tel, URL, Search, Date, Time, Color, Range).
type InputType string

const (
	// Standard input types
	InputTypeText     InputType = "TEXT"
	InputTypeRadio    InputType = "RADIO"
	InputTypeCheckbox InputType = "CHECKBOX"
	InputTypePassword InputType = "PASSWORD"
	InputTypeHidden   InputType = "HIDDEN"
	InputTypeSelect   InputType = "SELECT"
	InputTypeTextarea InputType = "TEXTAREA"
	InputTypeEmail    InputType = "EMAIL"
	InputTypeInput    InputType = "INPUT"
	InputTypeNumber   InputType = "NUMBER"

	InputTypeTel    InputType = "TEL"
	InputTypeURL    InputType = "URL"
	InputTypeSearch InputType = "SEARCH"
	InputTypeDate   InputType = "DATE"
	InputTypeTime   InputType = "TIME"
	InputTypeColor  InputType = "COLOR"
	InputTypeRange  InputType = "RANGE"
	InputTypeFile   InputType = "FILE"
)

// FormInput represents form input data.
type FormInput struct {
	Type           InputType       `json:"type"`
	Identification *Identification `json:"identification"`
	InputValues    []InputValue    `json:"inputValues"`
}

// InputValue represents a single input value.
type InputValue struct {
	Value   string `json:"value"`
	Checked bool   `json:"checked"`
}

// Equals checks equality of InputValue.
func (iv InputValue) Equals(other InputValue) bool {
	return iv.Value == other.Value && iv.Checked == other.Checked
}

// NewFormInput creates a new FormInput.
func NewFormInput(inputType InputType, identification *Identification) *FormInput {
	return &FormInput{
		Type:           inputType,
		Identification: identification,
		InputValues:    make([]InputValue, 0),
	}
}

// NewFormInputWithValue creates a new FormInput with a value.
func NewFormInputWithValue(inputType InputType, identification *Identification, value string) *FormInput {
	return &FormInput{
		Type:           inputType,
		Identification: identification,
		InputValues:    []InputValue{{Value: value, Checked: value == "1"}},
	}
}

// GetTypeFromStr converts string to InputType.
func GetTypeFromStr(typeStr string) InputType {
	switch strings.ToUpper(typeStr) {
	case "TEXT", "":
		return InputTypeText
	case "TEXTAREA":
		return InputTypeTextarea
	case "PASSWORD":
		return InputTypePassword
	case "EMAIL":
		return InputTypeEmail
	case "NUMBER":
		return InputTypeNumber
	case "HIDDEN":
		return InputTypeHidden
	case "CHECKBOX":
		return InputTypeCheckbox
	case "RADIO":
		return InputTypeRadio
	case "SELECT", "SELECT-ONE", "SELECT-MULTIPLE":
		return InputTypeSelect
	// GO EXTENSION: HTML5 input types
	case "TEL":
		return InputTypeTel
	case "URL":
		return InputTypeURL
	case "SEARCH":
		return InputTypeSearch
	case "DATE":
		return InputTypeDate
	case "TIME":
		return InputTypeTime
	case "COLOR":
		return InputTypeColor
	case "RANGE":
		return InputTypeRange
	case "FILE":
		return InputTypeFile
	default:
		return InputTypeText
	}
}

// AddInputValue adds a value to the input values list.
// Go matches this by simply appending without checking for duplicates.
func (f *FormInput) AddInputValue(iv InputValue) {
	f.InputValues = append(f.InputValues, iv)
}

// SetInputValues sets values from string slice.
func (f *FormInput) SetInputValues(values ...string) {
	for _, value := range values {
		f.AddInputValue(InputValue{Value: value, Checked: value == "1"})
	}
}

// SetInputValuesChecked sets values for checkboxes/radio buttons.
func (f *FormInput) SetInputValuesChecked(checks ...bool) {
	for _, checked := range checks {
		f.AddInputValue(InputValue{Checked: checked})
	}
}

// GetType returns the input type.
func (f *FormInput) GetType() InputType {
	return f.Type
}

// GetIdentification returns the identification.
func (f *FormInput) GetIdentification() *Identification {
	return f.Identification
}

// GetInputValues returns the input values.
func (f *FormInput) GetInputValues() []InputValue {
	return f.InputValues
}

// HasValues returns true if the input has configured values.
func (f *FormInput) HasValues() bool {
	return len(f.InputValues) > 0
}

// GetFirstValue returns the first input value string, or empty if none.
func (f *FormInput) GetFirstValue() string {
	if len(f.InputValues) > 0 {
		return f.InputValues[0].Value
	}
	return ""
}

// IsTextLike returns true if the input type accepts text input.
func (f *FormInput) IsTextLike() bool {
	switch f.Type {
	case InputTypeText, InputTypeTextarea, InputTypePassword, InputTypeEmail, InputTypeNumber, InputTypeInput:
		return true
	default:
		return false
	}
}

// Equals checks equality based on identification + type.
func (f *FormInput) Equals(other *FormInput) bool {
	if other == nil {
		return false
	}
	if f == other {
		return true
	}
	// Check identification equality
	if f.Identification == nil && other.Identification == nil {
		return f.Type == other.Type
	}
	if f.Identification == nil || other.Identification == nil {
		return false
	}
	return f.Identification.Equals(other.Identification) && f.Type == other.Type
}

// ContainsInput checks if slice contains FormInput with same Identification.
func ContainsInput(inputs []*FormInput, id *Identification) bool {
	for _, input := range inputs {
		if input.Identification != nil && input.Identification.Equals(id) {
			return true
		}
	}
	return false
}

// GetInput returns FormInput with matching Identification from slice.
func GetInput(inputs []*FormInput, id *Identification) *FormInput {
	for _, input := range inputs {
		if input.Identification != nil && input.Identification.Equals(id) {
			return input
		}
	}
	return nil
}

// CandidateElement represents an element that can be crawled (clicked, hovered, etc).
// This is BEFORE the event is fired. Once fired, it becomes an Eventable.
type CandidateElement struct {
	mu sync.RWMutex

	Identification *Identification `json:"identification"`
	RelatedFrame   string          `json:"relatedFrame"`
	FormInputs     []*FormInput    `json:"formInputs"`

	// DOM element info (serialized, since Go doesn't have DOM API)
	TagName    string `json:"tagName"`
	Attributes string `json:"attributes"` // All attributes as string (matches DomUtils.getAllElementAttributes)
	Text       string `json:"text"`
	Href       string `json:"href"`

	// Using interface{} to avoid import cycle - will be *fragment.Fragment
	ClosestFragment    interface{} `json:"-"`
	ClosestDomFragment interface{} `json:"-"`

	duplicateAccess  int  // Times this element led to a known state
	equivalentAccess int  // Times this element was equivalent to another
	directAccess     bool // Was this element directly accessed

	EventType EventType `json:"eventType"`

	// Using interface{} to avoid import cycle - will be *condition.EventableCondition
	EventableCondition interface{} `json:"-"`
}

// NewCandidateElement creates a new CandidateElement.
func NewCandidateElement(identification *Identification, relatedFrame string, formInputs []*FormInput) *CandidateElement {
	if formInputs == nil {
		formInputs = make([]*FormInput, 0)
	}
	return &CandidateElement{
		Identification: identification,
		RelatedFrame:   relatedFrame,
		FormInputs:     formInputs,
		EventType:      EventTypeClick,
	}
}

// NewCandidateElementWithXPath creates a CandidateElement with XPath identification.
func NewCandidateElementWithXPath(xpath string, formInputs []*FormInput) *CandidateElement {
	return NewCandidateElement(
		NewIdentification(HowXPath, xpath),
		"",
		formInputs,
	)
}

// GetIdentification returns the identification.
func (c *CandidateElement) GetIdentification() *Identification {
	return c.Identification
}

// GetIdentificationPair returns how and value for the state.CandidateElementIface interface.
func (c *CandidateElement) GetIdentificationPair() (string, string) {
	if c.Identification == nil {
		return "", ""
	}
	return string(c.Identification.How), c.Identification.Value
}

// GetRelatedFrame returns the related frame.
func (c *CandidateElement) GetRelatedFrame() string {
	return c.RelatedFrame
}

// GetFormInputs returns the form inputs.
func (c *CandidateElement) GetFormInputs() []*FormInput {
	return c.FormInputs
}

// GetEventType returns the event type.
func (c *CandidateElement) GetEventType() EventType {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.EventType
}

// SetEventType sets the event type.
func (c *CandidateElement) SetEventType(eventType EventType) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.EventType = eventType
}

// GetClosestFragment returns the closest fragment.
func (c *CandidateElement) GetClosestFragment() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ClosestFragment
}

// SetClosestFragment sets the closest fragment.
func (c *CandidateElement) SetClosestFragment(fragment interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ClosestFragment = fragment
}

// GetClosestDomFragment returns the closest DOM fragment.
func (c *CandidateElement) GetClosestDomFragment() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ClosestDomFragment
}

// SetClosestDomFragment sets the closest DOM fragment.
func (c *CandidateElement) SetClosestDomFragment(fragment interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ClosestDomFragment = fragment
}

// GetDuplicateAccess returns the duplicate access count.
func (c *CandidateElement) GetDuplicateAccess() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.duplicateAccess
}

// SetDuplicateAccess sets the duplicate access count.
func (c *CandidateElement) SetDuplicateAccess(count int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.duplicateAccess = count
}

// GetEquivalentAccess returns the equivalent access count.
func (c *CandidateElement) GetEquivalentAccess() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.equivalentAccess
}

// SetEquivalentAccess sets the equivalent access count.
func (c *CandidateElement) SetEquivalentAccess(count int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.equivalentAccess = count
}

// IsDirectAccess returns whether direct access occurred.
func (c *CandidateElement) IsDirectAccess() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.directAccess
}

// SetDirectAccess sets direct access and increments duplicate access.
func (c *CandidateElement) SetDirectAccess(direct bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.directAccess = direct
	c.incrementDuplicateAccessUnlocked()
}

// IncrementDuplicateAccess increments both duplicate and equivalent access.
func (c *CandidateElement) IncrementDuplicateAccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.incrementDuplicateAccessUnlocked()
}

// incrementDuplicateAccessUnlocked is the internal unlocked version.
func (c *CandidateElement) incrementDuplicateAccessUnlocked() {
	c.duplicateAccess++
	c.equivalentAccess++
}

// IncrementEquivalentAccess increments only equivalent access.
func (c *CandidateElement) IncrementEquivalentAccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.equivalentAccess++
}

// WasExplored returns whether this element was explored.
func (c *CandidateElement) WasExplored() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.directAccess || c.duplicateAccess > 0 || c.equivalentAccess > 0
}

// ConditionChecker interface for checking eventable conditions.
// This avoids import cycle with condition package.
type ConditionChecker interface {
	CheckAllConditionsSatisfied(page interface{}) bool
}

// AllConditionsSatisfied checks if all eventable conditions are satisfied.
func (c *CandidateElement) AllConditionsSatisfied(page interface{}) bool {
	c.mu.RLock()
	ec := c.EventableCondition
	c.mu.RUnlock()

	if ec == nil {
		return true
	}

	// Try to cast to ConditionChecker interface
	if checker, ok := ec.(ConditionChecker); ok {
		return checker.CheckAllConditionsSatisfied(page)
	}

	// No checker available, allow by default
	return true
}

// GetEventableCondition returns the eventable condition.
func (c *CandidateElement) GetEventableCondition() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.EventableCondition
}

// SetEventableCondition sets the eventable condition.
func (c *CandidateElement) SetEventableCondition(condition interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.EventableCondition = condition
}

// GetGeneralString returns unique string WITHOUT atusa attribute.
// Format: "TAGNAME: attr1=val1 attr2=val2 identification relatedFrame"
func (c *CandidateElement) GetGeneralString() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result strings.Builder

	if c.TagName != "" {
		result.WriteString(c.TagName)
		result.WriteString(": ")
	}

	// Get attributes excluding atusa
	attrs := c.getAttributesExcluding("atusa")
	result.WriteString(attrs)
	result.WriteString(" ")

	if c.Identification != nil {
		result.WriteString(c.Identification.String())
	}
	result.WriteString(" ")
	result.WriteString(c.RelatedFrame)

	return result.String()
}

// GetUniqueString returns unique string WITH all attributes.
// Format: "TAGNAME: attr1=val1 attr2=val2 identification relatedFrame"
func (c *CandidateElement) GetUniqueString() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result strings.Builder

	if c.TagName != "" {
		result.WriteString(c.TagName)
		result.WriteString(": ")
		result.WriteString(c.Attributes) // All attributes including atusa
		result.WriteString(" ")
	}

	if c.Identification != nil {
		result.WriteString(c.Identification.String())
	}
	result.WriteString(" ")
	result.WriteString(c.RelatedFrame)

	return result.String()
}

// getAttributesExcluding returns attributes excluding specified ones.
func (c *CandidateElement) getAttributesExcluding(exclude string) string {
	// Parse attributes and filter out excluded
	if c.Attributes == "" {
		return ""
	}

	// Simple parsing: assume format "key=value key2=value2"
	parts := strings.Fields(c.Attributes)
	var filtered []string
	for _, part := range parts {
		if !strings.HasPrefix(part, exclude+"=") {
			filtered = append(filtered, part)
		}
	}
	return strings.Join(filtered, " ")
}

// String returns a string representation.
func (c *CandidateElement) String() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return fmt.Sprintf("CandidateElement{identification=%v, tagName=%s, relatedFrame=%s, duplicateAccess=%d, equivalentAccess=%d}",
		c.Identification, c.TagName, c.RelatedFrame, c.duplicateAccess, c.equivalentAccess)
}
