package condition

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
)

// EventableCondition checks conditions for specific elements.
type EventableCondition struct {
	// XPath scope - only check elements matching this XPath
	InXPath string

	// Conditions that must be true for the element to be crawled
	Conditions []*Condition

	// Linked form inputs - form fields that should be filled when this element is clicked
	LinkedInputs []LinkedInput

	// Description for logging
	Description string
}

// LinkedInput represents a form input that should be filled with specific values.
type LinkedInput struct {
	Identification *action.Identification
	Type           string   // text, checkbox, radio, select
	Values         []string // Values to use
}

// NewEventableCondition creates a new element-level condition.
func NewEventableCondition() *EventableCondition {
	return &EventableCondition{
		Conditions:   make([]*Condition, 0),
		LinkedInputs: make([]LinkedInput, 0),
	}
}

// InXPathScope sets the XPath scope for this condition.
func (ec *EventableCondition) InXPathScope(xpath string) *EventableCondition {
	ec.InXPath = xpath
	return ec
}

// WithCondition adds a condition that must be met.
func (ec *EventableCondition) WithCondition(cond *Condition) *EventableCondition {
	ec.Conditions = append(ec.Conditions, cond)
	return ec
}

// WithURLContains adds a URL contains condition.
func (ec *EventableCondition) WithURLContains(substring string) *EventableCondition {
	return ec.WithCondition(URLContains(substring))
}

// WithElementExists adds an element exists condition.
func (ec *EventableCondition) WithElementExists(selector string) *EventableCondition {
	return ec.WithCondition(ElementExists(selector))
}

// WithElementVisible adds an element visible condition.
func (ec *EventableCondition) WithElementVisible(selector string) *EventableCondition {
	return ec.WithCondition(ElementVisible(selector))
}

// WithJavaScript adds a JavaScript condition.
func (ec *EventableCondition) WithJavaScript(expression string) *EventableCondition {
	return ec.WithCondition(JavaScript(expression))
}

// WithDescription adds a description for logging.
func (ec *EventableCondition) WithDescription(desc string) *EventableCondition {
	ec.Description = desc
	return ec
}

// AddLinkedInput adds a linked form input using Identification.
func (ec *EventableCondition) AddLinkedInput(identification *action.Identification, inputType string, values ...string) *EventableCondition {
	ec.LinkedInputs = append(ec.LinkedInputs, LinkedInput{
		Identification: identification,
		Type:           inputType,
		Values:         values,
	})
	return ec
}

// AddLinkedInputByID adds a linked form input by ID.
// Convenience wrapper for AddLinkedInput with HowID.
func (ec *EventableCondition) AddLinkedInputByID(id, inputType string, values ...string) *EventableCondition {
	return ec.AddLinkedInput(action.NewIdentification(action.HowID, id), inputType, values...)
}

// AddLinkedInputByName adds a linked form input by name.
// Convenience wrapper for AddLinkedInput with HowName.
func (ec *EventableCondition) AddLinkedInputByName(name, inputType string, values ...string) *EventableCondition {
	return ec.AddLinkedInput(action.NewIdentification(action.HowName, name), inputType, values...)
}

// AddLinkedInputByXPath adds a linked form input by XPath.
// Convenience wrapper for AddLinkedInput with HowXPath.
func (ec *EventableCondition) AddLinkedInputByXPath(xpath, inputType string, values ...string) *EventableCondition {
	return ec.AddLinkedInput(action.NewIdentification(action.HowXPath, xpath), inputType, values...)
}

// Check evaluates the condition for a specific element.
// elementXPath is the XPath of the element being checked.
// page is the browser page.
// Returns true if the element should be crawled.
func (ec *EventableCondition) Check(elementXPath string, page *browser.Page) bool {
	// Check XPath scope
	if ec.InXPath != "" && !ec.matchesXPathScope(elementXPath) {
		// Element is not in scope, allow it (don't filter)
		return true
	}

	// Check all conditions
	for _, cond := range ec.Conditions {
		if !cond.Check(page) {
			return false
		}
	}

	return true
}

// matchesXPathScope checks if an element XPath is within the scope.
// CRITICAL FIX: Uses strict prefix matching only,
// Before: Also used Contains() which was too permissive.
func (ec *EventableCondition) matchesXPathScope(elementXPath string) bool {
	if ec.InXPath == "" {
		return true
	}

	// Normalize XPaths for comparison
	normalizedScope := normalizeXPath(ec.InXPath)
	normalizedElement := normalizeXPath(elementXPath)

	// CRITICAL FIX: Element XPath should START with the scope XPath (strict prefix match)
	// This ensures the element is truly a descendant of the scope, not just containing the string.
	return strings.HasPrefix(normalizedElement, normalizedScope)
}

// normalizeXPath normalizes an XPath for comparison.
func normalizeXPath(xpath string) string {
	// Remove leading slashes for consistency
	xpath = strings.TrimPrefix(xpath, "//")
	xpath = strings.TrimPrefix(xpath, "/")
	// Lowercase for case-insensitive comparison
	return strings.ToLower(xpath)
}

// GetLinkedInputs returns the linked form inputs for this condition.
func (ec *EventableCondition) GetLinkedInputs() []LinkedInput {
	return ec.LinkedInputs
}

// HasLinkedInputs returns true if there are linked form inputs.
func (ec *EventableCondition) HasLinkedInputs() bool {
	return len(ec.LinkedInputs) > 0
}

// EventableConditionChecker manages multiple eventable conditions.
type EventableConditionChecker struct {
	conditions []*EventableCondition
}

// NewEventableConditionChecker creates a new checker.
func NewEventableConditionChecker() *EventableConditionChecker {
	return &EventableConditionChecker{
		conditions: make([]*EventableCondition, 0),
	}
}

// Add adds an eventable condition.
func (ecc *EventableConditionChecker) Add(ec *EventableCondition) {
	ecc.conditions = append(ecc.conditions, ec)
}

// Check evaluates all conditions for an element.
// Returns true if the element should be crawled.
func (ecc *EventableConditionChecker) Check(elementXPath string, page *browser.Page) bool {
	for _, ec := range ecc.conditions {
		if !ec.Check(elementXPath, page) {
			return false
		}
	}
	return true
}

// GetLinkedInputs returns linked inputs from conditions matching the element.
func (ecc *EventableConditionChecker) GetLinkedInputs(elementXPath string) []LinkedInput {
	var inputs []LinkedInput
	for _, ec := range ecc.conditions {
		if ec.matchesXPathScope(elementXPath) && ec.HasLinkedInputs() {
			inputs = append(inputs, ec.LinkedInputs...)
		}
	}
	return inputs
}

// Count returns the number of conditions.
func (ecc *EventableConditionChecker) Count() int {
	return len(ecc.conditions)
}

// Predefined condition factories

// WhenURLContains creates a condition that only applies when URL contains substring.
func WhenURLContains(substring string) *EventableCondition {
	return NewEventableCondition().WithURLContains(substring)
}

// WhenElementExists creates a condition that only applies when an element exists.
func WhenElementExists(selector string) *EventableCondition {
	return NewEventableCondition().WithElementExists(selector)
}

// WhenInXPath creates a condition scoped to elements matching an XPath.
func WhenInXPath(xpath string) *EventableCondition {
	return NewEventableCondition().InXPathScope(xpath)
}

// WithFormFill creates a condition with linked form input.
func WithFormFill(xpath string, inputIdentification *action.Identification, inputType string, values ...string) *EventableCondition {
	return NewEventableCondition().
		InXPathScope(xpath).
		AddLinkedInput(inputIdentification, inputType, values...)
}

// WithFormFillByID creates a condition with linked form input identified by ID.
// Convenience wrapper for WithFormFill with HowID.
func WithFormFillByID(xpath, inputID, inputType string, values ...string) *EventableCondition {
	return WithFormFill(xpath, action.NewIdentification(action.HowID, inputID), inputType, values...)
}

// WithFormFillByName creates a condition with linked form input identified by name.
// Convenience wrapper for WithFormFill with HowName.
func WithFormFillByName(xpath, inputName, inputType string, values ...string) *EventableCondition {
	return WithFormFill(xpath, action.NewIdentification(action.HowName, inputName), inputType, values...)
}

// GetCandidateElementsForInputs generates CandidateElement variants with different form input values.
func (ecc *EventableConditionChecker) GetCandidateElementsForInputs(elementXPath string, baseCandidate *action.CandidateElement) []*action.CandidateElement {
	// Collect all linked inputs from matching conditions
	var allInputs []LinkedInput
	for _, ec := range ecc.conditions {
		if ec.matchesXPathScope(elementXPath) && ec.HasLinkedInputs() {
			allInputs = append(allInputs, ec.LinkedInputs...)
		}
	}

	if len(allInputs) == 0 {
		return []*action.CandidateElement{baseCandidate}
	}

	// Calculate max combinations
	maxValues := 1
	for _, input := range allInputs {
		if len(input.Values) > maxValues {
			maxValues = len(input.Values)
		}
	}

	// Generate CandidateElement combinations
	combinations := make([]*action.CandidateElement, 0, maxValues)
	for i := 0; i < maxValues; i++ {
		// Clone the base candidate
		clone := &action.CandidateElement{
			Identification: baseCandidate.Identification,
			RelatedFrame:   baseCandidate.RelatedFrame,
			TagName:        baseCandidate.TagName,
			Attributes:     baseCandidate.Attributes,
			Text:           baseCandidate.Text,
			Href:           baseCandidate.Href,
			EventType:      baseCandidate.EventType,
			FormInputs:     make([]*action.FormInput, 0, len(allInputs)),
		}

		// Add form inputs for this combination
		for _, input := range allInputs {
			if len(input.Values) > 0 && input.Identification != nil {
				valueIndex := i % len(input.Values)
				formInput := &action.FormInput{
					Type:           action.InputType(input.Type),
					Identification: input.Identification,
					InputValues:    []action.InputValue{{Value: input.Values[valueIndex]}},
				}
				clone.FormInputs = append(clone.FormInputs, formInput)
			}
		}
		combinations = append(combinations, clone)
	}

	return combinations
}

// GetFormInputs returns all form inputs from all conditions.
func (ecc *EventableConditionChecker) GetFormInputs() []*action.FormInput {
	var result []*action.FormInput
	for _, ec := range ecc.conditions {
		for _, input := range ec.LinkedInputs {
			if input.Identification == nil {
				continue
			}
			// Convert LinkedInput to FormInput
			formInput := &action.FormInput{
				Type:           action.InputType(input.Type),
				Identification: input.Identification,
				InputValues:    make([]action.InputValue, 0, len(input.Values)),
			}
			for _, v := range input.Values {
				formInput.InputValues = append(formInput.InputValues, action.InputValue{Value: v})
			}
			result = append(result, formInput)
		}
	}
	return result
}
