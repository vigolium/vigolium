// Package action provides web crawling action types and handling.
package action

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// eventableIDCounter is used to generate unique IDs for Eventables.
var eventableIDCounter int64

// NextEventableID generates the next unique ID for an Eventable.
func NextEventableID() int64 {
	return atomic.AddInt64(&eventableIDCounter, 1)
}

// ResetEventableIDCounter resets the ID counter (for testing).
func ResetEventableIDCounter() {
	atomic.StoreInt64(&eventableIDCounter, 0)
}

// Element represents a DOM element with stripped info for serialization.
type Element struct {
	Tag        string            `json:"tag"`
	Text       string            `json:"text"`
	Attributes map[string]string `json:"attributes"`
}

// NewElement creates a new Element.
func NewElement(tag, text string, attributes map[string]string) *Element {
	if attributes == nil {
		attributes = make(map[string]string)
	}
	return &Element{
		Tag:        tag,
		Text:       text,
		Attributes: attributes,
	}
}

// NewElementFromCandidate creates an Element from CandidateElement info.
func NewElementFromCandidate(candidate *CandidateElement) *Element {
	// Parse attributes from string format "key=value key2=value2"
	attrs := make(map[string]string)
	if candidate.Attributes != "" {
		parts := strings.Fields(candidate.Attributes)
		for _, part := range parts {
			if idx := strings.Index(part, "="); idx > 0 {
				key := strings.ToLower(part[:idx])
				value := part[idx+1:]
				attrs[key] = value
			}
		}
	}
	return &Element{
		Tag:        candidate.TagName,
		Text:       candidate.Text,
		Attributes: attrs,
	}
}

// GetTag returns the tag name.
func (e *Element) GetTag() string {
	return e.Tag
}

// GetText returns the text content.
func (e *Element) GetText() string {
	return e.Text
}

// GetAttributes returns the attributes map.
func (e *Element) GetAttributes() map[string]string {
	return e.Attributes
}

// GetAttributeOrNull returns an attribute by name or empty string if not found.
func (e *Element) GetAttributeOrNull(attribute string) string {
	return e.Attributes[strings.ToLower(attribute)]
}

// GetElementID returns the id attribute or empty string.
func (e *Element) GetElementID() string {
	for key, value := range e.Attributes {
		if strings.EqualFold(key, "id") {
			return value
		}
	}
	return ""
}

// EqualAttributes checks if attributes are the same.
func (e *Element) EqualAttributes(other *Element) bool {
	if other == nil {
		return false
	}
	if len(e.Attributes) != len(other.Attributes) {
		return false
	}
	for key, value := range e.Attributes {
		if other.Attributes[key] != value {
			return false
		}
	}
	return true
}

// EqualID checks if both IDs are the same.
func (e *Element) EqualID(other *Element) bool {
	if other == nil {
		return false
	}
	myID := e.GetElementID()
	otherID := other.GetElementID()
	if myID == "" || otherID == "" {
		return false
	}
	return strings.EqualFold(myID, otherID)
}

// EqualText checks if both texts are the same.
func (e *Element) EqualText(other *Element) bool {
	if other == nil {
		return false
	}
	return strings.EqualFold(e.Text, other.Text)
}

// Equals checks equality with another Element.
func (e *Element) Equals(other *Element) bool {
	if other == nil {
		return false
	}
	if e == other {
		return true
	}
	return e.Tag == other.Tag &&
		e.Text == other.Text &&
		e.EqualAttributes(other)
}

// String returns a string representation.
func (e *Element) String() string {
	return fmt.Sprintf("Element{tag=%s, text=%s, attributes=%v}", e.Tag, e.Text, e.Attributes)
}

// Eventable represents an element having an event attached to it
// (onclick, onmouseover, ...) so that it can change the DOM state.
// This is AFTER the event is fired (becomes an edge in StateFlowGraph).
type Eventable struct {
	ID                int64           `json:"id"`
	EventType         EventType       `json:"eventType"`
	Identification    *Identification `json:"identification"`
	Element           *Element        `json:"element"`
	RelatedFormInputs []*FormInput    `json:"relatedFormInputs"`
	RelatedFrame      string          `json:"relatedFrame"`
	SourceStateID     string          `json:"sourceStateId"`
	TargetStateID     string          `json:"targetStateId"`
}

// NewEventable creates a new Eventable.
func NewEventable(identification *Identification, eventType EventType) *Eventable {
	return &Eventable{
		Identification:    identification,
		EventType:         eventType,
		RelatedFormInputs: make([]*FormInput, 0),
		RelatedFrame:      "",
	}
}

// NewEventableWithFrame creates a new Eventable with related frame.
func NewEventableWithFrame(identification *Identification, eventType EventType, relatedFrame string) *Eventable {
	e := NewEventable(identification, eventType)
	e.RelatedFrame = relatedFrame
	return e
}

// NewEventableFromCandidate creates an Eventable from CandidateElement.
func NewEventableFromCandidate(candidate *CandidateElement, eventType EventType, id int64) *Eventable {
	e := &Eventable{
		ID:             id,
		EventType:      eventType,
		Identification: candidate.Identification,
		RelatedFrame:   candidate.RelatedFrame,
	}

	// Copy form inputs
	if candidate.FormInputs != nil {
		e.RelatedFormInputs = make([]*FormInput, len(candidate.FormInputs))
		copy(e.RelatedFormInputs, candidate.FormInputs)
	} else {
		e.RelatedFormInputs = make([]*FormInput, 0)
	}

	// Create Element from candidate info
	if candidate.TagName != "" {
		e.Element = NewElementFromCandidate(candidate)
	}

	return e
}

// GetID returns the ID.
func (e *Eventable) GetID() int64 {
	return e.ID
}

// SetID sets the ID.
func (e *Eventable) SetID(id int64) {
	e.ID = id
}

// GetEventType returns the event type.
func (e *Eventable) GetEventType() EventType {
	return e.EventType
}

// SetEventType sets the event type.
func (e *Eventable) SetEventType(eventType EventType) {
	e.EventType = eventType
}

// GetIdentification returns the identification.
func (e *Eventable) GetIdentification() *Identification {
	return e.Identification
}

// SetIdentification sets the identification.
func (e *Eventable) SetIdentification(identification *Identification) {
	e.Identification = identification
}

// GetElement returns the element.
func (e *Eventable) GetElement() *Element {
	return e.Element
}

// SetElement sets the element.
func (e *Eventable) SetElement(element *Element) {
	e.Element = element
}

// GetRelatedFormInputs returns the related form inputs.
func (e *Eventable) GetRelatedFormInputs() []*FormInput {
	return e.RelatedFormInputs
}

// SetRelatedFormInputs sets the related form inputs.
func (e *Eventable) SetRelatedFormInputs(inputs []*FormInput) {
	if inputs == nil {
		e.RelatedFormInputs = make([]*FormInput, 0)
	} else {
		e.RelatedFormInputs = make([]*FormInput, len(inputs))
		copy(e.RelatedFormInputs, inputs)
	}
}

// GetRelatedFrame returns the related frame.
func (e *Eventable) GetRelatedFrame() string {
	return e.RelatedFrame
}

// GetSourceStateID returns the source state ID.
func (e *Eventable) GetSourceStateID() string {
	return e.SourceStateID
}

// SetSourceStateID sets the source state ID.
func (e *Eventable) SetSourceStateID(stateID string) {
	e.SourceStateID = stateID
}

// GetTargetStateID returns the target state ID.
func (e *Eventable) GetTargetStateID() string {
	return e.TargetStateID
}

// SetTargetStateID sets the target state ID.
func (e *Eventable) SetTargetStateID(stateID string) {
	e.TargetStateID = stateID
}

// Equals checks equality with another Eventable.
func (e *Eventable) Equals(other *Eventable) bool {
	if other == nil {
		return false
	}
	if e == other {
		return true
	}

	// Compare eventType
	if e.EventType != other.EventType {
		return false
	}

	// Compare identification
	if e.Identification == nil && other.Identification != nil {
		return false
	}
	if e.Identification != nil && !e.Identification.Equals(other.Identification) {
		return false
	}

	// Compare element
	if e.Element == nil && other.Element != nil {
		return false
	}
	if e.Element != nil && !e.Element.Equals(other.Element) {
		return false
	}

	// Compare source and target
	if e.SourceStateID != other.SourceStateID {
		return false
	}
	if e.TargetStateID != other.TargetStateID {
		return false
	}

	return true
}

// String returns a string representation.
func (e *Eventable) String() string {
	return fmt.Sprintf("Eventable{eventType=%s, identification=%v, element=%v, source=%s, target=%s}",
		e.EventType, e.Identification, e.Element, e.SourceStateID, e.TargetStateID)
}

// HashCode returns a hash code for this Eventable.
func (e *Eventable) HashCode() int64 {
	var h int64 = 17

	// Hash eventType
	for _, c := range e.EventType {
		h = 31*h + int64(c)
	}

	// Hash identification
	if e.Identification != nil {
		for _, c := range e.Identification.How {
			h = 31*h + int64(c)
		}
		for _, c := range e.Identification.Value {
			h = 31*h + int64(c)
		}
	}

	// Hash element
	if e.Element != nil {
		for _, c := range e.Element.Tag {
			h = 31*h + int64(c)
		}
		for _, c := range e.Element.Text {
			h = 31*h + int64(c)
		}
	}

	// Hash source and target
	for _, c := range e.SourceStateID {
		h = 31*h + int64(c)
	}
	for _, c := range e.TargetStateID {
		h = 31*h + int64(c)
	}

	return h
}

// GetSelector returns the selector string for this Eventable.
// This is a convenience method for executing the event.
func (e *Eventable) GetSelector() string {
	if e.Identification == nil {
		return ""
	}
	return e.Identification.Value
}

// GetIDString returns the ID as a string for legacy compatibility.
func (e *Eventable) GetIDString() string {
	return fmt.Sprintf("%d", e.ID)
}

// NewEventableFromCandidateCrawlAction creates an Eventable from a CandidateCrawlAction.
// This is the primary method used when adding edges to the graph after an action is fired.
func NewEventableFromCandidateCrawlAction(action *CandidateCrawlAction) *Eventable {
	if action == nil {
		return nil
	}
	return NewEventableFromCandidate(action.GetCandidateElement(), action.GetEventType(), NextEventableID())
}

// NewEventableFromCandidateCrawlActionWithID creates an Eventable with a specific ID.
func NewEventableFromCandidateCrawlActionWithID(action *CandidateCrawlAction, id int64) *Eventable {
	if action == nil {
		return nil
	}
	return NewEventableFromCandidate(action.GetCandidateElement(), action.GetEventType(), id)
}

// NewReloadEventable creates a reload Eventable for backtracking.
func NewReloadEventable(url string) *Eventable {
	return &Eventable{
		ID:                NextEventableID(),
		EventType:         EventTypeReload,
		Identification:    NewIdentification(HowXPath, ""),
		RelatedFormInputs: make([]*FormInput, 0),
		Element: &Element{
			Tag:        "reload",
			Text:       url,
			Attributes: map[string]string{"href": url},
		},
	}
}

// Clone creates a copy of this Eventable.
// Used for backtracking operations.
func (e *Eventable) Clone() *Eventable {
	clone := &Eventable{
		ID:            e.ID,
		EventType:     e.EventType,
		RelatedFrame:  e.RelatedFrame,
		SourceStateID: e.SourceStateID,
		TargetStateID: e.TargetStateID,
	}

	// Deep copy identification
	if e.Identification != nil {
		clone.Identification = NewIdentification(e.Identification.How, e.Identification.Value)
	}

	// Deep copy element
	if e.Element != nil {
		attrs := make(map[string]string)
		for k, v := range e.Element.Attributes {
			attrs[k] = v
		}
		clone.Element = NewElement(e.Element.Tag, e.Element.Text, attrs)
	}

	// Deep copy form inputs
	if e.RelatedFormInputs != nil {
		clone.RelatedFormInputs = make([]*FormInput, len(e.RelatedFormInputs))
		for i, input := range e.RelatedFormInputs {
			clone.RelatedFormInputs[i] = &FormInput{
				Type:           input.Type,
				Identification: input.Identification,
				InputValues:    make([]InputValue, len(input.InputValues)),
			}
			copy(clone.RelatedFormInputs[i].InputValues, input.InputValues)
		}
	}

	return clone
}
