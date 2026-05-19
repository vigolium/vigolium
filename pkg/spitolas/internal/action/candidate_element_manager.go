// Package action provides web crawling action types and handling.
package action

import (
	"sync"
	"sync/atomic"
)

// ExtractorManager defines the operations a CandidateExtractor can execute.
type ExtractorManager interface {
	// IsChecked checks if a given element is already checked, preventing duplicate work.
	IsChecked(element string) bool

	// MarkChecked marks a given element as checked to prevent duplicate work.
	// A element is only added when it is not already in the set of checked elements.
	// Returns true if !contains(candidateElement.uniqueString)
	MarkChecked(candidateElement *CandidateElement) bool

	// IncreaseElementsCounter increases the number of checked elements,
	// as a statistics measure to know how many elements were actually examined.
	IncreaseElementsCounter()

	// NumberOfExaminedElements returns internal counter for the examined elements.
	NumberOfExaminedElements() int

	// GetEventableConditionChecker returns the eventable condition checker.
	// Note: Returns interface{} to avoid import cycle - will be EventableConditionChecker
	GetEventableConditionChecker() interface{}

	// CheckCrawlCondition checks if one or more CrawlConditions matches the current state.
	// Returns true if one or more CrawlConditions satisfies or none is specified.
	// Note: Takes interface{} to avoid import cycle - will be browser
	CheckCrawlCondition(browser interface{}) bool
}

// CandidateElementManager is an ExtractorManager for the CandidateElements.
// It implements the ExtractorManager interface.
type CandidateElementManager struct {
	// counter uses atomic integer to prevent problems when increasing.
	counter int64

	// elements uses map for thread-safe checking and storing checkedElements.
	elements map[string]bool

	// elementsLock is used to lock the elements when adding multiple elements.
	elementsLock sync.Mutex

	// eventableConditionChecker where to load the EventableConditions from.
	// Using interface{} to avoid import cycle
	eventableConditionChecker interface{}

	// crawlConditionChecker to use in checkCrawlCondition operation.
	// Using interface{} to avoid import cycle
	crawlConditionChecker interface{}
}

// NewCandidateElementManager creates a new CandidateElementManager.
func NewCandidateElementManager(eventableConditionChecker, crawlConditionChecker interface{}) *CandidateElementManager {
	return &CandidateElementManager{
		counter:                   0,
		elements:                  make(map[string]bool),
		eventableConditionChecker: eventableConditionChecker,
		crawlConditionChecker:     crawlConditionChecker,
	}
}

// IncreaseElementsCounter increases the number of checked elements,
// as a statistics measure to know how many elements were actually examined.
// Thread safe by using atomic operations.
func (m *CandidateElementManager) IncreaseElementsCounter() {
	atomic.AddInt64(&m.counter, 1)
}

// IsChecked checks if a given element is already checked, preventing duplicate work.
func (m *CandidateElementManager) IsChecked(element string) bool {
	m.elementsLock.Lock()
	defer m.elementsLock.Unlock()
	return m.elements[element]
}

// MarkChecked marks a given element as checked to prevent duplicate work.
// A element is only added when it is not already in the set of checked elements.
// Returns true if !contains(element.uniqueString)
func (m *CandidateElementManager) MarkChecked(element *CandidateElement) bool {
	generalString := element.GetGeneralString()
	uniqueString := element.GetUniqueString()

	m.elementsLock.Lock()
	defer m.elementsLock.Unlock()

	if m.elements[uniqueString] {
		return false
	}

	m.elements[generalString] = true
	m.elements[uniqueString] = true
	return true
}

// NumberOfExaminedElements returns internal counter for the examined elements.
func (m *CandidateElementManager) NumberOfExaminedElements() int {
	return int(atomic.LoadInt64(&m.counter))
}

// GetEventableConditionChecker returns the eventable condition checker.
func (m *CandidateElementManager) GetEventableConditionChecker() interface{} {
	return m.eventableConditionChecker
}

// CheckCrawlCondition checks if one or more CrawlConditions matches the current state.
// Returns true if one or more CrawlConditions satisfies or none is specified.
func (m *CandidateElementManager) CheckCrawlCondition(browser interface{}) bool {
	if m.crawlConditionChecker == nil {
		return true
	}

	// Note: The actual implementation would call crawlConditionChecker.getFailedConditions(browser).isEmpty()
	// For now, return true as default (no failed conditions)
	// This will be properly implemented when condition package is added
	return true
}

// GetCheckedElementsCount returns the number of unique elements checked.
// This is a helper method for debugging/statistics.
func (m *CandidateElementManager) GetCheckedElementsCount() int {
	m.elementsLock.Lock()
	defer m.elementsLock.Unlock()
	return len(m.elements)
}

// Clear resets the manager state.
// This is for testing purposes.
func (m *CandidateElementManager) Clear() {
	m.elementsLock.Lock()
	defer m.elementsLock.Unlock()
	m.elements = make(map[string]bool)
	atomic.StoreInt64(&m.counter, 0)
}

// Ensure CandidateElementManager implements ExtractorManager
var _ ExtractorManager = (*CandidateElementManager)(nil)
