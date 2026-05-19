// Package action provides web crawling action types and handling.
package action

import "fmt"

// CandidateCrawlAction corresponds to the combination of a CandidateElement and a single EventType.
// This class is used to wrap a candidate element with its event type for crawling.
type CandidateCrawlAction struct {
	candidateElement *CandidateElement
	eventType        EventType
}

// NewCandidateCrawlAction creates a new CandidateCrawlAction.
func NewCandidateCrawlAction(candidateElement *CandidateElement, eventType EventType) *CandidateCrawlAction {
	return &CandidateCrawlAction{
		candidateElement: candidateElement,
		eventType:        eventType,
	}
}

// GetCandidateElement returns the candidate element.
func (c *CandidateCrawlAction) GetCandidateElement() *CandidateElement {
	return c.candidateElement
}

// GetEventType returns the event type.
func (c *CandidateCrawlAction) GetEventType() EventType {
	return c.eventType
}

// String returns a string representation.
func (c *CandidateCrawlAction) String() string {
	return fmt.Sprintf("CandidateCrawlAction{candidateElement=%v, eventType=%s}",
		c.candidateElement, c.eventType)
}
