// Package action provides web crawling action types and handling.
// This file implements CandidateCrawlAction matching Java Crawljax's
// com.crawljax.core.CandidateCrawlAction exactly.
package action

import "fmt"

// CandidateCrawlAction corresponds to the combination of a CandidateElement and a single EventType.
// This class is used to wrap a candidate element with its event type for crawling.
// Matches Java com.crawljax.core.CandidateCrawlAction exactly.
type CandidateCrawlAction struct {
	candidateElement *CandidateElement
	eventType        EventType
}

// NewCandidateCrawlAction creates a new CandidateCrawlAction.
// Matches Java constructor: CandidateCrawlAction(CandidateElement, EventType)
func NewCandidateCrawlAction(candidateElement *CandidateElement, eventType EventType) *CandidateCrawlAction {
	return &CandidateCrawlAction{
		candidateElement: candidateElement,
		eventType:        eventType,
	}
}

// GetCandidateElement returns the candidate element.
// Matches Java getCandidateElement()
func (c *CandidateCrawlAction) GetCandidateElement() *CandidateElement {
	return c.candidateElement
}

// GetEventType returns the event type.
// Matches Java getEventType()
func (c *CandidateCrawlAction) GetEventType() EventType {
	return c.eventType
}

// String returns a string representation.
// Matches Java toString()
func (c *CandidateCrawlAction) String() string {
	return fmt.Sprintf("CandidateCrawlAction{candidateElement=%v, eventType=%s}",
		c.candidateElement, c.eventType)
}
