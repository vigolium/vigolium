package condition

import "github.com/vigolium/vigolium/pkg/spitolas/internal/browser"

// Invariant represents a condition that must always hold during crawling.
// This matches Java Crawljax's Invariant for detecting unexpected state changes.
//
// An invariant has:
// - A description explaining what it checks
// - A condition that must evaluate to true
// - Optional preconditions that must hold before checking the main condition
type Invariant struct {
	// Description explains what this invariant checks (for logging/debugging)
	Description string

	// Condition is the main condition that must hold
	Condition *Condition

	// Preconditions are conditions that must be met before checking the main condition.
	// If any precondition fails, the invariant is considered N/A (not violated).
	Preconditions []*Condition
}

// NewInvariant creates a new invariant with the given condition.
func NewInvariant(description string, condition *Condition) *Invariant {
	return &Invariant{
		Description:   description,
		Condition:     condition,
		Preconditions: make([]*Condition, 0),
	}
}

// WithPrecondition adds a precondition to the invariant.
func (inv *Invariant) WithPrecondition(pre *Condition) *Invariant {
	inv.Preconditions = append(inv.Preconditions, pre)
	return inv
}

// Check evaluates the invariant against the current page state.
// Returns true if the invariant holds (condition is true or preconditions not met).
// Returns false if the invariant is violated (preconditions met but condition is false).
func (inv *Invariant) Check(page *browser.Page) bool {
	// First check all preconditions
	for _, pre := range inv.Preconditions {
		if !pre.Check(page) {
			// Precondition not met, invariant is N/A (not violated)
			return true
		}
	}

	// All preconditions met, check main condition
	return inv.Condition.Check(page)
}

// IsApplicable checks if the invariant applies (preconditions are met).
func (inv *Invariant) IsApplicable(page *browser.Page) bool {
	for _, pre := range inv.Preconditions {
		if !pre.Check(page) {
			return false
		}
	}
	return true
}

// InvariantChecker manages and checks multiple invariants.
type InvariantChecker struct {
	invariants []*Invariant
}

// NewInvariantChecker creates a new invariant checker.
func NewInvariantChecker() *InvariantChecker {
	return &InvariantChecker{
		invariants: make([]*Invariant, 0),
	}
}

// Add adds an invariant to the checker.
func (ic *InvariantChecker) Add(inv *Invariant) {
	ic.invariants = append(ic.invariants, inv)
}

// AddCondition adds a simple condition as an invariant (always applicable).
func (ic *InvariantChecker) AddCondition(description string, cond *Condition) {
	ic.invariants = append(ic.invariants, NewInvariant(description, cond))
}

// Check evaluates all invariants and returns any that are violated.
func (ic *InvariantChecker) Check(page *browser.Page) []*Invariant {
	var violated []*Invariant
	for _, inv := range ic.invariants {
		if !inv.Check(page) {
			violated = append(violated, inv)
		}
	}
	return violated
}

// CheckAll returns true if all invariants hold.
func (ic *InvariantChecker) CheckAll(page *browser.Page) bool {
	for _, inv := range ic.invariants {
		if !inv.Check(page) {
			return false
		}
	}
	return true
}

// Count returns the number of invariants.
func (ic *InvariantChecker) Count() int {
	return len(ic.invariants)
}

// Get returns the invariant at the given index.
func (ic *InvariantChecker) Get(index int) *Invariant {
	if index < 0 || index >= len(ic.invariants) {
		return nil
	}
	return ic.invariants[index]
}

// GetAll returns all invariants.
func (ic *InvariantChecker) GetAll() []*Invariant {
	result := make([]*Invariant, len(ic.invariants))
	copy(result, ic.invariants)
	return result
}

// InvariantResult holds the result of checking an invariant.
type InvariantResult struct {
	Invariant  *Invariant
	Passed     bool
	Applicable bool
}

// CheckDetailed returns detailed results for each invariant.
func (ic *InvariantChecker) CheckDetailed(page *browser.Page) []InvariantResult {
	results := make([]InvariantResult, len(ic.invariants))
	for i, inv := range ic.invariants {
		applicable := inv.IsApplicable(page)
		passed := true
		if applicable {
			passed = inv.Condition.Check(page)
		}
		results[i] = InvariantResult{
			Invariant:  inv,
			Passed:     passed,
			Applicable: applicable,
		}
	}
	return results
}

// Predefined invariant factories

// NoErrorPage creates an invariant that fails if error page indicators are present.
func NoErrorPage() *Invariant {
	return NewInvariant(
		"Page should not show error indicators",
		ElementExists("body").Not().WithPrecondition(
			Or(
				ElementExists(".error"),
				ElementExists("#error"),
				ElementExists("[class*='error']"),
			),
		),
	)
}

// NoServerError creates an invariant that fails on 500 error pages.
func NoServerError() *Invariant {
	return NewInvariant(
		"Page should not show server error",
		DOMRegex("(?i)(500|internal server error|service unavailable)").Not(),
	)
}

// NoEmptyPage creates an invariant that fails if page body is empty.
func NoEmptyPage() *Invariant {
	return NewInvariant(
		"Page should have content",
		JavaScript("document.body.innerHTML.trim().length > 0"),
	)
}

// HasElement creates an invariant that requires an element to exist.
func HasElement(selector, description string) *Invariant {
	return NewInvariant(description, ElementExists(selector))
}

// URLContainsInvariant creates an invariant that requires URL to contain substring.
func URLContainsInvariant(substring, description string) *Invariant {
	return NewInvariant(description, URLContains(substring))
}

// URLNotContainsInvariant creates an invariant that fails if URL contains substring.
func URLNotContainsInvariant(substring, description string) *Invariant {
	return NewInvariant(description, URLContains(substring).Not())
}
