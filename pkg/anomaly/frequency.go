package anomaly

import (
	"sync"
)

// ValueCounter tracks frequency counts for a single attribute type.
type ValueCounter struct {
	valueCounts map[uint32]int
	mu          sync.RWMutex
}

// newValueCounter creates a new ValueCounter.
func newValueCounter() *ValueCounter {
	return &ValueCounter{
		valueCounts: make(map[uint32]int),
	}
}

// incrementAndCheckNovel increments the count for a value and returns true
// if this is the first occurrence (novel value).
func (vc *ValueCounter) incrementAndCheckNovel(value uint32) bool {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	currentCount := vc.valueCounts[value]
	vc.valueCounts[value] = currentCount + 1

	return currentCount == 0 // First occurrence
}

// getCount returns the frequency count for a specific value.
func (vc *ValueCounter) getCount(value uint32) int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return vc.valueCounts[value]
}

// isVariant returns true if this attribute has multiple distinct values.
func (vc *ValueCounter) isVariant() bool {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return len(vc.valueCounts) > 1
}

// uniqueValueCount returns the number of distinct values.
func (vc *ValueCounter) uniqueValueCount() int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return len(vc.valueCounts)
}

// AttributeFrequencyTracker tracks the frequency of attribute values
// across a dataset of responses.
type AttributeFrequencyTracker struct {
	counters map[Type]*ValueCounter
	mu       sync.RWMutex
}

// NewAttributeFrequencyTracker creates a new AttributeFrequencyTracker.
func NewAttributeFrequencyTracker() *AttributeFrequencyTracker {
	return &AttributeFrequencyTracker{
		counters: make(map[Type]*ValueCounter),
	}
}

// Record records all attribute values from an AttributeSet.
// Returns a map indicating which attribute types had novel values.
func (aft *AttributeFrequencyTracker) Record(attrs *AttributeSet) map[Type]bool {
	novelAttributes := make(map[Type]bool)

	allAttrs := attrs.GetAll()
	for attrType, value := range allAttrs {
		isNovel := aft.RecordValue(attrType, value)
		if isNovel {
			novelAttributes[attrType] = true
		}
	}

	return novelAttributes
}

// RecordValue records an attribute value and returns true if this is
// the first occurrence (novel) of this value for this attribute type.
// This is critical for the weight degradation algorithm.
func (aft *AttributeFrequencyTracker) RecordValue(attrType Type, value uint32) bool {
	aft.mu.Lock()
	counter, exists := aft.counters[attrType]
	if !exists {
		counter = newValueCounter()
		aft.counters[attrType] = counter
	}
	aft.mu.Unlock()

	// Check if novel (first occurrence)
	return counter.incrementAndCheckNovel(value)
}

// GetFrequency returns the frequency count for a specific attribute value.
func (aft *AttributeFrequencyTracker) GetFrequency(attrType Type, value uint32) int {
	aft.mu.RLock()
	counter, exists := aft.counters[attrType]
	aft.mu.RUnlock()

	if !exists {
		return 0
	}

	return counter.getCount(value)
}

// IsVariant returns true if the attribute has multiple distinct values.
func (aft *AttributeFrequencyTracker) IsVariant(attrType Type) bool {
	aft.mu.RLock()
	counter, exists := aft.counters[attrType]
	aft.mu.RUnlock()

	if !exists {
		return false
	}

	return counter.isVariant()
}

// GetVariantAttributes returns all attribute types that have 2 or more
// distinct values across the dataset.
// Only variant attributes contribute to the anomaly score.
func (aft *AttributeFrequencyTracker) GetVariantAttributes() []Type {
	aft.mu.RLock()
	defer aft.mu.RUnlock()

	var variants []Type
	for attrType, counter := range aft.counters {
		if counter.isVariant() {
			variants = append(variants, attrType)
		}
	}

	return variants
}

// GetUniqueValueCount returns the number of distinct values for an attribute.
func (aft *AttributeFrequencyTracker) GetUniqueValueCount(attrType Type) int {
	aft.mu.RLock()
	counter, exists := aft.counters[attrType]
	aft.mu.RUnlock()

	if !exists {
		return 0
	}

	return counter.uniqueValueCount()
}
