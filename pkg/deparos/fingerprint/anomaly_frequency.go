package fingerprint

import (
	"sync"
)

// ValueCounter tracks occurrences of each unique value for one attribute.
// Thread-safe with fine-grained locking.
type ValueCounter struct {
	valueCounts map[uint32]int
	mu          sync.RWMutex
}

// NewValueCounter creates a new counter.
func NewValueCounter() *ValueCounter {
	return &ValueCounter{
		valueCounts: make(map[uint32]int),
	}
}

// Record records a value occurrence.
// Returns true if this is the first occurrence (novel value).
func (vc *ValueCounter) Record(value uint32) bool {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	_, exists := vc.valueCounts[value]
	vc.valueCounts[value]++
	return !exists
}

// GetFrequency returns occurrence count for a value.
func (vc *ValueCounter) GetFrequency(value uint32) int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return vc.valueCounts[value]
}

// UniqueCount returns number of unique values.
func (vc *ValueCounter) UniqueCount() int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return len(vc.valueCounts)
}

// AttributeFrequencyTracker tracks frequencies across all attributes.
// Thread-safe for concurrent access.
type AttributeFrequencyTracker struct {
	counters map[Attribute]*ValueCounter
	mu       sync.RWMutex
}

// NewAttributeFrequencyTracker creates a new tracker.
func NewAttributeFrequencyTracker() *AttributeFrequencyTracker {
	return &AttributeFrequencyTracker{
		counters: make(map[Attribute]*ValueCounter),
	}
}

// getOrCreateCounter returns existing counter or creates a new one.
func (aft *AttributeFrequencyTracker) getOrCreateCounter(attr Attribute) *ValueCounter {
	aft.mu.RLock()
	counter, exists := aft.counters[attr]
	aft.mu.RUnlock()

	if exists {
		return counter
	}

	aft.mu.Lock()
	defer aft.mu.Unlock()

	// Double-check after acquiring write lock
	if counter, exists = aft.counters[attr]; exists {
		return counter
	}

	counter = NewValueCounter()
	aft.counters[attr] = counter
	return counter
}

// RecordValue records a value occurrence for an attribute.
// Returns true if this is the first occurrence (novel value).
func (aft *AttributeFrequencyTracker) RecordValue(attr Attribute, value uint32) bool {
	counter := aft.getOrCreateCounter(attr)
	return counter.Record(value)
}

// GetFrequency returns occurrence count for an attribute-value pair.
func (aft *AttributeFrequencyTracker) GetFrequency(attr Attribute, value uint32) int {
	aft.mu.RLock()
	counter, exists := aft.counters[attr]
	aft.mu.RUnlock()

	if !exists {
		return 0
	}
	return counter.GetFrequency(value)
}

// GetVariantAttributes returns attributes with 2+ unique values.
// Only these attributes contribute to anomaly scoring.
func (aft *AttributeFrequencyTracker) GetVariantAttributes() []Attribute {
	aft.mu.RLock()
	defer aft.mu.RUnlock()

	var variants []Attribute
	for attr, counter := range aft.counters {
		if counter.UniqueCount() > 1 {
			variants = append(variants, attr)
		}
	}
	return variants
}

// IsVariant returns true if attribute has 2+ unique values.
func (aft *AttributeFrequencyTracker) IsVariant(attr Attribute) bool {
	aft.mu.RLock()
	counter, exists := aft.counters[attr]
	aft.mu.RUnlock()

	if !exists {
		return false
	}
	return counter.UniqueCount() > 1
}

// GetUniqueCount returns number of unique values for an attribute.
func (aft *AttributeFrequencyTracker) GetUniqueCount(attr Attribute) int {
	aft.mu.RLock()
	counter, exists := aft.counters[attr]
	aft.mu.RUnlock()

	if !exists {
		return 0
	}
	return counter.UniqueCount()
}

// Reset clears all tracked frequencies.
func (aft *AttributeFrequencyTracker) Reset() {
	aft.mu.Lock()
	defer aft.mu.Unlock()
	aft.counters = make(map[Attribute]*ValueCounter)
}
