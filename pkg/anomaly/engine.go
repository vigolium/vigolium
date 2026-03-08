package anomaly

import (
	"fmt"
	"sort"
)

// Engine is the main orchestrator for anomaly ranking.
// It coordinates frequency tracking, weight management, and scoring.
type Engine struct {
	attributeTypes []Type
}

// NewEngine creates a new anomaly ranking engine.
// If attributeTypes is nil or empty, uses all available attributes.
func NewEngine(attributeTypes []Type) *Engine {
	if len(attributeTypes) == 0 {
		attributeTypes = AllFingerprintAttributes
	}

	return &Engine{
		attributeTypes: attributeTypes,
	}
}

// NewDefaultEngine creates an engine with all available attributes.
func NewDefaultEngine() *Engine {
	return NewEngine(nil)
}

// Rank analyzes a collection of ResponseRecords and fills in their Score fields.
// The results are unsorted - use RankAndSort if you need them sorted.
//
// Algorithm:
// 1. Single pass: record frequencies and degrade weights for novel values
// 2. Identify variant attributes (those with 2+ unique values)
// 3. Calculate anomaly scores for all records
//
// Returns an error if ranking fails.
func (e *Engine) Rank(records []*ResponseRecord) error {
	if len(records) == 0 {
		return nil
	}

	// Phase 1: Initialize tracking components
	frequencyTracker := NewAttributeFrequencyTracker()
	weightManager := NewAttributeWeightManager(e.attributeTypes)

	// Phase 2: Single-pass frequency recording with weight degradation
	// CRITICAL: This must be done in ONE pass, not two separate loops.
	// The order of processing determines what's "novel".
	for _, record := range records {
		// Process all attribute types
		for _, attrType := range e.attributeTypes {
			value, ok := record.Attributes.Get(attrType)
			if !ok || value == 0 {
				continue
			}

			// Record value and check if it's novel (first occurrence)
			isNovel := frequencyTracker.RecordValue(attrType, value)

			// If this is the first time we've seen this value,
			// degrade the weight for this attribute
			if isNovel {
				weightManager.DegradeWeight(attrType)
			}
		}
	}

	// Phase 3: Identify variant attributes (those with 2+ unique values)
	// Only variant attributes contribute to the anomaly score
	variantAttributes := frequencyTracker.GetVariantAttributes()

	if len(variantAttributes) == 0 {
		// All responses are identical - no anomalies to detect
		// Set all scores to 0
		for _, record := range records {
			record.Score = 0
		}
		return nil
	}

	// Phase 4: Calculate scores
	calculator := NewAnomalyScoreCalculator(
		frequencyTracker,
		weightManager,
		variantAttributes,
	)

	for _, record := range records {
		score, err := calculator.CalculateScore(&record.Attributes)
		if err != nil {
			return fmt.Errorf("failed to calculate score: %w", err)
		}
		record.Score = score
	}

	return nil
}

// RankAndSort is a convenience method that ranks records and sorts them
// by anomaly score in descending order (highest scores first).
func (e *Engine) RankAndSort(records []*ResponseRecord) error {
	if err := e.Rank(records); err != nil {
		return err
	}

	// Sort in descending order (highest anomaly scores first)
	sort.Slice(records, func(i, j int) bool {
		return records[i].Score > records[j].Score
	})

	return nil
}

// GetAttributeTypes returns the attribute types this engine uses.
func (e *Engine) GetAttributeTypes() []Type {
	return e.attributeTypes
}
