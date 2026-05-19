package fingerprint

import (
	"sort"
)

// ResponseRecord wraps a Sample with metadata and score for anomaly detection.
// Metadata is user-defined (URL, index, request ID, custom struct, etc.)
type ResponseRecord struct {
	Sample   *Sample     // Reuse existing Sample (already has 31 attributes)
	Metadata interface{} // User-defined data
	Score    int         // Anomaly score (0-∞, higher = more anomalous)
}

// AnomalyEngine orchestrates the ranking of HTTP responses by anomaly score.
// Uses weighted inverse frequency analysis to identify unusual responses.
type AnomalyEngine struct {
	attributes []Attribute // Which attributes to analyze
}

// NewAnomalyEngine creates an engine with specified attributes.
// Pass nil or empty slice to use all active attributes.
func NewAnomalyEngine(attributes []Attribute) *AnomalyEngine {
	if len(attributes) == 0 {
		attributes = AllActiveAttributes()
	}
	return &AnomalyEngine{
		attributes: attributes,
	}
}

// NewDefaultAnomalyEngine creates an engine with all active attributes.
func NewDefaultAnomalyEngine() *AnomalyEngine {
	return NewAnomalyEngine(nil)
}

// Rank calculates anomaly scores for all records.
// Scores are set in place on each ResponseRecord.
// Higher scores indicate more anomalous (rare) responses.
func (e *AnomalyEngine) Rank(records []*ResponseRecord) error {
	if len(records) == 0 {
		return nil
	}

	// Phase 1: Build frequency tracker and weight manager
	frequencyTracker := NewAttributeFrequencyTracker()
	weightManager := NewAttributeWeightManager(e.attributes)

	// Phase 2: Single-pass frequency recording + weight degradation
	for _, record := range records {
		if record.Sample == nil {
			continue
		}
		for _, attr := range e.attributes {
			value := record.Sample.GetHash(attr)
			if value == 0 {
				continue
			}
			isNovel := frequencyTracker.RecordValue(attr, value)
			if isNovel {
				weightManager.DegradeWeight(attr)
			}
		}
	}

	// Phase 3: Identify variant attributes (those with 2+ unique values)
	variantAttributes := frequencyTracker.GetVariantAttributes()
	if len(variantAttributes) == 0 {
		// All attributes are constant - set all scores to 0
		for _, record := range records {
			record.Score = 0
		}
		return nil
	}

	// Phase 4: Calculate scores
	calculator := NewAnomalyScoreCalculator(frequencyTracker, weightManager, variantAttributes)
	for _, record := range records {
		if record.Sample == nil {
			record.Score = 0
			continue
		}
		score, err := calculator.CalculateScore(record.Sample)
		if err != nil {
			record.Score = 0
			continue
		}
		record.Score = score
	}

	return nil
}

// RankAndSort ranks all records and sorts by score descending.
// Records with highest anomaly scores appear first.
func (e *AnomalyEngine) RankAndSort(records []*ResponseRecord) error {
	if err := e.Rank(records); err != nil {
		return err
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Score > records[j].Score
	})

	return nil
}

// GetAttributes returns the attributes used by this engine.
func (e *AnomalyEngine) GetAttributes() []Attribute {
	result := make([]Attribute, len(e.attributes))
	copy(result, e.attributes)
	return result
}
