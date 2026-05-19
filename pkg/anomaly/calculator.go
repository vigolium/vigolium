package anomaly

import (
	"fmt"
	"math"
)

const (
	// scoreScaleFactor converts the floating-point score to an integer
	// with 4 decimal places of precision.
	scoreScaleFactor = 10000
)

// AnomalyScoreCalculator calculates anomaly scores for responses
// using weighted frequency analysis.
type AnomalyScoreCalculator struct {
	frequencyTracker  *AttributeFrequencyTracker
	weightManager     *AttributeWeightManager
	variantAttributes []Type
}

// NewAnomalyScoreCalculator creates a new calculator with the required components.
func NewAnomalyScoreCalculator(
	frequencyTracker *AttributeFrequencyTracker,
	weightManager *AttributeWeightManager,
	variantAttributes []Type,
) *AnomalyScoreCalculator {
	return &AnomalyScoreCalculator{
		frequencyTracker:  frequencyTracker,
		weightManager:     weightManager,
		variantAttributes: variantAttributes,
	}
}

// CalculateScore computes the anomaly score for a response.
//
// Formula: score = Σ(weight/frequency) × 10000
// where the sum is over all variant attributes (those with 2+ unique values).
//
// Higher scores indicate more anomalous responses (rarer attribute values).
func (calc *AnomalyScoreCalculator) CalculateScore(attrs *AttributeSet) (int, error) {
	if attrs == nil {
		return 0, fmt.Errorf("AttributeSet is nil")
	}

	var rawScore float64

	// Only process variant attributes (those with 2+ unique values)
	for _, attrType := range calc.variantAttributes {
		value, ok := attrs.Get(attrType)
		if !ok || value == 0 {
			continue // Skip attributes with no value
		}

		frequency := calc.frequencyTracker.GetFrequency(attrType, value)
		if frequency == 0 {
			continue // Skip if frequency is zero (shouldn't happen)
		}

		weight := calc.weightManager.GetWeight(attrType)

		// Add weighted inverse frequency to score
		// Rare values (low frequency) contribute more
		rawScore += weight / float64(frequency)
	}

	// Scale to integer with 4 decimal places precision
	scaledScore := rawScore * scoreScaleFactor

	// Check for overflow before converting to int
	if scaledScore > math.MaxInt32 {
		return 0, fmt.Errorf("score overflow: %.2f exceeds maximum integer value", scaledScore)
	}

	// Round and convert to integer
	score := int(math.Round(scaledScore))

	return score, nil
}

// GetAttributeContribution calculates how much a specific attribute
// contributes to the anomaly score for a response.
// Useful for debugging and explaining why a response is anomalous.
func (calc *AnomalyScoreCalculator) GetAttributeContribution(
	attrs *AttributeSet,
	attrType Type,
) (int, error) {
	if attrs == nil {
		return 0, fmt.Errorf("AttributeSet is nil")
	}

	// Check if this is a variant attribute
	isVariant := false
	for _, variant := range calc.variantAttributes {
		if variant == attrType {
			isVariant = true
			break
		}
	}

	if !isVariant {
		return 0, nil // Non-variant attributes don't contribute
	}

	value, ok := attrs.Get(attrType)
	if !ok || value == 0 {
		return 0, nil // No value for this attribute
	}

	frequency := calc.frequencyTracker.GetFrequency(attrType, value)
	if frequency == 0 {
		return 0, nil
	}

	weight := calc.weightManager.GetWeight(attrType)
	contribution := (weight / float64(frequency)) * scoreScaleFactor

	return int(math.Round(contribution)), nil
}
