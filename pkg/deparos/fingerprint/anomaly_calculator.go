package fingerprint

import (
	"errors"
	"math"
)

const (
	// scoreScale multiplier to preserve decimal precision as integer.
	// Score = rawScore * 10000, preserving 4 decimal places.
	scoreScale = 10000
)

var (
	// ErrScoreOverflow indicates score calculation exceeded integer bounds.
	ErrScoreOverflow = errors.New("score calculation overflow")

	// ErrNilSample indicates a nil sample was provided.
	ErrNilSample = errors.New("nil sample")
)

// AnomalyScoreCalculator computes anomaly scores using weighted inverse frequency.
// Formula: score = Σ(weight/frequency) × 10000
type AnomalyScoreCalculator struct {
	frequencyTracker  *AttributeFrequencyTracker
	weightManager     *AttributeWeightManager
	variantAttributes []Attribute
}

// NewAnomalyScoreCalculator creates a new calculator.
func NewAnomalyScoreCalculator(
	frequencyTracker *AttributeFrequencyTracker,
	weightManager *AttributeWeightManager,
	variantAttributes []Attribute,
) *AnomalyScoreCalculator {
	return &AnomalyScoreCalculator{
		frequencyTracker:  frequencyTracker,
		weightManager:     weightManager,
		variantAttributes: variantAttributes,
	}
}

// CalculateScore computes the anomaly score for a sample.
// Higher scores indicate more anomalous (rare) responses.
func (calc *AnomalyScoreCalculator) CalculateScore(sample *Sample) (int, error) {
	if sample == nil {
		return 0, ErrNilSample
	}

	var rawScore float64

	for _, attr := range calc.variantAttributes {
		value := sample.GetHash(attr)
		if value == 0 {
			continue
		}

		frequency := calc.frequencyTracker.GetFrequency(attr, value)
		if frequency == 0 {
			continue
		}

		weight := calc.weightManager.GetWeight(attr)
		if weight == 0 {
			continue
		}

		// Contribution = weight / frequency
		// Rare values (low frequency) contribute more
		rawScore += weight / float64(frequency)
	}

	// Scale to preserve decimal precision
	scaledScore := rawScore * scoreScale

	// Overflow check
	if scaledScore > math.MaxInt32 {
		return 0, ErrScoreOverflow
	}

	return int(math.Round(scaledScore)), nil
}

// GetAttributeContribution returns the score contribution from a single attribute.
// Useful for debugging and understanding why a response scored high.
func (calc *AnomalyScoreCalculator) GetAttributeContribution(sample *Sample, attr Attribute) (int, error) {
	if sample == nil {
		return 0, ErrNilSample
	}

	value := sample.GetHash(attr)
	if value == 0 {
		return 0, nil
	}

	frequency := calc.frequencyTracker.GetFrequency(attr, value)
	if frequency == 0 {
		return 0, nil
	}

	weight := calc.weightManager.GetWeight(attr)
	if weight == 0 {
		return 0, nil
	}

	contribution := (weight / float64(frequency)) * scoreScale
	return int(math.Round(contribution)), nil
}

// GetAttributeDetails returns detailed scoring info for each attribute.
// Returns map of attribute to (contribution, frequency, weight).
func (calc *AnomalyScoreCalculator) GetAttributeDetails(sample *Sample) map[Attribute]AttributeScoreDetail {
	if sample == nil {
		return nil
	}

	details := make(map[Attribute]AttributeScoreDetail)

	for _, attr := range calc.variantAttributes {
		value := sample.GetHash(attr)
		if value == 0 {
			continue
		}

		frequency := calc.frequencyTracker.GetFrequency(attr, value)
		weight := calc.weightManager.GetWeight(attr)

		var contribution int
		if frequency > 0 && weight > 0 {
			contribution = int(math.Round((weight / float64(frequency)) * scoreScale))
		}

		details[attr] = AttributeScoreDetail{
			Value:        value,
			Frequency:    frequency,
			Weight:       weight,
			Contribution: contribution,
		}
	}

	return details
}

// AttributeScoreDetail contains detailed scoring info for one attribute.
type AttributeScoreDetail struct {
	Value        uint32  // The attribute hash value
	Frequency    int     // How many times this value appeared
	Weight       float64 // Current weight after degradation
	Contribution int     // Score contribution (scaled)
}
