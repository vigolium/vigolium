package anomaly

import (
	"math"
	"sort"
)

// InterestingFilter provides intelligent filtering of anomalous responses
// without requiring manual threshold configuration.
type InterestingFilter struct {
	method FilterMethod
}

// FilterMethod defines the strategy for identifying interesting responses.
type FilterMethod int

const (
	// FilterMethodAuto automatically selects the best method based on data distribution
	FilterMethodAuto FilterMethod = iota

	// FilterMethodIQR uses Interquartile Range to detect outliers
	// Best for: datasets with clear separation between normal and anomalous
	FilterMethodIQR

	// FilterMethodZScore uses standard deviation to detect statistical outliers
	// Best for: normally distributed scores
	FilterMethodZScore

	// FilterMethodElbow finds the "elbow point" in score distribution
	// Best for: when there's a sharp drop-off in scores
	FilterMethodElbow

	// FilterMethodTopPercent takes top N% of responses
	// Best for: when you want a fixed percentage regardless of distribution
	FilterMethodTopPercent
)

// VarianceLevel categorizes the variance in score distribution.
// Used to select appropriate filtering strategy and provide insights.
type VarianceLevel int

const (
	// VarianceZero indicates all scores are identical (CV = 0 or IQR = 0)
	VarianceZero VarianceLevel = iota

	// VarianceVeryLow indicates very similar scores (CV < 10%)
	// All responses are too similar - no clear anomalies exist
	VarianceVeryLow

	// VarianceLow indicates low variance (CV 10-25%)
	// Some variation exists but anomalies may not be statistically significant
	VarianceLow

	// VarianceModerate indicates moderate variance (CV 25-50%)
	// Clear separation between normal and anomalous responses
	VarianceModerate

	// VarianceHigh indicates high variance (CV > 50%)
	// Strong separation - outliers are very distinct
	VarianceHigh
)

// FilterConfig configures the interesting filter behavior.
type FilterConfig struct {
	Method FilterMethod

	// For FilterMethodZScore: number of standard deviations above mean
	// Default: 2.0 (responses 2+ stddev above mean are interesting)
	ZScoreThreshold float64

	// For FilterMethodIQR: multiplier for IQR
	// Default: 1.5 (standard outlier detection)
	IQRMultiplier float64

	// For FilterMethodElbow: sensitivity for detecting score drops
	// Default: 0.5 (50% drop from previous score)
	ElbowSensitivity float64

	// For FilterMethodTopPercent: percentage to take (0.0-1.0)
	// Default: 0.1 (top 10%)
	TopPercent float64

	// MinimumInteresting: minimum number of interesting responses to return
	// Default: 1
	MinimumInteresting int

	// MaximumInteresting: maximum number of interesting responses to return
	// Default: unlimited (0)
	MaximumInteresting int
}

// DefaultFilterConfig returns a sensible default configuration.
func DefaultFilterConfig() FilterConfig {
	return FilterConfig{
		Method:             FilterMethodAuto,
		ZScoreThreshold:    2.0,
		IQRMultiplier:      1.5,
		ElbowSensitivity:   0.5,
		TopPercent:         0.1,
		MinimumInteresting: 1,
		MaximumInteresting: 0,
	}
}

// NewInterestingFilter creates a filter with the specified method.
func NewInterestingFilter(method FilterMethod) *InterestingFilter {
	return &InterestingFilter{
		method: method,
	}
}

// FilterInteresting returns only the interesting (anomalous) records from a sorted list.
// The records are assumed to be sorted by Score (highest first).
func (f *InterestingFilter) FilterInteresting(records []*ResponseRecord, config FilterConfig) []*ResponseRecord {
	if len(records) == 0 {
		return []*ResponseRecord{}
	}

	// Apply minimum constraint
	if len(records) <= config.MinimumInteresting {
		return records
	}

	// Check variance level - handle low variance case
	scores := extractScores(records)
	mean := calculateMean(scores)
	stddev := calculateStdDev(scores, mean)
	varianceLevel := calculateVarianceLevel(mean, stddev)

	// Low variance case: all responses are too similar
	// Return empty or minimum based on configuration
	if varianceLevel == VarianceZero || varianceLevel == VarianceVeryLow {
		if config.MinimumInteresting > 0 {
			minCount := config.MinimumInteresting
			if minCount > len(records) {
				minCount = len(records)
			}
			return records[:minCount]
		}
		return []*ResponseRecord{}
	}

	// Auto-select method if needed
	method := config.Method
	if method == FilterMethodAuto {
		method = f.selectBestMethod(records)
	}

	// Apply filtering based on selected method
	var interesting []*ResponseRecord
	switch method {
	case FilterMethodIQR:
		interesting = f.filterByIQR(records, config)
	case FilterMethodZScore:
		interesting = f.filterByZScore(records, config)
	case FilterMethodElbow:
		interesting = f.filterByElbow(records, config)
	case FilterMethodTopPercent:
		interesting = f.filterByTopPercent(records, config)
	default:
		// Fallback to IQR
		interesting = f.filterByIQR(records, config)
	}

	// Apply minimum constraint
	if len(interesting) < config.MinimumInteresting {
		minCount := config.MinimumInteresting
		if minCount > len(records) {
			minCount = len(records)
		}
		interesting = records[:minCount]
	}

	// Apply maximum constraint
	if config.MaximumInteresting > 0 && len(interesting) > config.MaximumInteresting {
		interesting = interesting[:config.MaximumInteresting]
	}

	return interesting
}

// selectBestMethod automatically selects the most appropriate filtering method
// based on the score distribution characteristics and variance level.
func (f *InterestingFilter) selectBestMethod(records []*ResponseRecord) FilterMethod {
	if len(records) < 10 {
		// For small datasets, use simple top percent
		return FilterMethodTopPercent
	}

	scores := extractScores(records)
	mean := calculateMean(scores)
	stddev := calculateStdDev(scores, mean)
	varianceLevel := calculateVarianceLevel(mean, stddev)

	// Variance-aware method selection
	switch varianceLevel {
	case VarianceZero, VarianceVeryLow:
		// Low variance: all responses similar, no clear anomalies
		// This case is already handled in FilterInteresting
		return FilterMethodTopPercent

	case VarianceLow:
		// Low variance: use sensitive methods
		// Elbow can detect subtle differences
		if hasSharpDropoff(scores, 0.3) { // Lower sensitivity for low variance
			return FilterMethodElbow
		}
		return FilterMethodZScore

	case VarianceModerate:
		// Moderate variance: use standard outlier detection
		_, q3, iqr := calculateIQR(scores)
		outlierThreshold := q3 + 1.5*iqr
		outlierCount := 0
		for _, score := range scores {
			if float64(score) > outlierThreshold {
				outlierCount++
			}
		}

		outlierRatio := float64(outlierCount) / float64(len(scores))
		if outlierRatio > 0.01 && outlierRatio < 0.2 {
			return FilterMethodIQR
		}

		if hasSharpDropoff(scores, 0.5) {
			return FilterMethodElbow
		}

		return FilterMethodZScore

	case VarianceHigh:
		// High variance: use robust methods
		// IQR is more robust to extreme outliers
		if hasSharpDropoff(scores, 0.6) { // Higher sensitivity for high variance
			return FilterMethodElbow
		}
		return FilterMethodIQR

	default:
		return FilterMethodZScore
	}
}

// filterByIQR uses Interquartile Range to detect outliers.
// Formula: outliers are values > Q3 + (IQR × multiplier)
func (f *InterestingFilter) filterByIQR(records []*ResponseRecord, config FilterConfig) []*ResponseRecord {
	scores := extractScores(records)
	_, q3, iqr := calculateIQR(scores)

	threshold := q3 + config.IQRMultiplier*iqr

	var interesting []*ResponseRecord
	for _, r := range records {
		if float64(r.Score) > threshold {
			interesting = append(interesting, r)
		}
	}

	return interesting
}

// filterByZScore uses standard deviation to detect statistical outliers.
// Formula: outliers are values > mean + (stddev × threshold)
func (f *InterestingFilter) filterByZScore(records []*ResponseRecord, config FilterConfig) []*ResponseRecord {
	scores := extractScores(records)
	mean := calculateMean(scores)
	stddev := calculateStdDev(scores, mean)

	threshold := mean + config.ZScoreThreshold*stddev

	var interesting []*ResponseRecord
	for _, r := range records {
		if float64(r.Score) > threshold {
			interesting = append(interesting, r)
		}
	}

	return interesting
}

// filterByElbow finds the "elbow point" where scores drop significantly.
// This is the point where the marginal decrease in score is much larger than previous decreases.
func (f *InterestingFilter) filterByElbow(records []*ResponseRecord, config FilterConfig) []*ResponseRecord {
	if len(records) < 3 {
		return records[:1]
	}

	// Calculate percentage drops between consecutive scores
	elbowIndex := 0
	maxDrop := 0.0

	for i := 0; i < len(records)-1; i++ {
		currentScore := float64(records[i].Score)
		nextScore := float64(records[i+1].Score)

		if currentScore == 0 {
			continue
		}

		// Calculate percentage drop
		drop := (currentScore - nextScore) / currentScore

		if drop > maxDrop && drop > config.ElbowSensitivity {
			maxDrop = drop
			elbowIndex = i
		}
	}

	// Return everything up to and including the elbow point
	if elbowIndex == 0 {
		elbowIndex = 1 // At least return top result
	}

	return records[:elbowIndex+1]
}

// filterByTopPercent returns the top N% of responses by score.
func (f *InterestingFilter) filterByTopPercent(records []*ResponseRecord, config FilterConfig) []*ResponseRecord {
	count := int(math.Ceil(float64(len(records)) * config.TopPercent))
	if count < 1 {
		count = 1
	}
	if count > len(records) {
		count = len(records)
	}

	return records[:count]
}

// FilterInteresting is a convenience function that ranks and filters in one call.
func FilterInteresting(engine *Engine, records []*ResponseRecord, config FilterConfig) ([]*ResponseRecord, error) {
	if err := engine.RankAndSort(records); err != nil {
		return nil, err
	}

	filter := NewInterestingFilter(config.Method)
	return filter.FilterInteresting(records, config), nil
}

// AnalyzeDistribution provides statistics about the score distribution
// to help understand the filtering results.
type DistributionStats struct {
	Total         int
	Mean          float64
	Median        float64
	StdDev        float64
	Min           int
	Max           int
	Q1            float64
	Q3            float64
	IQR           float64
	CV            float64 // Coefficient of Variation (%)
	VarianceLevel VarianceLevel
	Recommended   FilterMethod
}

// AnalyzeScoreDistribution returns statistics about the score distribution.
func AnalyzeScoreDistribution(records []*ResponseRecord) DistributionStats {
	if len(records) == 0 {
		return DistributionStats{}
	}

	scores := extractScores(records)
	mean := calculateMean(scores)
	stddev := calculateStdDev(scores, mean)
	q1, q3, iqr := calculateIQR(scores)
	cv := calculateCV(mean, stddev)
	varianceLevel := calculateVarianceLevel(mean, stddev)

	filter := NewInterestingFilter(FilterMethodAuto)
	recommended := filter.selectBestMethod(records)

	return DistributionStats{
		Total:         len(records),
		Mean:          mean,
		Median:        calculateMedian(scores),
		StdDev:        stddev,
		Min:           scores[len(scores)-1],
		Max:           scores[0],
		Q1:            q1,
		Q3:            q3,
		IQR:           iqr,
		CV:            cv,
		VarianceLevel: varianceLevel,
		Recommended:   recommended,
	}
}

// Helper functions

func extractScores(records []*ResponseRecord) []int {
	scores := make([]int, len(records))
	for i, r := range records {
		scores[i] = r.Score
	}
	return scores
}

func calculateMean(scores []int) float64 {
	if len(scores) == 0 {
		return 0
	}
	sum := 0
	for _, s := range scores {
		sum += s
	}
	return float64(sum) / float64(len(scores))
}

func calculateStdDev(scores []int, mean float64) float64 {
	if len(scores) == 0 {
		return 0
	}
	variance := 0.0
	for _, s := range scores {
		diff := float64(s) - mean
		variance += diff * diff
	}
	variance /= float64(len(scores))
	return math.Sqrt(variance)
}

func calculateMedian(scores []int) float64 {
	if len(scores) == 0 {
		return 0
	}
	sorted := make([]int, len(scores))
	copy(sorted, scores)
	sort.Ints(sorted)

	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return float64(sorted[mid-1]+sorted[mid]) / 2.0
	}
	return float64(sorted[mid])
}

func calculateIQR(scores []int) (q1, q3, iqr float64) {
	if len(scores) == 0 {
		return 0, 0, 0
	}

	sorted := make([]int, len(scores))
	copy(sorted, scores)
	sort.Ints(sorted)

	// Calculate Q1 (25th percentile)
	q1Index := len(sorted) / 4
	q1 = float64(sorted[q1Index])

	// Calculate Q3 (75th percentile)
	q3Index := (len(sorted) * 3) / 4
	q3 = float64(sorted[q3Index])

	iqr = q3 - q1
	return q1, q3, iqr
}

func hasSharpDropoff(scores []int, sensitivity float64) bool {
	if len(scores) < 3 {
		return false
	}

	for i := 0; i < len(scores)-1; i++ {
		if scores[i] == 0 {
			continue
		}
		drop := float64(scores[i]-scores[i+1]) / float64(scores[i])
		if drop > sensitivity {
			return true
		}
	}
	return false
}

// calculateCV calculates the Coefficient of Variation (CV).
// CV = (StdDev / Mean) × 100%
// Returns 0 if mean is 0 to avoid division by zero.
func calculateCV(mean, stddev float64) float64 {
	if mean == 0 {
		return 0
	}
	return (stddev / mean) * 100.0
}

// calculateVarianceLevel categorizes the variance in score distribution
// using Coefficient of Variation (CV).
func calculateVarianceLevel(mean, stddev float64) VarianceLevel {
	cv := calculateCV(mean, stddev)

	// Check for zero variance (all scores identical)
	if cv == 0 {
		return VarianceZero
	}

	// Categorize based on CV percentage
	if cv < 10.0 {
		return VarianceVeryLow
	} else if cv < 25.0 {
		return VarianceLow
	} else if cv < 50.0 {
		return VarianceModerate
	}
	return VarianceHigh
}
