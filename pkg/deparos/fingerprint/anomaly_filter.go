package fingerprint

import (
	"math"
	"sort"
)

// FilterMethod defines the filtering algorithm.
type FilterMethod int

const (
	// FilterMethodAuto selects the best method based on variance level.
	FilterMethodAuto FilterMethod = iota
	// FilterMethodIQR uses Interquartile Range (Q3 + 1.5*IQR threshold).
	FilterMethodIQR
	// FilterMethodZScore uses standard deviation (mean + N*stddev threshold).
	FilterMethodZScore
	// FilterMethodElbow detects sharp dropoff in scores.
	FilterMethodElbow
	// FilterMethodTopPercent returns top N% of records.
	FilterMethodTopPercent
)

// VarianceLevel categorizes data distribution based on coefficient of variation.
type VarianceLevel int

const (
	// VarianceZero indicates all scores are identical (CV = 0%).
	VarianceZero VarianceLevel = iota
	// VarianceVeryLow indicates very little variation (CV < 10%).
	VarianceVeryLow
	// VarianceLow indicates some variation (CV 10-25%).
	VarianceLow
	// VarianceModerate indicates clear separation (CV 25-50%).
	VarianceModerate
	// VarianceHigh indicates strong separation (CV > 50%).
	VarianceHigh
)

// FilterConfig configures filtering behavior.
type FilterConfig struct {
	Method             FilterMethod
	ZScoreThreshold    float64 // Default: 2.0 (2 standard deviations)
	IQRMultiplier      float64 // Default: 1.5 (standard outlier detection)
	ElbowSensitivity   float64 // Default: 0.5 (50% drop between consecutive scores)
	TopPercent         float64 // Default: 0.1 (top 10%)
	MinimumInteresting int     // Minimum records to return
	MaximumInteresting int     // Maximum records to return (0 = unlimited)
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

// DistributionStats holds score distribution analysis.
type DistributionStats struct {
	Total         int           // Number of records
	Mean          float64       // Average score
	Median        float64       // Median score
	StdDev        float64       // Standard deviation
	Min           int           // Minimum score
	Max           int           // Maximum score
	Q1            float64       // 25th percentile
	Q3            float64       // 75th percentile
	IQR           float64       // Interquartile range (Q3 - Q1)
	CV            float64       // Coefficient of Variation (StdDev/Mean * 100)
	VarianceLevel VarianceLevel // Categorized variance level
	Recommended   FilterMethod  // Recommended filter method
}

// InterestingFilter filters anomalous records based on configured method.
type InterestingFilter struct {
	method FilterMethod
}

// NewInterestingFilter creates a filter with specified method.
func NewInterestingFilter(method FilterMethod) *InterestingFilter {
	return &InterestingFilter{method: method}
}

// FilterInteresting returns records that exceed the threshold based on method.
// Records must be pre-ranked (scores already calculated).
func (f *InterestingFilter) FilterInteresting(
	records []*ResponseRecord,
	config FilterConfig,
) []*ResponseRecord {
	if len(records) == 0 {
		return nil
	}

	// Get sorted scores for statistical analysis
	scores := extractScores(records)
	sort.Sort(sort.Reverse(sort.IntSlice(scores)))

	// Determine method
	method := config.Method
	if method == FilterMethodAuto {
		stats := AnalyzeScoreDistribution(records)
		method = stats.Recommended
	}

	var threshold float64
	switch method {
	case FilterMethodIQR:
		threshold = calculateIQRThreshold(scores, config.IQRMultiplier)
	case FilterMethodZScore:
		threshold = calculateZScoreThreshold(scores, config.ZScoreThreshold)
	case FilterMethodElbow:
		threshold = calculateElbowThreshold(scores, config.ElbowSensitivity)
	case FilterMethodTopPercent:
		threshold = calculateTopPercentThreshold(scores, config.TopPercent)
	default:
		threshold = calculateIQRThreshold(scores, config.IQRMultiplier)
	}

	// Filter records above threshold
	var interesting []*ResponseRecord
	for _, record := range records {
		if float64(record.Score) >= threshold {
			interesting = append(interesting, record)
		}
	}

	// Apply min/max limits
	if len(interesting) < config.MinimumInteresting && len(records) >= config.MinimumInteresting {
		// Sort by score descending and take minimum
		sorted := make([]*ResponseRecord, len(records))
		copy(sorted, records)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Score > sorted[j].Score
		})
		interesting = sorted[:config.MinimumInteresting]
	}

	if config.MaximumInteresting > 0 && len(interesting) > config.MaximumInteresting {
		// Sort and truncate
		sort.Slice(interesting, func(i, j int) bool {
			return interesting[i].Score > interesting[j].Score
		})
		interesting = interesting[:config.MaximumInteresting]
	}

	return interesting
}

// AnalyzeScoreDistribution computes statistics and recommends a filter method.
func AnalyzeScoreDistribution(records []*ResponseRecord) DistributionStats {
	if len(records) == 0 {
		return DistributionStats{}
	}

	scores := extractScores(records)
	sort.Ints(scores)

	n := len(scores)
	stats := DistributionStats{
		Total: n,
		Min:   scores[0],
		Max:   scores[n-1],
	}

	// Calculate mean
	var sum float64
	for _, s := range scores {
		sum += float64(s)
	}
	stats.Mean = sum / float64(n)

	// Calculate median
	if n%2 == 0 {
		stats.Median = float64(scores[n/2-1]+scores[n/2]) / 2
	} else {
		stats.Median = float64(scores[n/2])
	}

	// Calculate standard deviation
	var sumSquares float64
	for _, s := range scores {
		diff := float64(s) - stats.Mean
		sumSquares += diff * diff
	}
	stats.StdDev = math.Sqrt(sumSquares / float64(n))

	// Calculate quartiles
	stats.Q1 = percentile(scores, 0.25)
	stats.Q3 = percentile(scores, 0.75)
	stats.IQR = stats.Q3 - stats.Q1

	// Calculate coefficient of variation
	if stats.Mean > 0 {
		stats.CV = (stats.StdDev / stats.Mean) * 100
	}

	// Determine variance level
	stats.VarianceLevel = categorizeVariance(stats.CV)

	// Recommend filter method based on variance
	stats.Recommended = recommendMethod(stats.VarianceLevel, n)

	return stats
}

// FilterInteresting is a convenience function that creates engine, ranks, and filters.
func FilterInteresting(
	engine *AnomalyEngine,
	records []*ResponseRecord,
	config FilterConfig,
) ([]*ResponseRecord, error) {
	if err := engine.RankAndSort(records); err != nil {
		return nil, err
	}

	filter := NewInterestingFilter(config.Method)
	return filter.FilterInteresting(records, config), nil
}

// extractScores extracts all scores from records.
func extractScores(records []*ResponseRecord) []int {
	scores := make([]int, len(records))
	for i, r := range records {
		scores[i] = r.Score
	}
	return scores
}

// percentile calculates the p-th percentile (0-1).
func percentile(sorted []int, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return float64(sorted[0])
	}

	index := p * float64(len(sorted)-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))

	if lower == upper {
		return float64(sorted[lower])
	}

	fraction := index - float64(lower)
	return float64(sorted[lower]) + fraction*(float64(sorted[upper])-float64(sorted[lower]))
}

// calculateIQRThreshold returns Q3 + (IQR * multiplier).
func calculateIQRThreshold(scores []int, multiplier float64) float64 {
	if len(scores) == 0 {
		return 0
	}

	sorted := make([]int, len(scores))
	copy(sorted, scores)
	sort.Ints(sorted)

	q1 := percentile(sorted, 0.25)
	q3 := percentile(sorted, 0.75)
	iqr := q3 - q1

	return q3 + (iqr * multiplier)
}

// calculateZScoreThreshold returns mean + (stddev * threshold).
func calculateZScoreThreshold(scores []int, threshold float64) float64 {
	if len(scores) == 0 {
		return 0
	}

	// Calculate mean
	var sum float64
	for _, s := range scores {
		sum += float64(s)
	}
	mean := sum / float64(len(scores))

	// Calculate standard deviation
	var sumSquares float64
	for _, s := range scores {
		diff := float64(s) - mean
		sumSquares += diff * diff
	}
	stddev := math.Sqrt(sumSquares / float64(len(scores)))

	return mean + (stddev * threshold)
}

// calculateElbowThreshold finds the point where score drops sharply.
func calculateElbowThreshold(scores []int, sensitivity float64) float64 {
	if len(scores) < 2 {
		if len(scores) == 1 {
			return float64(scores[0])
		}
		return 0
	}

	// Scores should be sorted descending
	sorted := make([]int, len(scores))
	copy(sorted, scores)
	sort.Sort(sort.Reverse(sort.IntSlice(sorted)))

	// Find elbow point (where drop exceeds sensitivity threshold)
	for i := 0; i < len(sorted)-1; i++ {
		current := float64(sorted[i])
		next := float64(sorted[i+1])

		if current == 0 {
			continue
		}

		dropRatio := (current - next) / current
		if dropRatio >= sensitivity {
			// Return threshold at elbow point
			return next
		}
	}

	// No clear elbow - return minimum score
	return float64(sorted[len(sorted)-1])
}

// calculateTopPercentThreshold returns threshold for top N%.
func calculateTopPercentThreshold(scores []int, topPercent float64) float64 {
	if len(scores) == 0 {
		return 0
	}

	sorted := make([]int, len(scores))
	copy(sorted, scores)
	sort.Sort(sort.Reverse(sort.IntSlice(sorted)))

	// Calculate index for top percent
	count := int(math.Ceil(float64(len(sorted)) * topPercent))
	if count == 0 {
		count = 1
	}
	if count > len(sorted) {
		count = len(sorted)
	}

	return float64(sorted[count-1])
}

// categorizeVariance categorizes CV into variance levels.
func categorizeVariance(cv float64) VarianceLevel {
	switch {
	case cv == 0:
		return VarianceZero
	case cv < 10:
		return VarianceVeryLow
	case cv < 25:
		return VarianceLow
	case cv < 50:
		return VarianceModerate
	default:
		return VarianceHigh
	}
}

// recommendMethod recommends filter method based on variance and count.
func recommendMethod(variance VarianceLevel, count int) FilterMethod {
	// For small datasets, use simple top percent
	if count < 10 {
		return FilterMethodTopPercent
	}

	switch variance {
	case VarianceZero, VarianceVeryLow:
		// Too similar to detect anomalies - use top percent
		return FilterMethodTopPercent
	case VarianceLow:
		// Some variation - use sensitive methods
		return FilterMethodElbow
	case VarianceModerate:
		// Clear separation - IQR works well
		return FilterMethodIQR
	case VarianceHigh:
		// Strong separation - use robust method
		return FilterMethodIQR
	default:
		return FilterMethodIQR
	}
}

// String returns the filter method name.
func (m FilterMethod) String() string {
	switch m {
	case FilterMethodAuto:
		return "auto"
	case FilterMethodIQR:
		return "iqr"
	case FilterMethodZScore:
		return "zscore"
	case FilterMethodElbow:
		return "elbow"
	case FilterMethodTopPercent:
		return "top_percent"
	default:
		return "unknown"
	}
}

// String returns the variance level name.
func (v VarianceLevel) String() string {
	switch v {
	case VarianceZero:
		return "zero"
	case VarianceVeryLow:
		return "very_low"
	case VarianceLow:
		return "low"
	case VarianceModerate:
		return "moderate"
	case VarianceHigh:
		return "high"
	default:
		return "unknown"
	}
}
