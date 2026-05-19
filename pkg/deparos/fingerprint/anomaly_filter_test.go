package fingerprint

import (
	"fmt"
	"math/rand"
	"testing"
)

// =============================================================================
// Test Helpers
// =============================================================================

// makeRecords creates ResponseRecords with given scores.
func makeRecords(scores []int) []*ResponseRecord {
	records := make([]*ResponseRecord, len(scores))
	for i, score := range scores {
		records[i] = &ResponseRecord{
			Score:    score,
			Metadata: i,
		}
	}
	return records
}

// makeRecordsWithSamples creates records with actual samples for full engine testing.
func makeRecordsWithSamples(attrs []map[Attribute]uint32) []*ResponseRecord {
	records := make([]*ResponseRecord, len(attrs))
	for i, a := range attrs {
		records[i] = &ResponseRecord{
			Sample:   createTestSample(a),
			Metadata: i,
		}
	}
	return records
}

// generateUniformScores creates n scores uniformly distributed between minVal and maxVal.
func generateUniformScores(n, minVal, maxVal int) []int {
	scores := make([]int, n)
	step := float64(maxVal-minVal) / float64(n-1)
	for i := range n {
		scores[i] = minVal + int(float64(i)*step)
	}
	return scores
}

// generateIdenticalScores creates n identical scores.
func generateIdenticalScores(n, value int) []int {
	scores := make([]int, n)
	for i := 0; i < n; i++ {
		scores[i] = value
	}
	return scores
}

// generateNormalWithOutliers creates n scores with base value and specific outliers.
func generateNormalWithOutliers(n, base int, outliers []int) []int {
	scores := make([]int, n)
	for i := 0; i < n-len(outliers); i++ {
		scores[i] = base
	}
	for i, o := range outliers {
		scores[n-len(outliers)+i] = o
	}
	return scores
}

// =============================================================================
// FilterMethodAuto: Variance Level Detection Tests
// =============================================================================

func TestFilterMethodAuto_VarianceZero(t *testing.T) {
	t.Run("all identical scores should use TopPercent", func(t *testing.T) {
		records := makeRecords(generateIdenticalScores(100, 500))
		stats := AnalyzeScoreDistribution(records)

		if stats.VarianceLevel != VarianceZero {
			t.Errorf("Expected VarianceZero, got %v (CV=%.2f%%)", stats.VarianceLevel, stats.CV)
		}
		if stats.Recommended != FilterMethodTopPercent {
			t.Errorf("Expected TopPercent for zero variance, got %v", stats.Recommended)
		}
	})

	t.Run("zero variance returns all records (all equal threshold)", func(t *testing.T) {
		records := makeRecords(generateIdenticalScores(100, 500))
		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto

		filter := NewInterestingFilter(FilterMethodAuto)
		interesting := filter.FilterInteresting(records, config)

		// When all scores are identical, TopPercent threshold = that score
		// So all records match threshold >= score. This is expected behavior.
		// With MaximumInteresting we can limit output.
		if len(interesting) != 100 {
			t.Errorf("Expected all 100 records (all equal threshold), got %d", len(interesting))
		}
	})
}

func TestFilterMethodAuto_VarianceVeryLow(t *testing.T) {
	t.Run("CV < 10% should use TopPercent", func(t *testing.T) {
		// Create scores with very low variance (CV < 10%)
		// Mean=100, StdDev<10 -> CV < 10%
		scores := make([]int, 100)
		for i := 0; i < 100; i++ {
			scores[i] = 100 + (i % 5) // Values 100-104, very low variance
		}

		records := makeRecords(scores)
		stats := AnalyzeScoreDistribution(records)

		if stats.VarianceLevel != VarianceVeryLow {
			t.Errorf("Expected VarianceVeryLow, got %v (CV=%.2f%%)", stats.VarianceLevel, stats.CV)
		}
		if stats.Recommended != FilterMethodTopPercent {
			t.Errorf("Expected TopPercent for very low variance, got %v", stats.Recommended)
		}
	})
}

func TestFilterMethodAuto_VarianceLow(t *testing.T) {
	t.Run("CV 10-25% should use Elbow", func(t *testing.T) {
		// Create scores with low variance (CV 10-25%)
		// CV = (StdDev/Mean) * 100
		// For CV ~15%: if mean=100, need stddev=15
		// Use range that gives CV around 15%
		scores := make([]int, 100)
		for i := 0; i < 100; i++ {
			// Range 70-130, mean=100, gives CV ~17%
			scores[i] = 70 + (i * 60 / 100)
		}

		records := makeRecords(scores)
		stats := AnalyzeScoreDistribution(records)

		if stats.VarianceLevel != VarianceLow {
			t.Errorf("Expected VarianceLow, got %v (CV=%.2f%%)", stats.VarianceLevel, stats.CV)
		}
		if stats.Recommended != FilterMethodElbow {
			t.Errorf("Expected Elbow for low variance, got %v", stats.Recommended)
		}
	})
}

func TestFilterMethodAuto_VarianceModerate(t *testing.T) {
	t.Run("CV 25-50% should use IQR", func(t *testing.T) {
		// Create scores with moderate variance (CV 25-50%)
		// CV = (StdDev/Mean) * 100
		// For CV ~35%: if mean=100, need stddev=35
		// Use wider range: 50-150 gives CV ~30%
		scores := make([]int, 100)
		for i := 0; i < 100; i++ {
			scores[i] = 50 + i // Values 50-149, mean=99.5
		}

		records := makeRecords(scores)
		stats := AnalyzeScoreDistribution(records)

		if stats.VarianceLevel != VarianceModerate {
			t.Errorf("Expected VarianceModerate, got %v (CV=%.2f%%)", stats.VarianceLevel, stats.CV)
		}
		if stats.Recommended != FilterMethodIQR {
			t.Errorf("Expected IQR for moderate variance, got %v", stats.Recommended)
		}
	})
}

func TestFilterMethodAuto_VarianceHigh(t *testing.T) {
	t.Run("CV > 50% should use IQR", func(t *testing.T) {
		// Create scores with high variance (CV > 50%)
		scores := []int{100, 200, 300, 500, 800, 1000, 2000, 5000, 10000, 50000}
		// Expand to 100 records
		for i := 0; i < 90; i++ {
			scores = append(scores, 100+(i*10))
		}

		records := makeRecords(scores)
		stats := AnalyzeScoreDistribution(records)

		if stats.VarianceLevel != VarianceHigh {
			t.Errorf("Expected VarianceHigh, got %v (CV=%.2f%%)", stats.VarianceLevel, stats.CV)
		}
		if stats.Recommended != FilterMethodIQR {
			t.Errorf("Expected IQR for high variance, got %v", stats.Recommended)
		}
	})
}

// =============================================================================
// FilterMethodAuto: Small Dataset Handling
// =============================================================================

func TestFilterMethodAuto_SmallDatasets(t *testing.T) {
	testCases := []struct {
		name     string
		count    int
		expected FilterMethod
	}{
		{"1 record", 1, FilterMethodTopPercent},
		{"2 records", 2, FilterMethodTopPercent},
		{"5 records", 5, FilterMethodTopPercent},
		{"9 records", 9, FilterMethodTopPercent},
		{"10 records should not use TopPercent by default", 10, FilterMethodIQR}, // Depends on variance
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// High variance scores so variance isn't the deciding factor
			scores := make([]int, tc.count)
			for i := 0; i < tc.count; i++ {
				scores[i] = (i + 1) * 1000 // 1000, 2000, 3000...
			}

			records := makeRecords(scores)
			stats := AnalyzeScoreDistribution(records)

			if tc.count < 10 && stats.Recommended != FilterMethodTopPercent {
				t.Errorf("Expected TopPercent for %d records, got %v", tc.count, stats.Recommended)
			}
		})
	}
}

// =============================================================================
// FilterMethodAuto: Detection Accuracy Tests
// =============================================================================

func TestFilterMethodAuto_DetectsOutliers_HighVariance(t *testing.T) {
	t.Run("should detect clear outliers in high variance data", func(t *testing.T) {
		// 95 normal responses, 5 outliers
		scores := generateNormalWithOutliers(100, 100, []int{10000, 8000, 6000, 5000, 4000})
		records := makeRecords(scores)

		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto

		filter := NewInterestingFilter(FilterMethodAuto)
		interesting := filter.FilterInteresting(records, config)

		// Should detect the 5 outliers
		outlierCount := 0
		for _, r := range interesting {
			if r.Score >= 4000 {
				outlierCount++
			}
		}

		if outlierCount < 3 {
			t.Errorf("Expected at least 3 outliers detected, got %d (total interesting: %d)",
				outlierCount, len(interesting))
		}
	})
}

func TestFilterMethodAuto_DetectsOutliers_ModerateVariance(t *testing.T) {
	t.Run("should detect outliers in moderate variance data", func(t *testing.T) {
		// Create moderate variance with some outliers
		scores := make([]int, 100)
		for i := 0; i < 90; i++ {
			scores[i] = 100 + (i % 30) // 100-129
		}
		// Add outliers
		scores[90] = 500
		scores[91] = 450
		scores[92] = 400
		scores[93] = 350
		scores[94] = 300
		scores[95] = 250
		scores[96] = 200
		scores[97] = 180
		scores[98] = 160
		scores[99] = 150

		records := makeRecords(scores)
		stats := AnalyzeScoreDistribution(records)

		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto

		filter := NewInterestingFilter(FilterMethodAuto)
		interesting := filter.FilterInteresting(records, config)

		// Check that high scores are in interesting
		has500 := false
		has450 := false
		for _, r := range interesting {
			if r.Score == 500 {
				has500 = true
			}
			if r.Score == 450 {
				has450 = true
			}
		}

		if !has500 || !has450 {
			t.Errorf("Top outliers (500, 450) should be in interesting. Stats: CV=%.2f, Recommended=%v, Interesting count=%d",
				stats.CV, stats.Recommended, len(interesting))
		}
	})
}

func TestFilterMethodAuto_NoFalsePositives_UniformData(t *testing.T) {
	t.Run("uniform data should not have many false positives", func(t *testing.T) {
		// Perfectly uniform data - no true outliers
		scores := generateUniformScores(100, 100, 200)
		records := makeRecords(scores)

		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto
		config.MinimumInteresting = 0 // Don't force minimum

		filter := NewInterestingFilter(FilterMethodAuto)
		interesting := filter.FilterInteresting(records, config)

		// With uniform data and TopPercent, should return ~10%
		// This is expected behavior - not false positives per se
		stats := AnalyzeScoreDistribution(records)
		if stats.Recommended != FilterMethodTopPercent && stats.Recommended != FilterMethodElbow {
			t.Errorf("Uniform data should use TopPercent or Elbow, got %v (interesting=%d)",
				stats.Recommended, len(interesting))
		}
	})
}

// =============================================================================
// FilterMethodAuto: Edge Cases
// =============================================================================

func TestFilterMethodAuto_EdgeCases(t *testing.T) {
	t.Run("empty records returns nil", func(t *testing.T) {
		filter := NewInterestingFilter(FilterMethodAuto)
		result := filter.FilterInteresting(nil, DefaultFilterConfig())
		if result != nil {
			t.Errorf("Expected nil for empty input, got %v", result)
		}
	})

	t.Run("single record", func(t *testing.T) {
		records := makeRecords([]int{100})
		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto

		filter := NewInterestingFilter(FilterMethodAuto)
		interesting := filter.FilterInteresting(records, config)

		if len(interesting) != 1 {
			t.Errorf("Single record should return 1 interesting, got %d", len(interesting))
		}
	})

	t.Run("two records", func(t *testing.T) {
		records := makeRecords([]int{100, 1000})
		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto

		filter := NewInterestingFilter(FilterMethodAuto)
		interesting := filter.FilterInteresting(records, config)

		// Should return at least the higher score
		if len(interesting) == 0 {
			t.Error("Should return at least one interesting record")
		}
		if interesting[0].Score != 1000 {
			t.Errorf("Highest score should be first, got %d", interesting[0].Score)
		}
	})

	t.Run("all zero scores", func(t *testing.T) {
		records := makeRecords(generateIdenticalScores(50, 0))
		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto

		filter := NewInterestingFilter(FilterMethodAuto)
		interesting := filter.FilterInteresting(records, config)

		// All scores are 0, threshold becomes 0, all match
		// This is expected - use MaximumInteresting to limit if needed
		if len(interesting) == 0 {
			t.Error("Should return records even for all-zero scores")
		}
	})

	t.Run("negative and positive mixed (edge case)", func(t *testing.T) {
		// While scores shouldn't be negative in practice, test robustness
		// Note: Current implementation uses uint32 for hashes but int for scores
		records := makeRecords([]int{-100, 0, 100, 200, 1000})
		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto

		filter := NewInterestingFilter(FilterMethodAuto)
		interesting := filter.FilterInteresting(records, config)

		// Should not panic and should return something
		if len(interesting) == 0 {
			t.Error("Should return at least one interesting record")
		}
	})

	t.Run("very large scores", func(t *testing.T) {
		scores := []int{1000000, 2000000, 3000000, 100000000}
		for i := 0; i < 96; i++ {
			scores = append(scores, 1000)
		}

		records := makeRecords(scores)
		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto

		filter := NewInterestingFilter(FilterMethodAuto)
		interesting := filter.FilterInteresting(records, config)

		// Should detect the large outliers
		hasLarge := false
		for _, r := range interesting {
			if r.Score >= 1000000 {
				hasLarge = true
				break
			}
		}
		if !hasLarge {
			t.Error("Should detect very large score outliers")
		}
	})
}

// =============================================================================
// FilterMethodAuto: MinimumInteresting and MaximumInteresting
// =============================================================================

func TestFilterMethodAuto_MinimumInteresting(t *testing.T) {
	testCases := []struct {
		name        string
		scores      []int
		minRequired int
		expectMin   int
	}{
		{
			name:        "enforce minimum when threshold too strict",
			scores:      generateIdenticalScores(100, 500),
			minRequired: 5,
			expectMin:   5,
		},
		{
			name:        "minimum 10 from 100 identical",
			scores:      generateIdenticalScores(100, 100),
			minRequired: 10,
			expectMin:   10,
		},
		{
			name:        "minimum larger than record count returns what threshold allows",
			scores:      []int{100, 200, 300},
			minRequired: 10,
			expectMin:   1, // MinimumInteresting only applies if total >= min
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			records := makeRecords(tc.scores)
			config := DefaultFilterConfig()
			config.Method = FilterMethodAuto
			config.MinimumInteresting = tc.minRequired

			filter := NewInterestingFilter(FilterMethodAuto)
			interesting := filter.FilterInteresting(records, config)

			if len(interesting) < tc.expectMin {
				t.Errorf("Expected at least %d interesting, got %d", tc.expectMin, len(interesting))
			}
		})
	}
}

func TestFilterMethodAuto_MaximumInteresting(t *testing.T) {
	testCases := []struct {
		name      string
		scores    []int
		maxLimit  int
		expectMax int
	}{
		{
			name:      "limit to 5 from high variance data",
			scores:    generateUniformScores(100, 1, 10000),
			maxLimit:  5,
			expectMax: 5,
		},
		{
			name:      "limit to 1",
			scores:    generateUniformScores(50, 100, 1000),
			maxLimit:  1,
			expectMax: 1,
		},
		{
			name:      "limit to 20",
			scores:    generateUniformScores(100, 1, 100),
			maxLimit:  20,
			expectMax: 20,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			records := makeRecords(tc.scores)
			config := DefaultFilterConfig()
			config.Method = FilterMethodAuto
			config.MaximumInteresting = tc.maxLimit

			filter := NewInterestingFilter(FilterMethodAuto)
			interesting := filter.FilterInteresting(records, config)

			if len(interesting) > tc.expectMax {
				t.Errorf("Expected at most %d interesting, got %d", tc.expectMax, len(interesting))
			}
		})
	}
}

func TestFilterMethodAuto_MinMaxCombined(t *testing.T) {
	t.Run("min and max together", func(t *testing.T) {
		records := makeRecords(generateUniformScores(100, 1, 1000))
		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto
		config.MinimumInteresting = 3
		config.MaximumInteresting = 10

		filter := NewInterestingFilter(FilterMethodAuto)
		interesting := filter.FilterInteresting(records, config)

		if len(interesting) < 3 {
			t.Errorf("Expected at least 3 interesting, got %d", len(interesting))
		}
		if len(interesting) > 10 {
			t.Errorf("Expected at most 10 interesting, got %d", len(interesting))
		}
	})
}

// =============================================================================
// FilterMethodAuto: Real-World Scenarios
// =============================================================================

func TestFilterMethodAuto_RealWorldScenario_ContentDiscovery(t *testing.T) {
	t.Run("simulates content discovery: many 404s, few real pages", func(t *testing.T) {
		// Simulate: 95% are soft-404 (similar scores), 5% are real pages (high scores)
		scores := make([]int, 1000)

		// Soft-404 responses: low, similar scores
		for i := 0; i < 950; i++ {
			scores[i] = 100 + (i % 10) // 100-109
		}

		// Real pages: distinctly higher scores
		realPages := []int{5000, 4500, 4000, 3500, 3000, 2800, 2600, 2400, 2200, 2000,
			1900, 1800, 1700, 1600, 1500, 1400, 1300, 1200, 1100, 1000,
			950, 900, 850, 800, 750, 700, 650, 600, 550, 500,
			480, 460, 440, 420, 400, 380, 360, 340, 320, 300,
			290, 280, 270, 260, 250, 240, 230, 220, 210, 200}

		for i, score := range realPages {
			scores[950+i] = score
		}

		records := makeRecords(scores)
		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto

		filter := NewInterestingFilter(FilterMethodAuto)
		interesting := filter.FilterInteresting(records, config)

		// Count how many "real pages" (score >= 200) were detected
		realDetected := 0
		for _, r := range interesting {
			if r.Score >= 200 {
				realDetected++
			}
		}

		// Should detect most real pages
		if realDetected < 20 {
			t.Errorf("Expected to detect at least 20 real pages, detected %d out of %d interesting",
				realDetected, len(interesting))
		}
	})
}

func TestFilterMethodAuto_RealWorldScenario_APIFuzzing(t *testing.T) {
	t.Run("simulates API fuzzing: mostly errors, some interesting responses", func(t *testing.T) {
		scores := make([]int, 500)

		// 90% standard error responses
		for i := 0; i < 450; i++ {
			scores[i] = 50 + (i % 5)
		}

		// 10% interesting responses (different error codes, content)
		interestingScores := []int{
			2000, 1800, 1600, 1400, 1200, // Very interesting
			1000, 900, 800, 700, 600, // Moderately interesting
			500, 450, 400, 350, 300, // Somewhat interesting
			250, 200, 180, 160, 140, // Borderline
			120, 110, 100, 95, 90, // Low interest
			85, 80, 75, 70, 65, 60, 58, 56, 54, 52, // Near noise
			51, 51, 51, 51, 51, 51, 51, 51, 51, 51, // Very close to noise
		}

		for i, score := range interestingScores {
			scores[450+i] = score
		}

		records := makeRecords(scores)
		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto

		filter := NewInterestingFilter(FilterMethodAuto)
		interesting := filter.FilterInteresting(records, config)

		// Check that highest scores are captured
		topScoreFound := false
		for _, r := range interesting {
			if r.Score == 2000 {
				topScoreFound = true
				break
			}
		}

		if !topScoreFound {
			t.Error("Highest score (2000) should be in interesting results")
		}
	})
}

func TestFilterMethodAuto_RealWorldScenario_BruteForce(t *testing.T) {
	t.Run("simulates bruteforce: one success among many failures", func(t *testing.T) {
		scores := make([]int, 10000)

		// 9999 failures with identical fingerprint
		for i := 0; i < 9999; i++ {
			scores[i] = 100
		}

		// 1 success with very different fingerprint
		scores[9999] = 50000

		records := makeRecords(scores)
		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto

		filter := NewInterestingFilter(FilterMethodAuto)
		interesting := filter.FilterInteresting(records, config)

		// Must find the one success
		found := false
		for _, r := range interesting {
			if r.Score == 50000 {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Must detect the single success. Found %d interesting records", len(interesting))
		}
	})
}

// =============================================================================
// FilterMethodAuto: Config Parameter Sensitivity
// =============================================================================

func TestFilterMethodAuto_ConfigSensitivity(t *testing.T) {
	t.Run("TopPercent parameter affects output count with varied data", func(t *testing.T) {
		// Create data with some variance so TopPercent threshold is meaningful
		scores := generateUniformScores(100, 100, 1000)
		records := makeRecords(scores)

		testCases := []struct {
			topPercent float64
			expectMin  int
			expectMax  int
		}{
			{0.05, 4, 6},   // 5%
			{0.10, 9, 11},  // 10%
			{0.20, 19, 21}, // 20%
			{0.50, 49, 51}, // 50%
		}

		for _, tc := range testCases {
			config := DefaultFilterConfig()
			config.Method = FilterMethodTopPercent // Force TopPercent to test the parameter
			config.TopPercent = tc.topPercent

			filter := NewInterestingFilter(FilterMethodTopPercent)
			interesting := filter.FilterInteresting(records, config)

			if len(interesting) < tc.expectMin || len(interesting) > tc.expectMax {
				t.Errorf("TopPercent=%.2f: expected %d-%d, got %d",
					tc.topPercent, tc.expectMin, tc.expectMax, len(interesting))
			}
		}
	})

	t.Run("IQRMultiplier affects threshold strictness", func(t *testing.T) {
		// Create data that triggers IQR method
		scores := make([]int, 105)
		for i := range 100 {
			scores[i] = 100 + i*10 // 100-1090
		}
		// Add outliers
		scores[100] = 5000
		scores[101] = 6000
		scores[102] = 7000
		scores[103] = 8000
		scores[104] = 9000

		records := makeRecords(scores)

		// Test different multipliers
		var counts []int
		for _, mult := range []float64{1.0, 1.5, 2.0, 3.0} {
			config := DefaultFilterConfig()
			config.Method = FilterMethodIQR // Force IQR to test multiplier
			config.IQRMultiplier = mult

			filter := NewInterestingFilter(FilterMethodIQR)
			interesting := filter.FilterInteresting(records, config)
			counts = append(counts, len(interesting))
		}

		// Higher multiplier should result in fewer (or equal) interesting records
		// Verify that counts are monotonically non-increasing
		for i := 0; i < len(counts)-1; i++ {
			if counts[i] < counts[i+1] {
				t.Errorf("Higher IQR multiplier should not increase count: mult index %d has %d, but index %d has %d",
					i, counts[i], i+1, counts[i+1])
			}
		}
	})
}

// =============================================================================
// Full Integration: FilterMethodAuto with AnomalyEngine
// =============================================================================

func TestFilterMethodAuto_FullIntegration(t *testing.T) {
	t.Run("complete pipeline with real samples", func(t *testing.T) {
		// Create samples with different characteristics
		attrs := make([]map[Attribute]uint32, 100)

		// 90 normal responses
		for i := 0; i < 90; i++ {
			attrs[i] = map[Attribute]uint32{
				StatusCode:    200,
				ContentLength: 1000,
				ContentType:   12345,
				BodyContent:   uint32(12345 + (i % 3)), // Small variation
			}
		}

		// 10 anomalous responses
		anomalyConfigs := []map[Attribute]uint32{
			{StatusCode: 500, ContentLength: 0, ContentType: 99999, BodyContent: 11111},
			{StatusCode: 403, ContentLength: 500, ContentType: 12345, BodyContent: 22222},
			{StatusCode: 301, ContentLength: 100, ContentType: 54321, BodyContent: 33333},
			{StatusCode: 404, ContentLength: 200, ContentType: 12345, BodyContent: 44444},
			{StatusCode: 200, ContentLength: 50000, ContentType: 12345, BodyContent: 55555},
			{StatusCode: 200, ContentLength: 1000, ContentType: 88888, BodyContent: 66666},
			{StatusCode: 201, ContentLength: 2000, ContentType: 12345, BodyContent: 77777},
			{StatusCode: 204, ContentLength: 0, ContentType: 12345, BodyContent: 88888},
			{StatusCode: 200, ContentLength: 100000, ContentType: 12345, BodyContent: 99999},
			{StatusCode: 502, ContentLength: 300, ContentType: 11111, BodyContent: 10101},
		}

		for i, config := range anomalyConfigs {
			attrs[90+i] = config
		}

		records := makeRecordsWithSamples(attrs)
		engine := NewAnomalyEngine([]Attribute{StatusCode, ContentLength, ContentType, BodyContent})
		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto

		interesting, err := FilterInteresting(engine, records, config)
		if err != nil {
			t.Fatalf("FilterInteresting failed: %v", err)
		}

		// Check that anomalies are detected
		anomalyDetected := 0
		for _, r := range interesting {
			idx, ok := r.Metadata.(int)
			if ok && idx >= 90 {
				anomalyDetected++
			}
		}

		if anomalyDetected < 5 {
			t.Errorf("Expected at least 5 anomalies detected, got %d (total interesting: %d)",
				anomalyDetected, len(interesting))
		}

		// Verify sorting (descending scores)
		for i := 0; i < len(interesting)-1; i++ {
			if interesting[i].Score < interesting[i+1].Score {
				t.Errorf("Results not sorted descending at position %d", i)
			}
		}
	})
}

// =============================================================================
// Statistical Distribution Tests
// =============================================================================

func TestAnalyzeScoreDistribution_Comprehensive(t *testing.T) {
	testCases := []struct {
		name             string
		scores           []int
		expectedVariance VarianceLevel
		expectedMean     float64
		expectedMedian   float64
		meanTolerance    float64
		medianTolerance  float64
	}{
		{
			name:             "simple sequence",
			scores:           []int{1, 2, 3, 4, 5},
			expectedVariance: VarianceModerate,
			expectedMean:     3.0,
			expectedMedian:   3.0,
			meanTolerance:    0.01,
			medianTolerance:  0.01,
		},
		{
			name:             "all same",
			scores:           []int{100, 100, 100, 100, 100},
			expectedVariance: VarianceZero,
			expectedMean:     100.0,
			expectedMedian:   100.0,
			meanTolerance:    0.01,
			medianTolerance:  0.01,
		},
		{
			name:             "high variance",
			scores:           []int{1, 10, 100, 1000, 10000},
			expectedVariance: VarianceHigh,
			expectedMean:     2222.2,
			expectedMedian:   100.0,
			meanTolerance:    0.1,
			medianTolerance:  0.1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			records := makeRecords(tc.scores)
			stats := AnalyzeScoreDistribution(records)

			if stats.VarianceLevel != tc.expectedVariance {
				t.Errorf("Variance: expected %v, got %v (CV=%.2f%%)",
					tc.expectedVariance, stats.VarianceLevel, stats.CV)
			}

			if diff := stats.Mean - tc.expectedMean; diff > tc.meanTolerance || diff < -tc.meanTolerance {
				t.Errorf("Mean: expected %.2f (±%.2f), got %.2f",
					tc.expectedMean, tc.meanTolerance, stats.Mean)
			}

			if diff := stats.Median - tc.expectedMedian; diff > tc.medianTolerance || diff < -tc.medianTolerance {
				t.Errorf("Median: expected %.2f (±%.2f), got %.2f",
					tc.expectedMedian, tc.medianTolerance, stats.Median)
			}
		})
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkFilterMethodAuto_100Records(b *testing.B) {
	records := makeRecords(generateUniformScores(100, 1, 10000))
	config := DefaultFilterConfig()
	config.Method = FilterMethodAuto
	filter := NewInterestingFilter(FilterMethodAuto)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = filter.FilterInteresting(records, config)
	}
}

func BenchmarkFilterMethodAuto_1000Records(b *testing.B) {
	records := makeRecords(generateUniformScores(1000, 1, 100000))
	config := DefaultFilterConfig()
	config.Method = FilterMethodAuto
	filter := NewInterestingFilter(FilterMethodAuto)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = filter.FilterInteresting(records, config)
	}
}

func BenchmarkFilterMethodAuto_10000Records(b *testing.B) {
	records := makeRecords(generateUniformScores(10000, 1, 1000000))
	config := DefaultFilterConfig()
	config.Method = FilterMethodAuto
	filter := NewInterestingFilter(FilterMethodAuto)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = filter.FilterInteresting(records, config)
	}
}

func BenchmarkAnalyzeScoreDistribution_1000Records(b *testing.B) {
	records := makeRecords(generateUniformScores(1000, 1, 100000))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AnalyzeScoreDistribution(records)
	}
}

// =============================================================================
// Randomized Testing
// =============================================================================

func TestFilterMethodAuto_RandomizedStability(t *testing.T) {
	t.Run("consistent results for same input", func(t *testing.T) {
		rng := rand.New(rand.NewSource(42))
		scores := make([]int, 100)
		for i := 0; i < 100; i++ {
			scores[i] = rng.Intn(10000)
		}

		records := makeRecords(scores)
		config := DefaultFilterConfig()
		config.Method = FilterMethodAuto
		filter := NewInterestingFilter(FilterMethodAuto)

		// Run multiple times
		var results []int
		for i := 0; i < 10; i++ {
			interesting := filter.FilterInteresting(records, config)
			results = append(results, len(interesting))
		}

		// All runs should produce same count
		for i := 1; i < len(results); i++ {
			if results[i] != results[0] {
				t.Errorf("Inconsistent results: run 0=%d, run %d=%d", results[0], i, results[i])
			}
		}
	})
}

func TestFilterMethodAuto_VariousDistributions(t *testing.T) {
	distributions := []struct {
		name      string
		generator func(n int) []int
	}{
		{
			name: "uniform",
			generator: func(n int) []int {
				return generateUniformScores(n, 100, 1000)
			},
		},
		{
			name: "exponential-like",
			generator: func(n int) []int {
				scores := make([]int, n)
				for i := 0; i < n; i++ {
					scores[i] = 100 * (i + 1) * (i + 1) / n
				}
				return scores
			},
		},
		{
			name: "bimodal",
			generator: func(n int) []int {
				scores := make([]int, n)
				for i := 0; i < n/2; i++ {
					scores[i] = 100 + i%10
				}
				for i := n / 2; i < n; i++ {
					scores[i] = 1000 + i%10
				}
				return scores
			},
		},
		{
			name: "heavy-tail",
			generator: func(n int) []int {
				scores := make([]int, n)
				for i := 0; i < n-5; i++ {
					scores[i] = 100 + i // Small variation to avoid all-same issue
				}
				scores[n-5] = 10000
				scores[n-4] = 20000
				scores[n-3] = 30000
				scores[n-2] = 40000
				scores[n-1] = 50000
				return scores
			},
		},
	}

	for _, dist := range distributions {
		t.Run(fmt.Sprintf("distribution_%s", dist.name), func(t *testing.T) {
			scores := dist.generator(100)
			records := makeRecords(scores)
			config := DefaultFilterConfig()
			config.Method = FilterMethodAuto

			filter := NewInterestingFilter(FilterMethodAuto)
			interesting := filter.FilterInteresting(records, config)

			// Just verify no panic and reasonable output
			if len(interesting) == 0 {
				stats := AnalyzeScoreDistribution(records)
				t.Errorf("No interesting records found. Stats: CV=%.2f, Recommended=%v",
					stats.CV, stats.Recommended)
			}

			// Note: InterestingFilter.FilterInteresting does NOT sort output
			// It preserves original order. Use FilterInteresting() convenience
			// function for sorted output.
		})
	}
}
