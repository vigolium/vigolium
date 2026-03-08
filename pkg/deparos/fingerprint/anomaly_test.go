package fingerprint

import (
	"testing"
)

// createTestSample creates a sample with specific attribute values for testing.
func createTestSample(attrs map[Attribute]uint32) *Sample {
	return &Sample{
		attributes: attrs,
		debug:      "test sample",
	}
}

func TestValueCounter(t *testing.T) {
	t.Run("Record returns true for novel values", func(t *testing.T) {
		vc := NewValueCounter()

		if !vc.Record(100) {
			t.Error("First occurrence should return true (novel)")
		}
		if vc.Record(100) {
			t.Error("Second occurrence should return false (not novel)")
		}
		if !vc.Record(200) {
			t.Error("Different value should return true (novel)")
		}
	})

	t.Run("GetFrequency returns correct count", func(t *testing.T) {
		vc := NewValueCounter()

		vc.Record(100)
		vc.Record(100)
		vc.Record(100)

		if got := vc.GetFrequency(100); got != 3 {
			t.Errorf("GetFrequency() = %d, want 3", got)
		}
		if got := vc.GetFrequency(999); got != 0 {
			t.Errorf("GetFrequency(unknown) = %d, want 0", got)
		}
	})

	t.Run("UniqueCount returns correct count", func(t *testing.T) {
		vc := NewValueCounter()

		vc.Record(100)
		vc.Record(100)
		vc.Record(200)
		vc.Record(300)

		if got := vc.UniqueCount(); got != 3 {
			t.Errorf("UniqueCount() = %d, want 3", got)
		}
	})
}

func TestAttributeFrequencyTracker(t *testing.T) {
	t.Run("RecordValue tracks across attributes", func(t *testing.T) {
		tracker := NewAttributeFrequencyTracker()

		if !tracker.RecordValue(StatusCode, 200) {
			t.Error("First StatusCode 200 should be novel")
		}
		if tracker.RecordValue(StatusCode, 200) {
			t.Error("Second StatusCode 200 should not be novel")
		}
		if !tracker.RecordValue(StatusCode, 404) {
			t.Error("StatusCode 404 should be novel")
		}
		if !tracker.RecordValue(ContentType, 12345) {
			t.Error("First ContentType should be novel")
		}
	})

	t.Run("GetVariantAttributes returns only multi-value attributes", func(t *testing.T) {
		tracker := NewAttributeFrequencyTracker()

		// StatusCode has 2 unique values
		tracker.RecordValue(StatusCode, 200)
		tracker.RecordValue(StatusCode, 404)

		// ContentType has only 1 unique value
		tracker.RecordValue(ContentType, 12345)
		tracker.RecordValue(ContentType, 12345)

		variants := tracker.GetVariantAttributes()
		if len(variants) != 1 {
			t.Errorf("Expected 1 variant attribute, got %d", len(variants))
		}
		if len(variants) > 0 && variants[0] != StatusCode {
			t.Errorf("Expected StatusCode to be variant, got %v", variants[0])
		}
	})

	t.Run("IsVariant correctly identifies variant attributes", func(t *testing.T) {
		tracker := NewAttributeFrequencyTracker()

		tracker.RecordValue(StatusCode, 200)
		tracker.RecordValue(StatusCode, 404)
		tracker.RecordValue(ContentType, 12345)

		if !tracker.IsVariant(StatusCode) {
			t.Error("StatusCode should be variant (2 unique values)")
		}
		if tracker.IsVariant(ContentType) {
			t.Error("ContentType should not be variant (1 unique value)")
		}
		if tracker.IsVariant(BodyContent) {
			t.Error("BodyContent should not be variant (0 values)")
		}
	})
}

func TestAttributeWeightManager(t *testing.T) {
	t.Run("Initial weights are 1.0", func(t *testing.T) {
		awm := NewAttributeWeightManager([]Attribute{StatusCode, ContentType})

		if got := awm.GetWeight(StatusCode); got != 1.0 {
			t.Errorf("Initial weight = %f, want 1.0", got)
		}
	})

	t.Run("DegradeWeight reduces by 0.9", func(t *testing.T) {
		awm := NewAttributeWeightManager([]Attribute{StatusCode})

		awm.DegradeWeight(StatusCode)
		if got := awm.GetWeight(StatusCode); got != 0.9 {
			t.Errorf("After 1 degradation = %f, want 0.9", got)
		}

		awm.DegradeWeight(StatusCode)
		expected := 0.81 // 0.9 * 0.9
		if got := awm.GetWeight(StatusCode); !floatEquals(got, expected) {
			t.Errorf("After 2 degradations = %f, want %f", got, expected)
		}
	})

	t.Run("ResetWeight restores to 1.0", func(t *testing.T) {
		awm := NewAttributeWeightManager([]Attribute{StatusCode})

		awm.DegradeWeight(StatusCode)
		awm.DegradeWeight(StatusCode)
		awm.ResetWeight(StatusCode)

		if got := awm.GetWeight(StatusCode); got != 1.0 {
			t.Errorf("After reset = %f, want 1.0", got)
		}
	})

	t.Run("ResetAll restores all weights", func(t *testing.T) {
		awm := NewAttributeWeightManager([]Attribute{StatusCode, ContentType})

		awm.DegradeWeight(StatusCode)
		awm.DegradeWeight(ContentType)
		awm.ResetAll()

		if got := awm.GetWeight(StatusCode); got != 1.0 {
			t.Errorf("StatusCode after ResetAll = %f, want 1.0", got)
		}
		if got := awm.GetWeight(ContentType); got != 1.0 {
			t.Errorf("ContentType after ResetAll = %f, want 1.0", got)
		}
	})
}

func TestAnomalyScoreCalculator(t *testing.T) {
	t.Run("CalculateScore returns higher for rare values", func(t *testing.T) {
		tracker := NewAttributeFrequencyTracker()
		weights := NewAttributeWeightManager([]Attribute{StatusCode})

		// 9 responses with 200, 1 with 404
		for i := 0; i < 9; i++ {
			tracker.RecordValue(StatusCode, 200)
		}
		tracker.RecordValue(StatusCode, 404)

		variants := tracker.GetVariantAttributes()
		calc := NewAnomalyScoreCalculator(tracker, weights, variants)

		// Create samples
		common := createTestSample(map[Attribute]uint32{StatusCode: 200})
		rare := createTestSample(map[Attribute]uint32{StatusCode: 404})

		commonScore, err := calc.CalculateScore(common)
		if err != nil {
			t.Fatalf("CalculateScore error: %v", err)
		}

		rareScore, err := calc.CalculateScore(rare)
		if err != nil {
			t.Fatalf("CalculateScore error: %v", err)
		}

		if rareScore <= commonScore {
			t.Errorf("Rare score (%d) should be higher than common score (%d)", rareScore, commonScore)
		}
	})

	t.Run("CalculateScore handles nil sample", func(t *testing.T) {
		tracker := NewAttributeFrequencyTracker()
		weights := NewAttributeWeightManager([]Attribute{StatusCode})
		calc := NewAnomalyScoreCalculator(tracker, weights, nil)

		_, err := calc.CalculateScore(nil)
		if err != ErrNilSample {
			t.Errorf("Expected ErrNilSample, got %v", err)
		}
	})
}

func TestAnomalyEngine(t *testing.T) {
	t.Run("Rank scores responses correctly", func(t *testing.T) {
		engine := NewAnomalyEngine([]Attribute{StatusCode, ContentLength})

		records := []*ResponseRecord{
			{Sample: createTestSample(map[Attribute]uint32{StatusCode: 200, ContentLength: 1000})},
			{Sample: createTestSample(map[Attribute]uint32{StatusCode: 200, ContentLength: 1000})},
			{Sample: createTestSample(map[Attribute]uint32{StatusCode: 200, ContentLength: 1000})},
			{Sample: createTestSample(map[Attribute]uint32{StatusCode: 500, ContentLength: 500})}, // Anomaly
		}

		if err := engine.Rank(records); err != nil {
			t.Fatalf("Rank error: %v", err)
		}

		// The 500 response should have the highest score
		if records[3].Score <= records[0].Score {
			t.Error("Anomalous record should have higher score")
		}
	})

	t.Run("RankAndSort orders by score descending", func(t *testing.T) {
		engine := NewAnomalyEngine([]Attribute{StatusCode})

		records := []*ResponseRecord{
			{Sample: createTestSample(map[Attribute]uint32{StatusCode: 200}), Metadata: "common1"},
			{Sample: createTestSample(map[Attribute]uint32{StatusCode: 200}), Metadata: "common2"},
			{Sample: createTestSample(map[Attribute]uint32{StatusCode: 200}), Metadata: "common3"},
			{Sample: createTestSample(map[Attribute]uint32{StatusCode: 404}), Metadata: "rare"},
		}

		if err := engine.RankAndSort(records); err != nil {
			t.Fatalf("RankAndSort error: %v", err)
		}

		// First record should be the rare one
		if records[0].Metadata != "rare" {
			t.Errorf("First record should be 'rare', got '%v'", records[0].Metadata)
		}

		// Verify descending order
		for i := 0; i < len(records)-1; i++ {
			if records[i].Score < records[i+1].Score {
				t.Errorf("Records not sorted descending at index %d: %d < %d", i, records[i].Score, records[i+1].Score)
			}
		}
	})

	t.Run("Rank handles empty records", func(t *testing.T) {
		engine := NewDefaultAnomalyEngine()

		if err := engine.Rank(nil); err != nil {
			t.Errorf("Rank(nil) should not error: %v", err)
		}
		if err := engine.Rank([]*ResponseRecord{}); err != nil {
			t.Errorf("Rank([]) should not error: %v", err)
		}
	})

	t.Run("Rank handles nil samples gracefully", func(t *testing.T) {
		engine := NewDefaultAnomalyEngine()

		records := []*ResponseRecord{
			{Sample: nil},
			{Sample: createTestSample(map[Attribute]uint32{StatusCode: 200})},
		}

		if err := engine.Rank(records); err != nil {
			t.Errorf("Rank should handle nil samples: %v", err)
		}

		if records[0].Score != 0 {
			t.Errorf("Nil sample should have score 0, got %d", records[0].Score)
		}
	})
}

func TestDistributionStats(t *testing.T) {
	t.Run("AnalyzeScoreDistribution calculates correctly", func(t *testing.T) {
		records := []*ResponseRecord{
			{Score: 100},
			{Score: 200},
			{Score: 300},
			{Score: 400},
			{Score: 500},
		}

		stats := AnalyzeScoreDistribution(records)

		if stats.Total != 5 {
			t.Errorf("Total = %d, want 5", stats.Total)
		}
		if stats.Min != 100 {
			t.Errorf("Min = %d, want 100", stats.Min)
		}
		if stats.Max != 500 {
			t.Errorf("Max = %d, want 500", stats.Max)
		}
		if stats.Mean != 300 {
			t.Errorf("Mean = %f, want 300", stats.Mean)
		}
		if stats.Median != 300 {
			t.Errorf("Median = %f, want 300", stats.Median)
		}
	})

	t.Run("AnalyzeScoreDistribution handles empty input", func(t *testing.T) {
		stats := AnalyzeScoreDistribution(nil)

		if stats.Total != 0 {
			t.Errorf("Empty input should have Total=0, got %d", stats.Total)
		}
	})

	t.Run("Variance levels are categorized correctly", func(t *testing.T) {
		tests := []struct {
			cv       float64
			expected VarianceLevel
		}{
			{0, VarianceZero},
			{5, VarianceVeryLow},
			{15, VarianceLow},
			{35, VarianceModerate},
			{60, VarianceHigh},
		}

		for _, tt := range tests {
			got := categorizeVariance(tt.cv)
			if got != tt.expected {
				t.Errorf("categorizeVariance(%f) = %v, want %v", tt.cv, got, tt.expected)
			}
		}
	})
}

func TestInterestingFilter(t *testing.T) {
	t.Run("FilterInteresting with TopPercent", func(t *testing.T) {
		records := make([]*ResponseRecord, 100)
		for i := 0; i < 100; i++ {
			records[i] = &ResponseRecord{Score: i}
		}

		filter := NewInterestingFilter(FilterMethodTopPercent)
		config := FilterConfig{
			Method:     FilterMethodTopPercent,
			TopPercent: 0.1, // Top 10%
		}

		interesting := filter.FilterInteresting(records, config)

		if len(interesting) != 10 {
			t.Errorf("Expected 10 interesting records (10%%), got %d", len(interesting))
		}
	})

	t.Run("FilterInteresting respects MinimumInteresting", func(t *testing.T) {
		records := []*ResponseRecord{
			{Score: 100},
			{Score: 100},
			{Score: 100},
		}

		filter := NewInterestingFilter(FilterMethodIQR)
		config := FilterConfig{
			Method:             FilterMethodIQR,
			IQRMultiplier:      1.5,
			MinimumInteresting: 2,
		}

		interesting := filter.FilterInteresting(records, config)

		if len(interesting) < 2 {
			t.Errorf("Should return at least 2 records (MinimumInteresting), got %d", len(interesting))
		}
	})

	t.Run("FilterInteresting respects MaximumInteresting", func(t *testing.T) {
		records := make([]*ResponseRecord, 100)
		for i := 0; i < 100; i++ {
			records[i] = &ResponseRecord{Score: 1000 - i}
		}

		filter := NewInterestingFilter(FilterMethodTopPercent)
		config := FilterConfig{
			Method:             FilterMethodTopPercent,
			TopPercent:         0.5, // Would be 50 records
			MaximumInteresting: 5,   // But limit to 5
		}

		interesting := filter.FilterInteresting(records, config)

		if len(interesting) > 5 {
			t.Errorf("Should return at most 5 records (MaximumInteresting), got %d", len(interesting))
		}
	})
}

func TestFilterMethodSelection(t *testing.T) {
	t.Run("Auto method selects based on variance", func(t *testing.T) {
		// High variance dataset - should recommend IQR
		highVariance := []*ResponseRecord{
			{Score: 100},
			{Score: 200},
			{Score: 300},
			{Score: 1000},
			{Score: 2000},
			{Score: 3000},
			{Score: 10000},
			{Score: 20000},
			{Score: 30000},
			{Score: 100000},
		}

		stats := AnalyzeScoreDistribution(highVariance)

		if stats.VarianceLevel != VarianceHigh {
			t.Errorf("Expected VarianceHigh, got %v", stats.VarianceLevel)
		}
		if stats.Recommended != FilterMethodIQR {
			t.Errorf("Expected FilterMethodIQR for high variance, got %v", stats.Recommended)
		}
	})
}

func TestElbowDetection(t *testing.T) {
	t.Run("Elbow detection finds sharp dropoff", func(t *testing.T) {
		// Scores with clear elbow at 500
		scores := []int{1000, 950, 900, 850, 500, 100, 50, 10}

		threshold := calculateElbowThreshold(scores, 0.3)

		// Should identify the drop from 850 to 500 (41% drop)
		if threshold < 100 || threshold > 500 {
			t.Errorf("Elbow threshold = %f, expected around 100-500", threshold)
		}
	})
}

func TestPercentile(t *testing.T) {
	t.Run("Percentile calculations are correct", func(t *testing.T) {
		sorted := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

		q1 := percentile(sorted, 0.25)
		median := percentile(sorted, 0.5)
		q3 := percentile(sorted, 0.75)

		// Q1 should be around 3.25
		if q1 < 2.5 || q1 > 3.5 {
			t.Errorf("Q1 = %f, expected around 3.25", q1)
		}

		// Median should be 5.5
		if median < 5.0 || median > 6.0 {
			t.Errorf("Median = %f, expected 5.5", median)
		}

		// Q3 should be around 7.75
		if q3 < 7.5 || q3 > 8.5 {
			t.Errorf("Q3 = %f, expected around 7.75", q3)
		}
	})
}

func TestIntegration(t *testing.T) {
	t.Run("Full workflow: create records, rank, filter", func(t *testing.T) {
		// Simulate 100 responses: 95 normal (200/1000), 5 anomalous
		records := make([]*ResponseRecord, 100)

		// Normal responses
		for i := 0; i < 95; i++ {
			records[i] = &ResponseRecord{
				Sample: createTestSample(map[Attribute]uint32{
					StatusCode:    200,
					ContentLength: 1000,
					ContentType:   12345,
				}),
				Metadata: i,
			}
		}

		// Anomalous responses
		anomalyConfigs := []map[Attribute]uint32{
			{StatusCode: 500, ContentLength: 0, ContentType: 99999},
			{StatusCode: 403, ContentLength: 500, ContentType: 12345},
			{StatusCode: 301, ContentLength: 100, ContentType: 54321},
			{StatusCode: 404, ContentLength: 200, ContentType: 12345},
			{StatusCode: 200, ContentLength: 50000, ContentType: 12345}, // Unusual size
		}

		for i, config := range anomalyConfigs {
			records[95+i] = &ResponseRecord{
				Sample:   createTestSample(config),
				Metadata: 95 + i,
			}
		}

		engine := NewAnomalyEngine([]Attribute{StatusCode, ContentLength, ContentType})
		config := DefaultFilterConfig()
		config.MinimumInteresting = 3
		config.MaximumInteresting = 10

		interesting, err := FilterInteresting(engine, records, config)
		if err != nil {
			t.Fatalf("FilterInteresting error: %v", err)
		}

		if len(interesting) < 3 {
			t.Errorf("Expected at least 3 interesting records, got %d", len(interesting))
		}

		// Verify interesting records are sorted by score descending
		for i := 0; i < len(interesting)-1; i++ {
			if interesting[i].Score < interesting[i+1].Score {
				t.Errorf("Interesting records not sorted descending at index %d", i)
			}
		}

		// The anomalous records should appear in interesting
		anomalyFound := 0
		for _, r := range interesting {
			idx, ok := r.Metadata.(int)
			if ok && idx >= 95 {
				anomalyFound++
			}
		}

		if anomalyFound == 0 {
			t.Error("None of the anomalous records were detected as interesting")
		}
	})
}

// floatEquals compares floats with tolerance.
func floatEquals(a, b float64) bool {
	const epsilon = 0.0001
	return (a-b) < epsilon && (b-a) < epsilon
}

func BenchmarkRank100(b *testing.B) {
	engine := NewDefaultAnomalyEngine()
	records := make([]*ResponseRecord, 100)
	for i := 0; i < 100; i++ {
		records[i] = &ResponseRecord{
			Sample: createTestSample(map[Attribute]uint32{
				StatusCode:    uint32(200 + (i % 5)),
				ContentLength: uint32(1000 + i*10),
				ContentType:   uint32(i % 3),
			}),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Rank(records)
	}
}

func BenchmarkRankAndSort1000(b *testing.B) {
	engine := NewDefaultAnomalyEngine()
	records := make([]*ResponseRecord, 1000)
	for i := 0; i < 1000; i++ {
		records[i] = &ResponseRecord{
			Sample: createTestSample(map[Attribute]uint32{
				StatusCode:    uint32(200 + (i % 10)),
				ContentLength: uint32(1000 + i*10),
				ContentType:   uint32(i % 5),
				BodyContent:   uint32(i % 100),
			}),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.RankAndSort(records)
	}
}
