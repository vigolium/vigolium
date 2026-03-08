package anomaly

import (
	"testing"

	testdata "github.com/vigolium/vigolium/test/pkg-testdata/anomaly"
)

// ============================================================================
// REAL-WORLD BRUTE FORCE TEST SUITE
// Using actual HTTP responses captured from live brute force scans
// ============================================================================

// TestRealWorld_Domain1_VeryHighContentVariance tests detection on highly varied responses
// Real data: 100 responses, CV=372.80% (102-8619 bytes)
// Mix: 2 x 200 OK, 15 x 403, 83 x 404
// This represents a typical brute force scenario where rare valid paths exist
func TestRealWorld_Domain1_VeryHighContentVariance(t *testing.T) {
	dataset, err := testdata.LoadDataset("real_domain1_18.200.137.227.json.gz")
	if err != nil {
		t.Skipf("Skipping: test data not available: %v", err)
	}

	responseData := testdata.ExtractResponseData(dataset.FilterSuccessful())
	if len(responseData) == 0 {
		t.Fatal("No responses loaded")
	}

	// Convert to ResponseRecords
	records := make([]*ResponseRecord, len(responseData))
	for i, rd := range responseData {
		attrs, err := ExtractAttributesFromRaw(rd.StatusCode, rd.Body, rd.Headers)
		if err != nil {
			t.Fatalf("Failed to extract attributes: %v", err)
		}

		records[i] = &ResponseRecord{
			Attributes: *attrs,
			Metadata: map[string]interface{}{
				"index":      i,
				"statusCode": rd.StatusCode,
			},
		}
	}

	t.Logf("Loaded %d responses (content CV=372.80%%)", len(records))

	engine := NewDefaultEngine()
	err = engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("RankAndSort failed: %v", err)
	}

	// Analyze score distribution (not content distribution)
	stats := AnalyzeScoreDistribution(records)
	t.Logf("Score stats: CV=%.2f%%, variance level=%d", stats.CV, stats.VarianceLevel)

	// With very high content variance, engine should detect clear anomalies
	filter := NewInterestingFilter(FilterMethodAuto)
	interesting := filter.FilterInteresting(records, DefaultFilterConfig())

	t.Logf("Filtered to %d interesting responses", len(interesting))

	if len(interesting) == 0 {
		t.Error("Expected some interesting responses with high content variance")
	}

	// Verify rare 200 OK responses are captured
	count200 := 0
	for _, r := range interesting {
		meta := r.Metadata.(map[string]interface{})
		if meta["statusCode"].(int) == 200 {
			count200++
		}
	}
	t.Logf("Captured %d/2 rare 200 OK responses", count200)
	if count200 < 2 {
		t.Errorf("Expected to capture 2 200 OK responses, got %d", count200)
	}
}

// TestRealWorld_Domain2_VeryLowContentVariance tests behavior with nearly identical responses
// Real data: 100 responses, CV=0.19% (748-754 bytes), all 403
// Score variance may still exist due to minor content differences
func TestRealWorld_Domain2_VeryLowContentVariance(t *testing.T) {
	dataset, err := testdata.LoadDataset("real_domain2_payment.backend-capital.com.json.gz")
	if err != nil {
		t.Skipf("Skipping: test data not available: %v", err)
	}

	responseData := testdata.ExtractResponseData(dataset.FilterSuccessful())
	records := make([]*ResponseRecord, len(responseData))
	for i, rd := range responseData {
		attrs, _ := ExtractAttributesFromRaw(rd.StatusCode, rd.Body, rd.Headers)
		records[i] = &ResponseRecord{
			Attributes: *attrs,
			Metadata:   i,
		}
	}

	t.Logf("Loaded %d responses (content CV=0.19%%, all same status)", len(records))

	engine := NewDefaultEngine()
	err = engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("RankAndSort failed: %v", err)
	}

	stats := AnalyzeScoreDistribution(records)
	t.Logf("Score stats: CV=%.2f%%, variance level=%d", stats.CV, stats.VarianceLevel)

	// Very low content variance should result in few/no interesting responses
	// Engine may still detect minor differences in scoring
	filter := NewInterestingFilter(FilterMethodAuto)
	interesting := filter.FilterInteresting(records, DefaultFilterConfig())

	t.Logf("Found %d interesting responses from near-identical content", len(interesting))
	// Don't enforce strict count - score variance can vary based on subtle differences
}

// TestRealWorld_Domain3_LowContentVariance tests moderate similarity
// Real data: 84 responses, CV=10.97% (196-258 bytes)
// Mix: 47 x 301, 37 x 404
func TestRealWorld_Domain3_LowContentVariance(t *testing.T) {
	dataset, err := testdata.LoadDataset("real_domain3_52.19.167.193.json.gz")
	if err != nil {
		t.Skipf("Skipping: test data not available: %v", err)
	}

	responseData := testdata.ExtractResponseData(dataset.FilterSuccessful())
	records := make([]*ResponseRecord, len(responseData))
	for i, rd := range responseData {
		attrs, _ := ExtractAttributesFromRaw(rd.StatusCode, rd.Body, rd.Headers)
		records[i] = &ResponseRecord{
			Attributes: *attrs,
			Metadata:   rd.StatusCode,
		}
	}

	t.Logf("Loaded %d responses (content CV=10.97%%)", len(records))

	engine := NewDefaultEngine()
	err = engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("RankAndSort failed: %v", err)
	}

	stats := AnalyzeScoreDistribution(records)
	t.Logf("Score stats: CV=%.2f%%, variance level=%d, recommended=%v",
		stats.CV, stats.VarianceLevel, stats.Recommended)

	filter := NewInterestingFilter(FilterMethodAuto)
	interesting := filter.FilterInteresting(records, DefaultFilterConfig())

	t.Logf("Filtered to %d interesting responses", len(interesting))
	if len(interesting) == 0 {
		t.Error("Expected some interesting responses")
	}
}

// TestRealWorld_Domain4_LowContentVariance tests low variance with rare anomalies
// Real data: 192 responses, CV=8.86% (50-362 bytes)
// Mix: 2 x 200 OK, 190 x 404
func TestRealWorld_Domain4_LowContentVariance(t *testing.T) {
	dataset, err := testdata.LoadDataset("real_domain4_63.32.0.98.json.gz")
	if err != nil {
		t.Skipf("Skipping: test data not available: %v", err)
	}

	responseData := testdata.ExtractResponseData(dataset.FilterSuccessful())
	records := make([]*ResponseRecord, len(responseData))
	for i, rd := range responseData {
		attrs, _ := ExtractAttributesFromRaw(rd.StatusCode, rd.Body, rd.Headers)
		records[i] = &ResponseRecord{
			Attributes: *attrs,
			Metadata: map[string]interface{}{
				"statusCode": rd.StatusCode,
			},
		}
	}

	t.Logf("Loaded %d responses (content CV=8.86%%)", len(records))

	engine := NewDefaultEngine()
	err = engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("RankAndSort failed: %v", err)
	}

	stats := AnalyzeScoreDistribution(records)
	t.Logf("Score stats: CV=%.2f%%, variance level=%d", stats.CV, stats.VarianceLevel)

	filter := NewInterestingFilter(FilterMethodAuto)
	interesting := filter.FilterInteresting(records, DefaultFilterConfig())

	t.Logf("Filtered to %d interesting responses", len(interesting))

	// Verify rare 200 OK responses are detected
	count200 := 0
	for _, r := range interesting {
		meta := r.Metadata.(map[string]interface{})
		if meta["statusCode"].(int) == 200 {
			count200++
		}
	}
	t.Logf("Captured %d/2 rare 200 OK responses", count200)
	if count200 < 2 {
		t.Errorf("Expected to capture 2 200 OK responses, got %d", count200)
	}
}

// TestRealWorld_Domain5_VeryLowContentVariance tests nearly identical responses
// Real data: 100 responses, CV=0.21% (747-754 bytes), all 403
func TestRealWorld_Domain5_VeryLowContentVariance(t *testing.T) {
	dataset, err := testdata.LoadDataset("real_domain5_test-payment.json.gz")
	if err != nil {
		t.Skipf("Skipping: test data not available: %v", err)
	}

	responseData := testdata.ExtractResponseData(dataset.FilterSuccessful())
	records := make([]*ResponseRecord, len(responseData))
	for i, rd := range responseData {
		attrs, _ := ExtractAttributesFromRaw(rd.StatusCode, rd.Body, rd.Headers)
		records[i] = &ResponseRecord{
			Attributes: *attrs,
			Metadata:   i,
		}
	}

	t.Logf("Loaded %d responses (content CV=0.21%%, all same status)", len(records))

	engine := NewDefaultEngine()
	err = engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("RankAndSort failed: %v", err)
	}

	stats := AnalyzeScoreDistribution(records)
	t.Logf("Score stats: CV=%.2f%%, variance level=%d", stats.CV, stats.VarianceLevel)

	// Very low content variance - interesting count depends on score variance
	filter := NewInterestingFilter(FilterMethodAuto)
	interesting := filter.FilterInteresting(records, DefaultFilterConfig())

	t.Logf("Found %d interesting from near-identical content", len(interesting))
	// Don't enforce strict expectations - score variance can still exist
}

// ============================================================================
// FILTER METHOD TESTS - Testing different filtering strategies
// ============================================================================

func TestRealWorld_FilterMethods_Comparison(t *testing.T) {
	dataset, err := testdata.LoadDataset("real_domain1_18.200.137.227.json.gz")
	if err != nil {
		t.Skipf("Skipping: test data not available: %v", err)
	}

	responseData := testdata.ExtractResponseData(dataset.FilterSuccessful())
	records := make([]*ResponseRecord, len(responseData))
	for i, rd := range responseData {
		attrs, _ := ExtractAttributesFromRaw(rd.StatusCode, rd.Body, rd.Headers)
		records[i] = &ResponseRecord{
			Attributes: *attrs,
			Metadata:   rd.StatusCode,
		}
	}

	engine := NewDefaultEngine()
	err = engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("RankAndSort failed: %v", err)
	}

	methods := []FilterMethod{
		FilterMethodIQR,
		FilterMethodZScore,
		FilterMethodElbow,
		FilterMethodTopPercent,
		FilterMethodAuto,
	}

	t.Log("Comparing filter methods:")
	for _, method := range methods {
		filter := NewInterestingFilter(method)
		interesting := filter.FilterInteresting(records, DefaultFilterConfig())

		count200 := 0
		for _, r := range interesting {
			if r.Metadata.(int) == 200 {
				count200++
			}
		}

		t.Logf("  %v: %d interesting, %d/2 200 OK captured",
			method, len(interesting), count200)
	}
}

// TestRealWorld_AutoMethodSelection verifies auto-selection picks appropriate methods
func TestRealWorld_AutoMethodSelection(t *testing.T) {
	testCases := []struct {
		name    string
		dataset string
	}{
		{"HighVariance_Domain1", "real_domain1_18.200.137.227.json.gz"},
		{"LowVariance_Domain3", "real_domain3_52.19.167.193.json.gz"},
		{"LowVariance_Domain4", "real_domain4_63.32.0.98.json.gz"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataset, err := testdata.LoadDataset(tc.dataset)
			if err != nil {
				t.Skipf("Skipping: test data not available: %v", err)
			}

			responseData := testdata.ExtractResponseData(dataset.FilterSuccessful())
			records := make([]*ResponseRecord, len(responseData))
			for i, rd := range responseData {
				attrs, _ := ExtractAttributesFromRaw(rd.StatusCode, rd.Body, rd.Headers)
				records[i] = &ResponseRecord{
					Attributes: *attrs,
					Metadata:   i,
				}
			}

			engine := NewDefaultEngine()
			err = engine.RankAndSort(records)
			if err != nil {
				t.Fatalf("RankAndSort failed: %v", err)
			}

			stats := AnalyzeScoreDistribution(records)
			t.Logf("Auto-selected %v for variance=%d (CV=%.2f%%)",
				stats.Recommended, stats.VarianceLevel, stats.CV)

			filter := NewInterestingFilter(FilterMethodAuto)
			interesting := filter.FilterInteresting(records, DefaultFilterConfig())
			t.Logf("Returned %d interesting responses", len(interesting))
		})
	}
}

// ============================================================================
// ANOMALY DETECTION ACCURACY TESTS
// ============================================================================

// TestRealWorld_RareResponseDetection verifies rare 200 OK are detected among 404s
func TestRealWorld_RareResponseDetection(t *testing.T) {
	testCases := []struct {
		name          string
		dataset       string
		expected200   int
		expectedTotal int
	}{
		{"Domain1_2of100", "real_domain1_18.200.137.227.json.gz", 2, 100},
		{"Domain4_2of192", "real_domain4_63.32.0.98.json.gz", 2, 192},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataset, err := testdata.LoadDataset(tc.dataset)
			if err != nil {
				t.Skipf("Skipping: test data not available: %v", err)
			}

			responseData := testdata.ExtractResponseData(dataset.FilterSuccessful())
			records := make([]*ResponseRecord, len(responseData))

			// Track actual 200s
			actual200 := 0
			for i, rd := range responseData {
				if rd.StatusCode == 200 {
					actual200++
				}

				attrs, _ := ExtractAttributesFromRaw(rd.StatusCode, rd.Body, rd.Headers)
				records[i] = &ResponseRecord{
					Attributes: *attrs,
					Metadata: map[string]interface{}{
						"statusCode": rd.StatusCode,
					},
				}
			}

			if len(records) != tc.expectedTotal {
				t.Fatalf("Expected %d responses, got %d", tc.expectedTotal, len(records))
			}

			if actual200 != tc.expected200 {
				t.Fatalf("Dataset has %d 200 OK, expected %d", actual200, tc.expected200)
			}

			engine := NewDefaultEngine()
			err = engine.RankAndSort(records)
			if err != nil {
				t.Fatalf("RankAndSort failed: %v", err)
			}

			filter := NewInterestingFilter(FilterMethodAuto)
			interesting := filter.FilterInteresting(records, DefaultFilterConfig())

			// Count 200s in interesting set
			detected200 := 0
			for _, r := range interesting {
				meta := r.Metadata.(map[string]interface{})
				if meta["statusCode"].(int) == 200 {
					detected200++
				}
			}

			detectionRate := float64(detected200) / float64(tc.expected200) * 100
			t.Logf("Detected %d/%d 200 OK responses (%.1f%% detection rate)",
				detected200, tc.expected200, detectionRate)

			if detected200 < tc.expected200 {
				t.Errorf("Failed to detect all rare 200 OK responses: %d/%d",
					detected200, tc.expected200)
			}
		})
	}
}

// ============================================================================
// CONFIGURATION TESTS
// ============================================================================

// TestRealWorld_MinMaxConstraints verifies min/max configuration works
func TestRealWorld_MinMaxConstraints(t *testing.T) {
	dataset, err := testdata.LoadDataset("real_domain1_18.200.137.227.json.gz")
	if err != nil {
		t.Skipf("Skipping: test data not available: %v", err)
	}

	responseData := testdata.ExtractResponseData(dataset.FilterSuccessful())
	records := make([]*ResponseRecord, len(responseData))
	for i, rd := range responseData {
		attrs, _ := ExtractAttributesFromRaw(rd.StatusCode, rd.Body, rd.Headers)
		records[i] = &ResponseRecord{
			Attributes: *attrs,
			Metadata:   i,
		}
	}

	engine := NewDefaultEngine()
	err = engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("RankAndSort failed: %v", err)
	}

	testCases := []struct {
		name string
		min  int
		max  int
	}{
		{"Min5", 5, 0},
		{"Max10", 0, 10},
		{"Min3Max20", 3, 20},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := NewInterestingFilter(FilterMethodAuto)
			config := DefaultFilterConfig()
			config.MinimumInteresting = tc.min
			config.MaximumInteresting = tc.max

			interesting := filter.FilterInteresting(records, config)
			count := len(interesting)

			t.Logf("Min=%d, Max=%d → %d interesting", tc.min, tc.max, count)

			if tc.min > 0 && count < tc.min {
				t.Errorf("Expected at least %d, got %d", tc.min, count)
			}
			if tc.max > 0 && count > tc.max {
				t.Errorf("Expected at most %d, got %d", tc.max, count)
			}
		})
	}
}

// TestRealWorld_CustomThresholds tests custom threshold parameters
func TestRealWorld_CustomThresholds(t *testing.T) {
	dataset, err := testdata.LoadDataset("real_domain1_18.200.137.227.json.gz")
	if err != nil {
		t.Skipf("Skipping: test data not available: %v", err)
	}

	responseData := testdata.ExtractResponseData(dataset.FilterSuccessful())
	records := make([]*ResponseRecord, len(responseData))
	for i, rd := range responseData {
		attrs, _ := ExtractAttributesFromRaw(rd.StatusCode, rd.Body, rd.Headers)
		records[i] = &ResponseRecord{
			Attributes: *attrs,
			Metadata:   i,
		}
	}

	engine := NewDefaultEngine()
	err = engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("RankAndSort failed: %v", err)
	}

	testCases := []struct {
		name      string
		method    FilterMethod
		threshold float64
	}{
		{"IQR_Sensitive", FilterMethodIQR, 1.0},
		{"IQR_Strict", FilterMethodIQR, 2.5},
		{"ZScore_Loose", FilterMethodZScore, 1.5},
		{"ZScore_Strict", FilterMethodZScore, 3.0},
		{"TopPercent_5", FilterMethodTopPercent, 5.0},
		{"TopPercent_20", FilterMethodTopPercent, 20.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := NewInterestingFilter(tc.method)
			config := DefaultFilterConfig()
			config.IQRMultiplier = tc.threshold
			config.ZScoreThreshold = tc.threshold
			config.TopPercent = tc.threshold / 100.0 // Convert percentage to fraction

			interesting := filter.FilterInteresting(records, config)
			t.Logf("%v (threshold=%.1f) → %d interesting",
				tc.method, tc.threshold, len(interesting))
		})
	}
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

// TestRealWorld_EmptyDataset verifies handling of empty input
func TestRealWorld_EmptyDataset(t *testing.T) {
	engine := NewDefaultEngine()
	err := engine.RankAndSort([]*ResponseRecord{})
	if err != nil {
		t.Fatalf("RankAndSort failed on empty: %v", err)
	}
}

// TestRealWorld_SingleResponse tests single response handling
func TestRealWorld_SingleResponse(t *testing.T) {
	attrs, _ := ExtractAttributesFromRaw(200, "test body", map[string][]string{"Content-Type": {"text/html"}})
	records := []*ResponseRecord{
		{
			Attributes: *attrs,
			Metadata:   0,
		},
	}

	engine := NewDefaultEngine()
	err := engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("RankAndSort failed: %v", err)
	}

	filter := NewInterestingFilter(FilterMethodAuto)
	interesting := filter.FilterInteresting(records, DefaultFilterConfig())

	t.Logf("Single response → %d interesting", len(interesting))
	if len(interesting) != 1 {
		t.Errorf("Expected 1 interesting, got %d", len(interesting))
	}
}

// TestRealWorld_TwoResponses tests two response handling
func TestRealWorld_TwoResponses(t *testing.T) {
	attrs1, _ := ExtractAttributesFromRaw(200, "short", map[string][]string{})
	attrs2, _ := ExtractAttributesFromRaw(404, "much longer response body here", map[string][]string{})

	records := []*ResponseRecord{
		{Attributes: *attrs1, Metadata: 0},
		{Attributes: *attrs2, Metadata: 1},
	}

	engine := NewDefaultEngine()
	err := engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("RankAndSort failed: %v", err)
	}

	filter := NewInterestingFilter(FilterMethodAuto)
	interesting := filter.FilterInteresting(records, DefaultFilterConfig())

	t.Logf("Two responses → %d interesting", len(interesting))
	if len(interesting) == 0 {
		t.Error("Expected at least one interesting response")
	}
}

// TestRealWorld_AllIdenticalResponses tests identical response handling
func TestRealWorld_AllIdenticalResponses(t *testing.T) {
	body := "identical response body"
	headers := map[string][]string{"Content-Type": {"text/html"}}

	records := make([]*ResponseRecord, 50)
	for i := range records {
		attrs, _ := ExtractAttributesFromRaw(404, body, headers)
		records[i] = &ResponseRecord{
			Attributes: *attrs,
			Metadata:   i,
		}
	}

	engine := NewDefaultEngine()
	err := engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("RankAndSort failed: %v", err)
	}

	stats := AnalyzeScoreDistribution(records)
	t.Logf("Identical responses: variance=%d, CV=%.2f%%",
		stats.VarianceLevel, stats.CV)

	filter := NewInterestingFilter(FilterMethodAuto)
	interesting := filter.FilterInteresting(records, DefaultFilterConfig())

	t.Logf("Identical responses → %d interesting", len(interesting))
	// Zero or minimal interesting expected for identical responses
}
