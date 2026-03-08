package anomaly_test

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/anomaly"
)

// Example showing basic usage with minimal metadata (index only)
func ExampleEngine_basic() {
	engine := anomaly.NewDefaultEngine()

	// Create records with attributes extracted from responses
	// Storing only index as metadata (minimal memory)
	records := []*anomaly.ResponseRecord{
		{
			Attributes: *createSampleAttrs(200, "Normal page"),
			Metadata:   0,
		},
		{
			Attributes: *createSampleAttrs(200, "Normal page"),
			Metadata:   1,
		},
		{
			Attributes: *createSampleAttrs(404, "Not found"),
			Metadata:   2,
		},
	}

	// Rank and sort
	_ = engine.RankAndSort(records)

	// Display top anomaly
	if len(records) > 0 {
		top := records[0]
		fmt.Printf("Most anomalous: index=%d, score=%d\n", top.Metadata.(int), top.Score)
	}

	// Output:
	// Most anomalous: index=2, score=40500
}

// Example showing usage with custom metadata struct
func ExampleEngine_customMetadata() {
	type RequestInfo struct {
		URL        string
		StatusCode int
	}

	engine := anomaly.NewDefaultEngine()

	records := []*anomaly.ResponseRecord{
		{
			Attributes: *createSampleAttrs(200, "Normal page content"),
			Metadata: RequestInfo{
				URL:        "https://example.com/page1",
				StatusCode: 200,
			},
		},
		{
			Attributes: *createSampleAttrs(200, "Normal page content"),
			Metadata: RequestInfo{
				URL:        "https://example.com/page2",
				StatusCode: 200,
			},
		},
		{
			Attributes: *createSampleAttrs(404, "Not Found - The requested page does not exist"),
			Metadata: RequestInfo{
				URL:        "https://example.com/missing",
				StatusCode: 404,
			},
		},
	}

	_ = engine.RankAndSort(records)

	// Access custom metadata
	fmt.Printf("Found %d responses\n", len(records))
	meta := records[0].Metadata.(RequestInfo)
	fmt.Printf("Most anomalous: %s (status=%d)\n", meta.URL, meta.StatusCode)

	// Output:
	// Found 3 responses
	// Most anomalous: https://example.com/missing (status=404)
}

// Example showing filtering interesting responses
func ExampleFilterInteresting() {
	engine := anomaly.NewDefaultEngine()

	// Many normal responses + few anomalous
	records := make([]*anomaly.ResponseRecord, 0, 100)

	// 95 normal responses
	for i := 0; i < 95; i++ {
		records = append(records, &anomaly.ResponseRecord{
			Attributes: *createSampleAttrs(200, "Normal page content"),
			Metadata:   i,
		})
	}

	// 5 anomalous responses
	for i := 95; i < 100; i++ {
		statusCode := 400 + i // Different error codes
		records = append(records, &anomaly.ResponseRecord{
			Attributes: *createSampleAttrs(statusCode, "Error page"),
			Metadata:   i,
		})
	}

	// Filter interesting (auto mode)
	config := anomaly.DefaultFilterConfig()
	interesting, _ := anomaly.FilterInteresting(engine, records, config)

	fmt.Printf("Total: %d, Interesting: %d\n", len(records), len(interesting))

	// Output:
	// Total: 100, Interesting: 5
}

// Helper to create sample AttributeSet
func createSampleAttrs(statusCode int, body string) *anomaly.AttributeSet {
	attrs, _ := anomaly.ExtractAttributesFromRaw(
		statusCode,
		body,
		map[string][]string{"Content-Type": {"text/html"}},
	)
	return attrs
}
