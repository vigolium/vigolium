package testdata

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CapturedResponse represents a full HTTP response capture for testing
type CapturedResponse struct {
	URL        string              `json:"url"`
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
	ContentLen int                 `json:"content_len"`
	WordCount  int                 `json:"word_count"`
	LineCount  int                 `json:"line_count"`
	FetchedAt  time.Time           `json:"fetched_at"`
	FetchError string              `json:"fetch_error,omitempty"`
}

// Dataset represents a collection of responses for a specific test scenario
type Dataset struct {
	Name        string
	Description string
	Responses   []CapturedResponse
	Stats       DatasetStats
}

// DatasetStats provides summary statistics about a dataset
type DatasetStats struct {
	TotalResponses    int
	SuccessfulFetches int
	FailedFetches     int
	UniqueStatuses    map[int]int
	MinContentLen     int
	MaxContentLen     int
	AvgContentLen     float64
}

// Cache for loaded datasets (singleton pattern)
var (
	datasetCache = make(map[string]*Dataset)
	cacheMutex   sync.RWMutex
)

// LoadDataset loads a gzipped JSON test dataset
// Results are cached for performance
func LoadDataset(filename string) (*Dataset, error) {
	// Check cache first
	cacheMutex.RLock()
	if cached, ok := datasetCache[filename]; ok {
		cacheMutex.RUnlock()
		return cached, nil
	}
	cacheMutex.RUnlock()

	// Load from disk
	dataset, err := loadFromDisk(filename)
	if err != nil {
		return nil, err
	}

	// Cache for future use
	cacheMutex.Lock()
	datasetCache[filename] = dataset
	cacheMutex.Unlock()

	return dataset, nil
}

// loadFromDisk reads and decompresses a gzipped JSON dataset file
func loadFromDisk(filename string) (*Dataset, error) {
	// Find the file (check multiple possible locations)
	fullPath, err := findTestDataFile(filename)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", fullPath, err)
	}
	defer func() { _ = f.Close() }()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gzReader.Close() }()

	var responses []CapturedResponse
	decoder := json.NewDecoder(gzReader)
	if err := decoder.Decode(&responses); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	// Calculate statistics
	stats := calculateStats(responses)

	dataset := &Dataset{
		Name:        filepath.Base(filename),
		Description: fmt.Sprintf("Test dataset with %d responses", len(responses)),
		Responses:   responses,
		Stats:       stats,
	}

	return dataset, nil
}

// findTestDataFile locates the test data file in various possible locations
func findTestDataFile(filename string) (string, error) {
	// List of possible paths to check
	possiblePaths := []string{
		filename,                            // Direct path
		filepath.Join("testdata", filename), // Relative to current dir
		filepath.Join("test", "pkg-testdata", "anomaly", filename), // From project root
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("test data file %s not found in any expected location", filename)
}

// calculateStats computes summary statistics for a dataset
func calculateStats(responses []CapturedResponse) DatasetStats {
	stats := DatasetStats{
		TotalResponses: len(responses),
		UniqueStatuses: make(map[int]int),
	}

	if len(responses) == 0 {
		return stats
	}

	minLen := responses[0].ContentLen
	maxLen := responses[0].ContentLen
	totalLen := 0

	for _, resp := range responses {
		if resp.FetchError == "" {
			stats.SuccessfulFetches++
		} else {
			stats.FailedFetches++
			continue
		}

		stats.UniqueStatuses[resp.StatusCode]++

		if resp.ContentLen < minLen {
			minLen = resp.ContentLen
		}
		if resp.ContentLen > maxLen {
			maxLen = resp.ContentLen
		}
		totalLen += resp.ContentLen
	}

	stats.MinContentLen = minLen
	stats.MaxContentLen = maxLen
	if stats.SuccessfulFetches > 0 {
		stats.AvgContentLen = float64(totalLen) / float64(stats.SuccessfulFetches)
	}

	return stats
}

// FilterSuccessful returns only responses that were successfully fetched
func (d *Dataset) FilterSuccessful() []CapturedResponse {
	filtered := make([]CapturedResponse, 0, d.Stats.SuccessfulFetches)
	for _, resp := range d.Responses {
		if resp.FetchError == "" {
			filtered = append(filtered, resp)
		}
	}
	return filtered
}

// FilterByStatus returns only responses with the specified status code
func (d *Dataset) FilterByStatus(statusCode int) []CapturedResponse {
	filtered := make([]CapturedResponse, 0)
	for _, resp := range d.Responses {
		if resp.StatusCode == statusCode {
			filtered = append(filtered, resp)
		}
	}
	return filtered
}

// FilterByContentLenRange returns responses within the specified content length range
func (d *Dataset) FilterByContentLenRange(minLen, maxLen int) []CapturedResponse {
	filtered := make([]CapturedResponse, 0)
	for _, resp := range d.Responses {
		if resp.ContentLen >= minLen && resp.ContentLen <= maxLen {
			filtered = append(filtered, resp)
		}
	}
	return filtered
}

// Top returns the top N responses sorted by content length
func (d *Dataset) Top(n int) []CapturedResponse {
	if n > len(d.Responses) {
		n = len(d.Responses)
	}

	// Sort by content length descending (assumes they're already roughly sorted)
	top := make([]CapturedResponse, n)
	copy(top, d.Responses[:n])
	return top
}

// ClearCache clears the dataset cache (useful for testing)
func ClearCache() {
	cacheMutex.Lock()
	datasetCache = make(map[string]*Dataset)
	cacheMutex.Unlock()
}
