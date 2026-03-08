package metrics

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CodeCoverageClient fetches code coverage from Arachnarium endpoint.
// Used by PHP apps (addressbook, phpbb2, drupal, etc.)
// Arachnarium returns JSON: {"filename.php": ["1-5", "10", "15-20"], ...}
type CodeCoverageClient struct {
	mu          sync.Mutex
	endpointURL string       // e.g., "http://web/arachnarium/coverage"
	outputDir   string       // Directory for coverage_N.txt files
	httpClient  *http.Client // HTTP client with timeout
	lastCount   int          // Last coverage count for delta calculation
}

// ArachnariumResponse represents the JSON response from Arachnarium.
// Maps filename -> list of covered line ranges (e.g., ["1-5", "10", "15-20"])
type ArachnariumResponse map[string][]string

// NewCodeCoverageClient creates a new coverage client.
func NewCodeCoverageClient(endpointURL, outputDir string) (*CodeCoverageClient, error) {
	// Ensure coverage directory exists
	coverageDir := filepath.Join(outputDir, "coverage")
	if err := os.MkdirAll(coverageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create coverage directory: %w", err)
	}

	return &CodeCoverageClient{
		endpointURL: endpointURL,
		outputDir:   coverageDir,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		lastCount: 0,
	}, nil
}

// Fetch fetches current coverage from Arachnarium endpoint.
// Returns the raw response and total line count.
func (c *CodeCoverageClient) Fetch() (ArachnariumResponse, int, error) {
	if c.endpointURL == "" {
		return nil, 0, nil // No coverage for Node.js apps
	}

	resp, err := c.httpClient.Get(c.endpointURL)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to fetch coverage: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("coverage endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read coverage response: %w", err)
	}

	var coverage ArachnariumResponse
	if err := json.Unmarshal(body, &coverage); err != nil {
		return nil, 0, fmt.Errorf("failed to parse coverage JSON: %w", err)
	}

	count := CountCoveredLines(coverage)
	return coverage, count, nil
}

// FetchAndSave fetches coverage and saves to coverage_{step}.txt.
// Returns: total lines covered, delta from last call, error
func (c *CodeCoverageClient) FetchAndSave(step int) (int, int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	coverage, count, err := c.Fetch()
	if err != nil {
		return 0, 0, err
	}

	if coverage == nil {
		return 0, 0, nil // No coverage for this app type
	}

	// Save to file
	filename := filepath.Join(c.outputDir, fmt.Sprintf("coverage_%d.txt", step))
	file, err := os.Create(filename)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create coverage file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(coverage); err != nil {
		return 0, 0, fmt.Errorf("failed to encode coverage: %w", err)
	}

	// Calculate delta
	delta := count - c.lastCount
	c.lastCount = count

	return count, delta, nil
}

// GetLastCount returns the last coverage count.
func (c *CodeCoverageClient) GetLastCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastCount
}

// CountCoveredLines counts total covered lines from Arachnarium response.
// Parses ranges like "1-5" (= 5 lines) and single lines like "10" (= 1 line).
func CountCoveredLines(coverage ArachnariumResponse) int {
	total := 0
	for _, ranges := range coverage {
		for _, lineRange := range ranges {
			total += countLinesInRange(lineRange)
		}
	}
	return total
}

// countLinesInRange counts lines in a range string.
// "1-5" -> 5, "10" -> 1, "15-20" -> 6
func countLinesInRange(s string) int {
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		if len(parts) != 2 {
			return 1
		}
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return 1
		}
		return end - start + 1
	}
	return 1
}

// ConvertToSnapshot converts Arachnarium response to CodeCoverageSnapshot.
// Expands ranges to individual line numbers.
func ConvertToSnapshot(coverage ArachnariumResponse) CodeCoverageSnapshot {
	snapshot := make(CodeCoverageSnapshot)
	for filename, ranges := range coverage {
		var lines []int
		for _, lineRange := range ranges {
			lines = append(lines, expandRange(lineRange)...)
		}
		snapshot[filename] = lines
	}
	return snapshot
}

// expandRange expands a range string to individual line numbers.
// "1-5" -> [1, 2, 3, 4, 5], "10" -> [10]
func expandRange(s string) []int {
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		if len(parts) != 2 {
			return nil
		}
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return nil
		}
		lines := make([]int, 0, end-start+1)
		for i := start; i <= end; i++ {
			lines = append(lines, i)
		}
		return lines
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return []int{n}
}
