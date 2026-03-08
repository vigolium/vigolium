package harvester

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	ccIndexURL     = "https://index.commoncrawl.org/collinfo.json"
	ccMaxYearsBack = 5
)

type ccIndexEntry struct {
	ID     string `json:"id"`
	APIURL string `json:"cdx-api"`
}

// CommonCrawlSource collects URLs from the Common Crawl CDX index.
type CommonCrawlSource struct {
	client *http.Client
}

// NewCommonCrawlSource creates a new Common Crawl harvester source.
// proxyURL is optional; pass "" for no proxy.
func NewCommonCrawlSource(proxyURL ...string) *CommonCrawlSource {
	var proxy string
	if len(proxyURL) > 0 {
		proxy = proxyURL[0]
	}
	return &CommonCrawlSource{
		client: NewHTTPClient(60*time.Second, proxy),
	}
}

func (s *CommonCrawlSource) Name() string    { return "commoncrawl" }
func (s *CommonCrawlSource) NeedsKey() bool  { return false }

// Run fetches URLs for the domain from Common Crawl indices.
func (s *CommonCrawlSource) Run(ctx context.Context, domain string) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		// Fetch index list
		indexes, err := s.fetchIndexes(ctx)
		if err != nil {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("fetch indexes: %w", err)}
			return
		}

		// Select indices from last N years
		currentYear := time.Now().Year()
		years := make([]string, 0, ccMaxYearsBack)
		for i := range ccMaxYearsBack {
			years = append(years, strconv.Itoa(currentYear-i))
		}

		selectedAPIs := make(map[string]string)
		for _, year := range years {
			for _, idx := range indexes {
				if strings.Contains(idx.ID, year) {
					if _, exists := selectedAPIs[year]; !exists {
						selectedAPIs[year] = idx.APIURL
						break
					}
				}
			}
		}

		// Query each selected index
		for _, apiURL := range selectedAPIs {
			select {
			case <-ctx.Done():
				return
			default:
			}

			s.queryIndex(ctx, apiURL, domain, results)
		}
	}()

	return results
}

func (s *CommonCrawlSource) fetchIndexes(ctx context.Context) ([]ccIndexEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ccIndexURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var indexes []ccIndexEntry
	if err := json.NewDecoder(resp.Body).Decode(&indexes); err != nil {
		return nil, err
	}
	return indexes, nil
}

func (s *CommonCrawlSource) queryIndex(ctx context.Context, apiURL, domain string, results chan<- Result) {
	searchURL := fmt.Sprintf("%s?url=*.%s&output=text&fl=url", apiURL, domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		results <- Result{Source: s.Name(), Error: err}
		return
	}
	req.Header.Set("Host", "index.commoncrawl.org")

	resp, err := s.client.Do(req)
	if err != nil {
		results <- Result{Source: s.Name(), Error: err}
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		results <- Result{Source: s.Name(), URL: line}
	}
}
