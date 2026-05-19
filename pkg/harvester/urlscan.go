package harvester

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type urlscanResponse struct {
	Results []urlscanResult `json:"results"`
	HasMore bool            `json:"has_more"`
}

type urlscanResult struct {
	Page urlscanPage `json:"page"`
	Sort []any       `json:"sort"`
}

type urlscanPage struct {
	URL string `json:"url"`
}

// URLScanSource collects URLs from the URLScan.io API.
type URLScanSource struct {
	apiKey string
	client *http.Client
}

// NewURLScanSource creates a new URLScan.io harvester source.
// proxyURL is optional; pass "" for no proxy.
func NewURLScanSource(apiKey string, proxyURL ...string) *URLScanSource {
	var proxy string
	if len(proxyURL) > 0 {
		proxy = proxyURL[0]
	}
	return &URLScanSource{
		apiKey: apiKey,
		client: NewHTTPClient(60*time.Second, proxy),
	}
}

func (s *URLScanSource) Name() string   { return "urlscan" }
func (s *URLScanSource) NeedsKey() bool { return true }

// Run fetches URLs for the domain from URLScan.io.
func (s *URLScanSource) Run(ctx context.Context, domain string) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		var searchAfter string
		hasMore := true
		baseURL := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=10000", domain)

		for hasMore {
			select {
			case <-ctx.Done():
				return
			default:
			}

			apiURL := baseURL
			if searchAfter != "" {
				apiURL = fmt.Sprintf("%s&search_after=%s", apiURL, searchAfter)
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
			if err != nil {
				results <- Result{Source: s.Name(), Error: err}
				return
			}
			req.Header.Set("API-Key", s.apiKey)

			resp, err := s.client.Do(req)
			if err != nil {
				results <- Result{Source: s.Name(), Error: err}
				return
			}

			if resp.StatusCode == http.StatusTooManyRequests {
				_ = resp.Body.Close()
				results <- Result{Source: s.Name(), Error: fmt.Errorf("urlscan rate limited")}
				return
			}

			var data urlscanResponse
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				_ = resp.Body.Close()
				results <- Result{Source: s.Name(), Error: err}
				return
			}
			_ = resp.Body.Close()

			for _, r := range data.Results {
				if r.Page.URL != "" {
					select {
					case <-ctx.Done():
						return
					case results <- Result{Source: s.Name(), URL: r.Page.URL}:
					}
				}
			}

			// Build search_after token for pagination
			if len(data.Results) > 0 {
				last := data.Results[len(data.Results)-1]
				if len(last.Sort) >= 2 {
					sort1 := strconv.Itoa(int(last.Sort[0].(float64)))
					sort2, _ := last.Sort[1].(string)
					searchAfter = fmt.Sprintf("%s,%s", sort1, sort2)
				}
			}
			hasMore = data.HasMore
		}
	}()

	return results
}
