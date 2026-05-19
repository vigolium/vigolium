package harvester

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type virustotalResponse struct {
	DetectedURLs []struct {
		URL string `json:"url"`
	} `json:"detected_urls"`
	UndetectedURLs [][]any `json:"undetected_urls"`
}

// VirusTotalSource collects URLs from the VirusTotal API.
type VirusTotalSource struct {
	apiKey string
	client *http.Client
}

// NewVirusTotalSource creates a new VirusTotal harvester source.
// proxyURL is optional; pass "" for no proxy.
func NewVirusTotalSource(apiKey string, proxyURL ...string) *VirusTotalSource {
	var proxy string
	if len(proxyURL) > 0 {
		proxy = proxyURL[0]
	}
	return &VirusTotalSource{
		apiKey: apiKey,
		client: NewHTTPClient(60*time.Second, proxy),
	}
}

func (s *VirusTotalSource) Name() string   { return "virustotal" }
func (s *VirusTotalSource) NeedsKey() bool { return true }

// Run fetches URLs for the domain from VirusTotal.
func (s *VirusTotalSource) Run(ctx context.Context, domain string) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		apiURL := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", s.apiKey, domain)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			results <- Result{Source: s.Name(), Error: err}
			return
		}

		resp, err := s.client.Do(req)
		if err != nil {
			results <- Result{Source: s.Name(), Error: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("virustotal: unexpected status %d", resp.StatusCode)}
			return
		}

		var data virustotalResponse
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			results <- Result{Source: s.Name(), Error: err}
			return
		}

		for _, detected := range data.DetectedURLs {
			if detected.URL != "" {
				select {
				case <-ctx.Done():
					return
				case results <- Result{Source: s.Name(), URL: detected.URL}:
				}
			}
		}

		for _, undetected := range data.UndetectedURLs {
			if len(undetected) > 0 {
				if urlStr, ok := undetected[0].(string); ok && urlStr != "" {
					select {
					case <-ctx.Done():
						return
					case results <- Result{Source: s.Name(), URL: urlStr}:
					}
				}
			}
		}
	}()

	return results
}
