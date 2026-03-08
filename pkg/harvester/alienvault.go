package harvester

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type alienvaultResponse struct {
	URLList []alienvaultURL `json:"url_list"`
	HasNext bool            `json:"has_next"`
}

type alienvaultURL struct {
	URL string `json:"url"`
}

// AlienVaultSource collects URLs from the AlienVault OTX API.
type AlienVaultSource struct {
	client *http.Client
}

// NewAlienVaultSource creates a new AlienVault OTX harvester source.
// proxyURL is optional; pass "" for no proxy.
func NewAlienVaultSource(proxyURL ...string) *AlienVaultSource {
	var proxy string
	if len(proxyURL) > 0 {
		proxy = proxyURL[0]
	}
	return &AlienVaultSource{
		client: NewHTTPClient(60*time.Second, proxy),
	}
}

func (s *AlienVaultSource) Name() string    { return "alienvault" }
func (s *AlienVaultSource) NeedsKey() bool  { return false }

// Run fetches URLs for the domain from AlienVault OTX.
func (s *AlienVaultSource) Run(ctx context.Context, domain string) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		page := 1
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			apiURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?page=%d", domain, page)

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

			var data alienvaultResponse
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				_ = resp.Body.Close()
				results <- Result{Source: s.Name(), Error: err}
				return
			}
			_ = resp.Body.Close()

			for _, record := range data.URLList {
				if record.URL != "" {
					select {
					case <-ctx.Done():
						return
					case results <- Result{Source: s.Name(), URL: record.URL}:
					}
				}
			}

			if !data.HasNext {
				break
			}
			page++
		}
	}()

	return results
}
