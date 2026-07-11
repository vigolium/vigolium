package burpbridge

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
)

const MaxSiteMapMessageBytes = 8 * 1024 * 1024

type SiteMapSaveResult struct {
	Selected int      `json:"selected"`
	Added    int      `json:"added"`
	Skipped  int      `json:"skipped"`
	Errors   []string `json:"errors,omitempty"`
}

type siteMapSaveResponse struct {
	Added       int    `json:"added"`
	URL         string `json:"url"`
	RequestHash string `json:"request_hash"`
	Message     string `json:"message"`
}

// AddToSiteMap sends one raw request/response pair to the extension's Target
// Site map. The endpoint is loopback-only and does not replay the request.
func (c *Client) AddToSiteMap(
	ctx context.Context,
	rawURL string,
	rawRequest, rawResponse []byte,
	source string,
) error {
	if rawURL == "" {
		return errors.New("burp Site map save requires a URL")
	}
	target, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return errors.New("burp Site map save requires an absolute http or https URL")
	}
	if len(rawRequest) == 0 {
		return errors.New("burp Site map save requires a raw request")
	}
	if len(rawRequest) > MaxSiteMapMessageBytes || len(rawResponse) > MaxSiteMapMessageBytes {
		return fmt.Errorf("request or response exceeds the %d MiB Burp Site map safety limit", MaxSiteMapMessageBytes/(1024*1024))
	}
	if source == "" {
		source = "vigolium"
	}
	input := map[string]any{
		"input_mode":          "burp_base64",
		"url":                 target.String(),
		"source":              source,
		"http_request_base64": base64.StdEncoding.EncodeToString(rawRequest),
	}
	if len(rawResponse) > 0 {
		input["http_response_base64"] = base64.StdEncoding.EncodeToString(rawResponse)
	}
	var response siteMapSaveResponse
	if err := c.post(ctx, "/api/burp-bridge/sitemap", input, &response); err != nil {
		return err
	}
	if response.Added != 1 {
		return errors.New("burp bridge did not add the Site map item")
	}
	return nil
}

// SaveRecordsToSiteMap copies database records without issuing network
// requests to their target hosts. Per-record failures are reported and do not
// prevent the remaining selected records from being attempted.
func (c *Client) SaveRecordsToSiteMap(
	ctx context.Context,
	records []*database.HTTPRecord,
) SiteMapSaveResult {
	result := SiteMapSaveResult{Selected: len(records)}
	for _, record := range records {
		if err := c.AddToSiteMap(ctx, record.URL, record.RawRequest, record.RawResponse, "vigolium-db"); err != nil {
			result.Skipped++
			if len(result.Errors) < 10 {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", record.URL, err))
			}
			continue
		}
		result.Added++
	}
	return result
}
