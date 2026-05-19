package harness

import (
	"fmt"

	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// FetchForPassiveScan fetches a URL using the test infrastructure's HTTP client
// and returns a fully populated HttpRequestResponse suitable for passive scanning.
// The returned HRR contains the actual HTTP response for passive module analysis.
// Optional headers (e.g., cookies) are injected into the request before fetching.
func FetchForPassiveScan(url string, headers map[string]string, infra *TestInfra) (*httpmsg.HttpRequestResponse, error) {
	rr, err := buildRequestWithHeaders(url, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to create request from URL %s: %w", url, err)
	}

	respChain, _, err := infra.HTTPClient.Execute(rr, httpRequester.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", url, err)
	}

	// Read the full response and attach it to the HRR
	fullResp := respChain.FullResponse().Bytes()
	rawResponseCopy := make([]byte, len(fullResp))
	copy(rawResponseCopy, fullResp)
	respChain.Close()

	httpResp := httpmsg.NewHttpResponse(rawResponseCopy)
	return rr.WithResponse(httpResp), nil
}
