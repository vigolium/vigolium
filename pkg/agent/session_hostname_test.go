package agent

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/backend"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TestReplaceAuthHeadersInHTTPRR stays in the root agent package because it
// calls ToHTTPRequestResponse which lives here (not in backend).
func TestReplaceAuthHeadersInHTTPRR(t *testing.T) {
	t.Run("nil session headers is no-op", func(t *testing.T) {
		rec := AgentHTTPRecord{
			Method:  "GET",
			URL:     "http://example.com/test",
			Headers: map[string]string{"Authorization": "Bearer stale"},
		}
		rr, err := ToHTTPRequestResponse(rec)
		if err != nil {
			t.Fatal(err)
		}
		records := []*httpmsg.HttpRequestResponse{rr}
		backend.ReplaceAuthHeadersInHTTPRR(records, nil)
		// Should remain unchanged
		found := false
		for _, h := range records[0].Request().Headers() {
			if h.Name == "Authorization" && h.Value == "Bearer stale" {
				found = true
			}
		}
		if !found {
			t.Error("expected Authorization header to remain unchanged")
		}
	})

	t.Run("replaces auth in HttpRequestResponse", func(t *testing.T) {
		rec := AgentHTTPRecord{
			Method:  "GET",
			URL:     "http://example.com/test",
			Headers: map[string]string{"Authorization": "Bearer stale", "Accept": "text/html"},
		}
		rr, err := ToHTTPRequestResponse(rec)
		if err != nil {
			t.Fatal(err)
		}
		records := []*httpmsg.HttpRequestResponse{rr}
		backend.ReplaceAuthHeadersInHTTPRR(records, map[string]string{"Authorization": "Bearer fresh"})

		foundAuth := false
		foundAccept := false
		for _, h := range records[0].Request().Headers() {
			if h.Name == "Authorization" {
				if h.Value != "Bearer fresh" {
					t.Errorf("expected Bearer fresh, got %s", h.Value)
				}
				foundAuth = true
			}
			if h.Name == "Accept" {
				foundAccept = true
			}
		}
		if !foundAuth {
			t.Error("expected Authorization header to be present")
		}
		if !foundAccept {
			t.Error("expected Accept header to be preserved")
		}
	})
}
