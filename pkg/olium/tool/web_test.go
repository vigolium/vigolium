package tool

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// stubCaptureSink is a no-op CaptureSink so the capture-enabled web_fetch
// variant can be constructed in tests without a database.
type stubCaptureSink struct{}

func (stubCaptureSink) SaveRecord(context.Context, *httpmsg.HttpRequestResponse, string, string) (string, error) {
	return "rec-uuid", nil
}
func (stubCaptureSink) SaveRecordBatch(context.Context, []*httpmsg.HttpRequestResponse, string, string) ([]string, error) {
	return nil, nil
}

// TestWebFetchIsReadOnly locks in the fix: the capture-enabled variant writes
// http_records (and can issue state-changing methods), so it must NOT be
// eligible for the engine's read-only parallel fan-out. Only the no-capture
// variant is genuinely read-only.
func TestWebFetchIsReadOnly(t *testing.T) {
	if !NewWebFetch().IsReadOnly() {
		t.Error("no-capture web_fetch should be read-only")
	}
	if NewWebFetchWithCapture(stubCaptureSink{}, "proj").IsReadOnly() {
		t.Error("capture-enabled web_fetch must NOT be read-only (it writes records concurrently)")
	}
}

// TestWebFetchTruncationBoundary locks in the off-by-one fix: a body landing
// exactly on max_bytes is complete, not truncated; a body one byte over is
// truncated and trimmed back to the cap.
func TestWebFetchTruncationBoundary(t *testing.T) {
	const n = 100
	body := strings.Repeat("x", n)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	fetch := NewWebFetch()
	ctx := context.Background()

	cases := []struct {
		name          string
		maxBytes      float64
		wantTruncated bool
		wantBytes     int
	}{
		{"exactly at limit", float64(n), false, n},
		{"one under limit", float64(n - 1), true, n - 1},
		{"well over limit", float64(n + 50), false, n},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := fetch.Execute(ctx, map[string]any{
				"url":       srv.URL,
				"max_bytes": tc.maxBytes,
			}, nil)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if res.IsError {
				t.Fatalf("unexpected error result: %s", res.Content)
			}
			gotTrunc, _ := res.Details["truncated"].(bool)
			if gotTrunc != tc.wantTruncated {
				t.Errorf("truncated = %v, want %v", gotTrunc, tc.wantTruncated)
			}
			gotBytes, _ := res.Details["bytes"].(int)
			if gotBytes != tc.wantBytes {
				t.Errorf("bytes = %d, want %d", gotBytes, tc.wantBytes)
			}
			if tc.wantTruncated && !strings.Contains(res.Content, "[truncated at") {
				t.Error("expected truncation marker in content")
			}
		})
	}
}
