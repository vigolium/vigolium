package http_method_tampering

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_CatchAllEndpoint reproduces the reported false positive:
// an endpoint (à la DataDome /js/) that returns a 2xx, non-shell, per-request
// changing body for ANY method — so the wildcard/baseline shell checks are
// defeated and a dangerous method or honored override looks "enabled". The
// catch-all guard sends an unsupported sentinel method, sees it accepted just
// the same, and reports nothing.
func TestScanPerRequest_CatchAllEndpoint(t *testing.T) {
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 2xx + meaningful, per-request-varying body for ANY method (incl. the sentinel).
		c := atomic.AddInt64(&n, 1)
		_, _ = fmt.Fprintf(w, "<html><body>request %020d accepted and processed ok by the service</body></html>", c)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/js/"),
		"text/html",
		"<html><body>request 00000000000000000000 accepted and processed ok by the service</body></html>",
	)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a catch-all endpoint (2xx for any method) must not be reported, got %d: %+v", len(res), res)
	}
}

// TestScanPerRequest_DangerousMethodEnabled is the positive counterpart: a real
// endpoint that serves write methods but rejects unknown methods with 405. The
// sentinel probe is rejected, so the catch-all guard does NOT fire and the
// genuine finding survives.
func TestScanPerRequest_DangerousMethodEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			_, _ = io.WriteString(w, "<html><body>resource listing: alpha beta gamma delta epsilon zeta</body></html>")
		case "PUT", "DELETE", "PATCH", "MKCOL", "MOVE", "COPY":
			_, _ = io.WriteString(w, "<html><body>resource modified by "+r.Method+" successfully, new state persisted</body></html>")
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = io.WriteString(w, "method not allowed")
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/item/42"),
		"text/html",
		"<html><body>resource listing: alpha beta gamma delta epsilon zeta</body></html>",
	)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) == 0 {
		t.Fatal("expected a finding: write methods are enabled and the sentinel method is rejected (not a catch-all)")
	}
}

func TestIsSuccessfulMethod(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		want       bool
	}{
		{
			name:       "200 with meaningful body is successful",
			statusCode: 200,
			body:       "<html><body>Welcome to the admin panel, you have full access</body></html>",
			want:       true,
		},
		{
			name:       "405 is not successful",
			statusCode: 405,
			body:       "Method Not Allowed",
			want:       false,
		},
		{
			name:       "403 is not successful",
			statusCode: 403,
			body:       "Forbidden",
			want:       false,
		},
		{
			name:       "200 with method not allowed in body is not successful",
			statusCode: 200,
			body:       "<html>Method Not Allowed for this resource</html>",
			want:       false,
		},
		{
			name:       "200 with not supported in body is not successful",
			statusCode: 200,
			body:       "<html>This HTTP method is not supported on this endpoint</html>",
			want:       false,
		},
		{
			name:       "200 with login redirect is not successful",
			statusCode: 200,
			body:       "<html>Redirecting to /login please authenticate first</html>",
			want:       false,
		},
		{
			name:       "200 with empty body is not successful",
			statusCode: 200,
			body:       "",
			want:       false,
		},
		{
			name:       "200 with very short body is not successful",
			statusCode: 200,
			body:       "OK",
			want:       false,
		},
		{
			name:       "500 is not successful",
			statusCode: 500,
			body:       "Internal Server Error",
			want:       false,
		},
		{
			name:       "302 is not successful",
			statusCode: 302,
			body:       "",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSuccessfulMethod(tt.statusCode, tt.body)
			if got != tt.want {
				t.Errorf("isSuccessfulMethod(%d, ...) = %v, want %v", tt.statusCode, got, tt.want)
			}
		})
	}
}
