package prototype_pollution

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const benignJSONBody = `{"name":"alice"}`

// jsonPost builds a POST request with an application/json body so the module's
// CanProcess gate (POST/PUT/PATCH + JSON content type) is satisfied. modtest's
// RequestMethod hardcodes a form content type, so the raw request is assembled
// here directly.
func jsonPost(t *testing.T, rawURL, body string) *httpmsg.HttpRequestResponse {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)

	port := 80
	if p := u.Port(); p != "" {
		_, _ = fmt.Sscanf(p, "%d", &port)
	} else if u.Scheme == "https" {
		port = 443
	}

	svc, err := httpmsg.NewService(u.Hostname(), port, u.Scheme)
	require.NoError(t, err)

	target := u.RequestURI()
	if target == "" {
		target = "/"
	}
	raw := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		target, u.Host, len(body), body,
	)
	req := httpmsg.NewHttpRequestWithService(svc, []byte(raw))
	return httpmsg.NewHttpRequestResponse(req, nil)
}

// TestScanPerRequest_DetectsPollutionReflection drives the scan against a
// handler that echoes the request body back. The benign baseline body lacks the
// pollution marker, but a __proto__ payload carrying vigolium_pp_test is
// reflected, triggering detection.
func TestScanPerRequest_DetectsPollutionReflection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b) // reflect the request body
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := jsonPost(t, srv.URL+"/api/user", benignJSONBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the pollution marker is reflected")
}

// TestScanPerRequest_DetectsStatusPollution simulates a server that honors a
// polluted status property by returning HTTP 510, while the benign baseline is
// 200.
func TestScanPerRequest_DetectsStatusPollution(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), `"status":510`) {
			w.WriteHeader(510)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := jsonPost(t, srv.URL+"/api/user", benignJSONBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when status-code pollution flips the response to 510")
}

// TestScanPerRequest_NoFalsePositive ensures a server that ignores the injected
// payloads (static benign response) yields no findings.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := jsonPost(t, srv.URL+"/api/user", benignJSONBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server unaffected by pollution payloads must not yield findings")
}

// TestCanProcess validates the POST/PUT/PATCH + JSON gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	jsonReq := modtest.Response(jsonPost(t, "http://example.com/api", benignJSONBody), "application/json", "{}")
	assert.True(t, m.CanProcess(jsonReq), "POST with JSON body should be processable")

	getReq := modtest.Response(modtest.Request(t, "http://example.com/api"), "application/json", "{}")
	assert.False(t, m.CanProcess(getReq), "GET request should not be processable")
}
