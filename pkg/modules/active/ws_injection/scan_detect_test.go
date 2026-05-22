package ws_injection

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestNew_Metadata verifies module identity and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, ModuleTags, m.Tags())
}

// TestScanPerInsertionPoint_DetectsReflectedXSS drives the real scan method
// against a server that reflects a WS-named parameter unencoded into the body.
// The module only targets WebSocket-message-style parameter names (e.g.
// "message"), so the injected payload should surface as a finding.
func TestScanPerInsertionPoint_DetectsReflectedXSS(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the message parameter back verbatim (unencoded reflection).
		_, _ = w.Write([]byte("chat: " + r.URL.Query().Get("message")))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws?message=hello")
	ip := modtest.InsertionPoint(t, rr, "message")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an injection finding when a WS param reflects payloads")
	assert.True(t, res[0].MatcherStatus)
}

// TestScanPerInsertionPoint_SkipsNonWSParam ensures a parameter whose name is
// not associated with WebSocket message processing is skipped entirely, even if
// it reflects.
func TestScanPerInsertionPoint_SkipsNonWSParam(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Query().Get("color")))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws?color=red")
	ip := modtest.InsertionPoint(t, rr, "color")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "non-WebSocket parameter names must be skipped")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a WS-named parameter that is
// safely handled (no reflection, no SQL error, no command output) yields no
// finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("message received"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws?message=hello")
	ip := modtest.InsertionPoint(t, rr, "message")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a safely-handled WS param must not yield a finding")
}
