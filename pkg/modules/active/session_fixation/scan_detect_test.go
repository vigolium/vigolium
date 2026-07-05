package session_fixation

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestPermissiveSession_Detected: the server issues a SESSIONID for a fresh
// request but keeps whatever SESSIONID the client sends (never regenerates) — a
// permissive mechanism that must be reported.
func TestPermissiveSession_Detected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("SESSIONID"); err == nil && c.Value != "" {
			// Client supplied a session — accept it as-is (permissive).
			w.WriteHeader(http.StatusOK)
			return
		}
		// No session — issue one.
		http.SetCookie(w, &http.Cookie{Name: "SESSIONID", Value: "server-generated-123"})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app")
	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected a permissive-session finding")
	assert.Contains(t, res[0].Info.Name, "Permissive Session Management")
}

// TestStrictSession_NotDetected: a server that always regenerates its own
// SESSIONID (ignoring the client's) must not be flagged.
func TestStrictSession_NotDetected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Always issues a fresh server-side session, regardless of input.
		http.SetCookie(w, &http.Cookie{Name: "SESSIONID", Value: "fresh-server-value"})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app")
	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that regenerates its own session must not be flagged")
}

// TestNoSession_NotDetected: a host that never issues a session cookie is not
// tested (fail closed).
func TestNoSession_NotDetected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("static page"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app")
	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host without session cookies must not be flagged")
}
