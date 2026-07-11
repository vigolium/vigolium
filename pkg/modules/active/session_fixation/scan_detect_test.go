package session_fixation

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// TestIgnoredUnknownSession_NotDetected is the central false-positive
// regression: silence does not prove that the server adopted the supplied ID.
func TestIgnoredUnknownSession_NotDetected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("SESSIONID"); err == nil {
			// Ignore unknown client values and serve an anonymous response without
			// issuing a replacement.
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
	assert.Empty(t, res, "a 200 response with no Set-Cookie does not prove adoption")
}

func TestExplicitSessionAdoption_IsCandidate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("SESSIONID"); err == nil && c.Value != "" {
			http.SetCookie(w, &http.Cookie{Name: "SESSIONID", Value: c.Value})
			w.WriteHeader(http.StatusOK)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "SESSIONID", Value: "server-generated-123"})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/app"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, res[0].EvidenceGrade)
}

func TestSessionAdoptionAcrossLogin_IsFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("SESSIONID"); err == nil && c.Value != "" {
			http.SetCookie(w, &http.Cookie{Name: "SESSIONID", Value: c.Value})
		} else {
			http.SetCookie(w, &http.Cookie{Name: "SESSIONID", Value: "server-generated-123"})
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authenticated":true,"welcome":"alice"}`))
	}))
	defer srv.Close()

	rr := modtest.RequestMethod(t, http.MethodPost, srv.URL+"/login", "username=alice&password=secret")
	rr = modtest.Response(rr, "application/json", `{"authenticated":true,"welcome":"alice"}`)
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, output.RecordKindFinding, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeBypass, res[0].EvidenceGrade)
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
