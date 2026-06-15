package dashboard_exposure

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// loginFinding returns the default-credentials finding for product, or nil.
func loginFinding(res []*output.ResultEvent, product string) *output.ResultEvent {
	for _, r := range res {
		if r.Metadata["product"] == product && r.Metadata["default_login"] == true {
			return r
		}
	}
	return nil
}

func readBody(r *http.Request) string {
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

// TestDefaultLogin_GrafanaValidCreds: a Grafana that is confirmed via /api/health
// AND accepts admin/admin must yield a Critical default-credentials finding with
// the working pair shown unredacted.
func TestDefaultLogin_GrafanaValidCreds(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"database":"ok","version":"10.1.0"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/login":
			body := readBody(r)
			if strings.Contains(body, `"user":"admin"`) && strings.Contains(body, `"password":"admin"`) {
				w.Header().Set("Set-Cookie", "grafana_session=abc123; Path=/; HttpOnly")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"Logged in"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Invalid username or password"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)

	lf := loginFinding(res, "grafana")
	require.NotNil(t, lf, "expected a Grafana default-credentials finding")
	assert.Equal(t, severity.Critical, lf.Info.Severity)
	assert.Equal(t, severity.Certain, lf.Info.Confidence)
	assert.Equal(t, "admin", lf.Metadata["username"])
	assert.Equal(t, "admin", lf.Metadata["password"])
	assert.Contains(t, lf.ExtractedResults, "valid credentials: admin:admin")
	assert.Contains(t, lf.Info.Tags, "default-login")
}

// TestDefaultLogin_NegativeControlRejects: a login endpoint that "succeeds" for
// ANY credentials (a permissive / catch-all matcher) must NOT produce a
// default-credentials finding — the negative control rejects it. The presence
// (exposure) finding is still reported.
func TestDefaultLogin_NegativeControlRejects(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"database":"ok","version":"10.1.0"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/login":
			// Accepts anything — should be caught by the negative control.
			w.Header().Set("Set-Cookie", "grafana_session=abc123; Path=/")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"Logged in"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Nil(t, loginFinding(res, "grafana"), "permissive login endpoint must be rejected by the negative control")
	// The exposure (presence/leak) finding is still expected.
	var exposure bool
	for _, r := range res {
		if r.Metadata["product"] == "grafana" && r.Metadata["default_login"] != true {
			exposure = true
		}
	}
	assert.True(t, exposure, "the Grafana exposure finding should still be reported")
}

// TestDefaultLogin_WrongCredsNoFinding: a confirmed Grafana that rejects the
// default credentials yields the exposure finding but no default-credentials one.
func TestDefaultLogin_WrongCredsNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"database":"ok","version":"10.1.0"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/login":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Invalid username or password"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Nil(t, loginFinding(res, "grafana"), "rejected default creds must not produce a finding")
}

// TestDefaultLogin_RabbitMQBasicAuth: the basic-auth login path (guest/guest)
// against a confirmed RabbitMQ management API.
func TestDefaultLogin_RabbitMQBasicAuth(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/overview":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"rabbitmq_version":"3.12.0","management_version":"3.12.0"}`))
		case "/api/whoami":
			user, pass, ok := r.BasicAuth()
			if ok && user == "guest" && pass == "guest" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"name":"guest","tags":["administrator"]}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	lf := loginFinding(res, "rabbitmq")
	require.NotNil(t, lf, "expected a RabbitMQ default-credentials finding")
	assert.Equal(t, severity.Critical, lf.Info.Severity)
	assert.Equal(t, "guest", lf.Metadata["username"])
}
