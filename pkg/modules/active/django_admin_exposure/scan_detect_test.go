package django_admin_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// TestScanPerRequest_DetectsDjangoAdmin drives the real scan method against a
// host whose /admin/ serves the Django administration login page. The random
// 404 fingerprint path returns a distinct not-found body.
func TestScanPerRequest_DetectsDjangoAdmin(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") {
			_, _ = w.Write([]byte("<html><head><title>Log in | Django site admin</title></head>" +
				"<body class=\"login\"><h1>Django administration</h1>" +
				"<form><input id=\"id_username\"><input id=\"id_password\">" +
				"<input name=\"csrfmiddlewaretoken\"></form></body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 Not Found generic distinct body padding padding</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "one Django admin surface should produce one observation")
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, res[0].EvidenceGrade)
	assert.False(t, res[0].IsFinding())
	assert.Equal(t, true, res[0].Metadata["credential_free"])
}

func TestScanPerRequest_AuthenticatedAdminIsNotCalledPublic(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") && r.Header.Get("Cookie") == "session=admin" {
			_, _ = w.Write([]byte(`<h1>Django administration</h1><input id="id_username">`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	rr := modtest.Request(t, srv.URL+"/")
	raw, err := httpmsg.AddOrReplaceHeader(rr.Request().Raw(), "Cookie", "session=admin")
	require.NoError(t, err)
	rr = httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(rr.Service(), raw), modtest.Response(rr, "text/html", "ok").Response())

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an admin page visible only with the captured session is not public exposure")
}

// TestScanPerRequest_NoFalsePositive ensures a host returning 404 for the admin
// paths yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 Not Found</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host without a Django admin must not yield a finding")
}
