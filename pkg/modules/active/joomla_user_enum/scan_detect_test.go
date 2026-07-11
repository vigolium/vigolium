package joomla_user_enum

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// TestScanPerRequest_DetectsRegistrationForm drives the real scan method against
// a host that exposes the Joomla user registration view. The module probes
// /index.php?option=com_users&view=registration and looks for jform[...] field
// markers in a 200 response.
func TestScanPerRequest_DetectsRegistrationForm(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php" && r.URL.Query().Get("view") == "registration" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<form id="member-registration" method="post">` +
				`<input name="jform[name]" type="text">` +
				`<input name="jform[username]" type="text">` +
				`<input name="jform[email1]" type="text"></form>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a user-enumeration finding when the registration form is exposed")
	assert.Contains(t, strings.ToLower(res[0].Info.Name), "joomla")
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
	assert.False(t, res[0].IsFinding(), "registration-form presence does not prove enumeration")
}

func TestParseJoomlaAPIUsersRequiresStructuredResources(t *testing.T) {
	t.Parallel()
	count, labels, ok := parseJoomlaAPIUsers(`{"data":[{"type":"users","id":"1","attributes":{"name":"Alice"}}]}`)
	assert.True(t, ok)
	assert.Equal(t, 1, count)
	assert.Equal(t, []string{"Alice"}, labels)

	_, _, ok = parseJoomlaAPIUsers(`{"message":"type users"}`)
	assert.False(t, ok, "a string marker is not a Joomla users collection")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every vector path
// yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that 404s every vector must not yield a user-enumeration finding")
}
