package jsonp_callback

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestParseJSONPRequiresJSONArgument(t *testing.T) {
	tests := []struct {
		body string
		ok   bool
	}{
		{`callback({"key":"value"})`, true},
		{`callback([1,2,3]);`, true},
		{`namespace.callback({"key":"value"})`, true},
		{`callback(alert(document.domain))`, false},
		{`callback({key: "not-json"})`, false},
		{`alert(1)`, false},
		{`{"key":"value"}`, false},
		{`bad-name({"key":"value"})`, false},
	}
	for _, test := range tests {
		_, got := parseJSONP(test.body)
		assert.Equal(t, test.ok, got, test.body)
	}
}

func TestContainsSensitiveDataRequiresRealValue(t *testing.T) {
	tests := []struct {
		body string
		want bool
	}{
		{`{"email":"test@example.com"}`, true},
		{`{"access_token":"abc123token"}`, true},
		{`{"password":"secret"}`, true},
		{`{"password":"***","token":"redacted"}`, false},
		{`{"token":null,"email":"email field"}`, false},
		{`{"name":"John","age":30}`, false},
	}
	for _, test := range tests {
		assert.Equal(t, test.want, containsSensitiveData(test.body), test.body)
	}
}

func TestDynamicPublicJSONPIsObservation(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callback := r.URL.Query().Get("callback")
		if callback == "" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"public"}`))
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(callback + `({"name":"public"})`))
	}))
	defer srv.Close()

	ctx := modtest.Response(modtest.Request(t, srv.URL+"/data"), "application/json", `{"name":"public"}`)
	results, err := New().ScanPerRequest(ctx, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
}

func TestSensitivePublicJSONPIsCandidate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callback := r.URL.Query().Get("callback")
		if callback == "" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"public-token-value"}`))
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(callback + `({"access_token":"public-token-value"})`))
	}))
	defer srv.Close()

	ctx := modtest.Response(modtest.Request(t, srv.URL+"/data"), "application/json", `{"access_token":"public-token-value"}`)
	results, err := New().ScanPerRequest(ctx, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.False(t, results[0].IsFinding())
}

func TestCredentialDependentSensitiveJSONPIsFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "session=secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		callback := r.URL.Query().Get("callback")
		if callback == "" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"private-token-value"}`))
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(callback + `({"access_token":"private-token-value"})`))
	}))
	defer srv.Close()

	base := modtest.Request(t, srv.URL+"/data")
	raw, err := httpmsg.AddOrReplaceHeader(base.Request().Raw(), "Cookie", "session=secret")
	require.NoError(t, err)
	req := httpmsg.NewHttpRequestWithService(base.Service(), raw)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: session=secret; Path=/; SameSite=None; Secure; HttpOnly\r\n\r\n{\"access_token\":\"private-token-value\"}"))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)

	results, err := New().ScanPerRequest(ctx, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindFinding, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeImpact, results[0].EvidenceGrade)
	assert.Equal(t, true, results[0].Metadata["credential_free_control_clean"])
}

func TestJSONMIMEWithNosniffIsNotBrowserFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callback := r.URL.Query().Get("callback")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(callback + `({"access_token":"private-token-value"})`))
	}))
	defer srv.Close()

	ctx := modtest.Response(modtest.Request(t, srv.URL+"/data"), "application/json", `{"access_token":"private-token-value"}`)
	results, err := New().ScanPerRequest(ctx, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, false, results[0].Metadata["browser_executable"])
}
