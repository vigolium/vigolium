package nextjs_version_audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// vulnNextBody fingerprints the host as Next.js (via __NEXT_DATA__) and embeds
// a version string for a release affected by CVE-2025-29927 (>= 11.0.0,
// < 15.2.3).
const vulnNextBody = `<html><body>
<script id="__NEXT_DATA__" type="application/json">{"buildId":"abc"}</script>
<!--! Next.js v15.0.0 -->
</body></html>`

// TestScanPerHost_FlagsVulnerableVersion drives the real scan method against a
// Next.js host whose body discloses an affected version and asserts a CVE
// finding is reported.
func TestScanPerHost_FlagsVulnerableVersion(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", vulnNextBody)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected at least one advisory finding for Next.js 15.0.0")
	assert.Equal(t, ModuleID, res[0].ModuleID)
}

// TestScanPerHost_PatchedVersionNoFinding ensures a Next.js host running a
// patched version yields no advisory finding.
func TestScanPerHost_PatchedVersionNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	patched := `<html><body>
<script id="__NEXT_DATA__" type="application/json">{"buildId":"abc"}</script>
<!--! Next.js v15.5.0 -->
</body></html>`

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", patched)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a patched Next.js version must not match any advisory")
}

// TestScanPerHost_NonNextJSHostSkipped ensures a non-Next.js host is skipped.
func TestScanPerHost_NonNextJSHostSkipped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>plain</body></html>")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that does not look like Next.js must be skipped")
}

// TestExtractVersion exercises the pure version-extraction helper across the
// patterns it supports.
func TestExtractVersion(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"banner Next.js v14.2.1 here":    "14.2.1",
		`var NEXT_VERSION = "13.5.6";`:   "13.5.6",
		`/*! next v12.0.0 */`:            "12.0.0",
		`{"version":"15.1.2"}`:           "15.1.2",
		"nothing version related at all": "",
	}
	for body, want := range cases {
		assert.Equal(t, want, extractVersion(body), "body=%q", body)
	}
}

// TestIsVersionAffected checks the inclusive-lower / exclusive-upper range gate.
func TestIsVersionAffected(t *testing.T) {
	t.Parallel()
	assert.True(t, isVersionAffected("15.0.0", "11.0.0", "15.2.3"))
	assert.True(t, isVersionAffected("11.0.0", "11.0.0", "15.2.3"), "lower bound is inclusive")
	assert.False(t, isVersionAffected("15.2.3", "11.0.0", "15.2.3"), "upper bound is exclusive")
	assert.False(t, isVersionAffected("10.0.0", "11.0.0", "15.2.3"))
	assert.False(t, isVersionAffected("bad", "11.0.0", "15.2.3"))
}

// TestCanProcess covers the custom CanProcess gate: a request needs a response.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))

	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(rr), "no baseline response means not processable")

	withResp := modtest.Response(rr, "text/html", "ok")
	assert.True(t, m.CanProcess(withResp))
}
