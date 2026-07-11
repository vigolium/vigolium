package nextjs_version_audit

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

// vulnNextBody fingerprints the host as Next.js (via __NEXT_DATA__) and embeds
// a version string for a release affected by CVE-2025-29927 (>= 11.0.0,
// < 15.2.3).
const vulnNextBody = `<html><body>
<script id="__NEXT_DATA__" type="application/json">{"buildId":"abc"}</script>
<script>var NEXT_VERSION = "15.0.0";</script>
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
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind, "feature-conditioned advisories require applicability confirmation")
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
<script>var NEXT_VERSION = "15.5.0";</script>
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
		`var NEXT_VERSION = "13.5.6";`:   "13.5.6",
		`/*! Next.js v12.0.0 */`:         "12.0.0",
		`{"nextVersion":"15.1.2"}`:       "15.1.2",
		`{"version":"15.1.2"}`:           "",
		"article says Next.js v14.2.1":   "",
		"nothing version related at all": "",
	}
	for body, want := range cases {
		assert.Equal(t, want, extractVersion(body), "body=%q", body)
	}
}

func TestBranchSpecificAdvisoryRanges(t *testing.T) {
	t.Parallel()
	find := func(cve string) advisory {
		for _, adv := range knownAdvisories {
			if adv.cve == cve {
				return adv
			}
		}
		t.Fatalf("missing advisory %s", cve)
		return advisory{}
	}

	middleware := find("CVE-2025-29927")
	for _, version := range []string{"12.3.4", "13.5.8", "14.2.24", "15.2.2"} {
		_, affected := advisoryAffectsVersion(version, middleware)
		assert.True(t, affected, "version=%s", version)
	}
	for _, version := range []string{"12.3.5", "13.5.9", "13.6.0", "14.2.25", "15.2.3"} {
		_, affected := advisoryAffectsVersion(version, middleware)
		assert.False(t, affected, "patched/gap version=%s", version)
	}

	cache := find("CVE-2024-46982")
	for _, version := range []string{"13.4.9", "13.5.7", "13.9.0", "14.2.10"} {
		_, affected := advisoryAffectsVersion(version, cache)
		assert.False(t, affected, "version=%s", version)
	}
	for _, version := range []string{"13.5.1", "13.5.6", "14.0.0", "14.2.9"} {
		_, affected := advisoryAffectsVersion(version, cache)
		assert.True(t, affected, "version=%s", version)
	}

	dos := find("CVE-2024-39693")
	_, affected := advisoryAffectsVersion("14.0.0", dos)
	assert.False(t, affected, "CVE-2024-39693 affects only the reviewed 13.3.1-13.4.x interval")
}

func TestGenericApplicationVersionDoesNotBecomeNextVersion(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>fallback</html>`))
	}))
	defer srv.Close()
	body := `<script id="__NEXT_DATA__" type="application/json">{"buildId":"abc","version":"13.4.0"}</script>`
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", body)
	res, err := New().ScanPerHost(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
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
