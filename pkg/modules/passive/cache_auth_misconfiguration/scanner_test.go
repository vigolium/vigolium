package cache_auth_misconfiguration

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// buildCtx assembles an HttpRequestResponse from a request path/headers and a
// set of response headers, for driving the passive scan with no live server.
func buildCtx(t *testing.T, path, reqHeaders string, respHeaders []string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n%s\r\n", path, reqHeaders)
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte(rawReq),
	)
	raw := "HTTP/1.1 200 OK\r\n"
	for _, h := range respHeaders {
		raw += h + "\r\n"
	}
	raw += "\r\n<html></html>"
	resp := httpmsg.NewHttpResponse([]byte(raw))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// scan runs the module once and returns the number of findings. A fresh module
// is used so the disk-set dedup never interferes (ScanContext{} has no manager).
func scan(t *testing.T, path, reqHeaders string, respHeaders []string) []interface{} {
	t.Helper()
	res, err := New().ScanPerRequest(buildCtx(t, path, reqHeaders, respHeaders), &modkit.ScanContext{})
	require.NoError(t, err)
	out := make([]interface{}, len(res))
	for i := range res {
		out[i] = res[i]
	}
	return out
}

func TestNew(t *testing.T) {
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.Tentative, m.Confidence())
}

// --- True positive: every gate satisfied -----------------------------------

// A dynamic path, publicly cacheable, served through a shared cache, with a
// genuinely user-specific Set-Cookie and no Vary: Cookie.
func TestScanPerRequest_SensitiveCookieCachedNoVary_Flags(t *testing.T) {
	resp := []string{
		"Cache-Control: public, max-age=60",
		"Set-Cookie: session=abc123; HttpOnly; Secure",
		"CF-Cache-Status: HIT",
	}
	assert.Len(t, scan(t, "/account/profile", "", resp), 1,
		"sensitive cookie + shared cache + cacheable + no Vary must flag")
}

// Authorization-keyed cacheable response through a shared cache, no Vary:Authorization.
func TestScanPerRequest_AuthHeaderCachedNoVary_Flags(t *testing.T) {
	resp := []string{
		"Cache-Control: s-maxage=300",
		"Age: 12",
	}
	assert.Len(t, scan(t, "/api/me", "Authorization: Bearer eyJ\r\n", resp), 1,
		"Authorization + shared cache + cacheable + no Vary:Authorization must flag")
}

// --- Negative: static-asset path by segment (the reported FP) ---------------

// /css/images has no file extension but both segments are static dirs — the
// exact lp.stryker.com false positive this hardening targets.
func TestScanPerRequest_StaticDirSegment_NoFinding(t *testing.T) {
	resp := []string{
		"Cache-Control: public, max-age=60",
		"Set-Cookie: session=abc123",
		"CF-Cache-Status: HIT",
	}
	assert.Empty(t, scan(t, "/css/images", "", resp),
		"a static-asset path (/css/images) must not be flagged")
}

func TestScanPerRequest_StaticExtension_NoFinding(t *testing.T) {
	resp := []string{
		"Cache-Control: public, max-age=60",
		"Set-Cookie: session=abc123",
		"Age: 5",
	}
	assert.Empty(t, scan(t, "/bundles/app.css", "", resp),
		"a path with a static file extension must not be flagged")
}

// --- Negative: no shared-cache signal ---------------------------------------

func TestScanPerRequest_NoCacheIndicator_NoFinding(t *testing.T) {
	resp := []string{
		"Cache-Control: public, max-age=60",
		"Set-Cookie: session=abc123",
	}
	assert.Empty(t, scan(t, "/account/profile", "", resp),
		"origin public Cache-Control without any shared-cache signal must not be flagged")
}

// --- Negative: non-sensitive cookies ----------------------------------------

func TestScanPerRequest_NonSensitiveCookies_NoFinding(t *testing.T) {
	cases := []struct {
		name   string
		cookie string
	}{
		{"lb-affinity-aws", "AWSALB=xyz"},
		{"lb-affinity-bigip", "BIGipServerpool_web=123.456.789"},
		{"analytics-ga", "_ga=GA1.2.3"},
		{"analytics-ga4", "_ga_AB12CD=GS1.1"},
		{"cloudflare-bm", "__cf_bm=token"},
		{"consent", "cookieconsent_status=allow"},
		{"incapsula", "incap_ses_123_456=abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := []string{
				"Cache-Control: public, max-age=60",
				"Set-Cookie: " + tc.cookie,
				"CF-Cache-Status: HIT",
			}
			assert.Empty(t, scan(t, "/landing", "", resp),
				"a known non-sensitive cookie (%s) must not be flagged", tc.cookie)
		})
	}
}

// A sensitive cookie alongside non-sensitive ones is still flagged.
func TestScanPerRequest_MixedCookies_Flags(t *testing.T) {
	resp := []string{
		"Cache-Control: public, max-age=60",
		"Set-Cookie: _ga=GA1.2.3",
		"Set-Cookie: auth_token=secret",
		"X-Cache: HIT",
	}
	res := scan(t, "/dashboard", "", resp)
	assert.Len(t, res, 1, "a sensitive cookie mixed with analytics cookies must flag")
}

// --- Negative: correct config / not cacheable -------------------------------

func TestScanPerRequest_HasVaryCookie_NoFinding(t *testing.T) {
	resp := []string{
		"Cache-Control: public, max-age=60",
		"Set-Cookie: session=abc123",
		"Vary: Cookie",
		"CF-Cache-Status: HIT",
	}
	assert.Empty(t, scan(t, "/account/profile", "", resp),
		"a response that correctly varies on Cookie must not be flagged")
}

func TestScanPerRequest_PrivateNotCacheable_NoFinding(t *testing.T) {
	resp := []string{
		"Cache-Control: private, max-age=60",
		"Set-Cookie: session=abc123",
		"CF-Cache-Status: MISS",
	}
	assert.Empty(t, scan(t, "/account/profile", "", resp),
		"a private (non-cacheable) response must not be flagged")
}

func TestScanPerRequest_NoUserIndicators_NoFinding(t *testing.T) {
	resp := []string{
		"Cache-Control: public, max-age=60",
		"Age: 30",
	}
	assert.Empty(t, scan(t, "/blog/post-1", "", resp),
		"a cacheable response with no cookie and no Authorization must not be flagged")
}

// --- Unit coverage for the new helpers --------------------------------------

func TestIsNonSensitiveCookie(t *testing.T) {
	nonSensitive := []string{
		"AWSALB", "awsalb", "BIGipServerpool_x", "_ga", "_ga_ABCDEF",
		"__cf_bm", "cf_clearance", "incap_ses_1_2", "_gid", "cookieconsent",
		"__utma", "_hjSessionUser_1",
	}
	for _, c := range nonSensitive {
		assert.True(t, isNonSensitiveCookie(c), "%q should be non-sensitive", c)
	}
	sensitive := []string{"session", "auth_token", "jwt", "sid", "PHPSESSID", "user"}
	for _, c := range sensitive {
		assert.False(t, isNonSensitiveCookie(c), "%q should be treated as sensitive", c)
	}
}

func TestFirstSensitiveCookie(t *testing.T) {
	assert.Equal(t, "", firstSensitiveCookie([]string{"_ga=1", "AWSALB=2; Path=/"}))
	assert.Equal(t, "session", firstSensitiveCookie([]string{"_ga=1", "session=abc; HttpOnly"}))
	assert.Equal(t, "", firstSensitiveCookie(nil))
}

func TestCookieName(t *testing.T) {
	assert.Equal(t, "session", cookieName("session=abc123; Path=/; HttpOnly"))
	assert.Equal(t, "_ga", cookieName("_ga=GA1.2.3"))
	assert.Equal(t, "", cookieName("malformed-no-equals"))
}

func TestIsCacheable(t *testing.T) {
	tests := []struct {
		cc   string
		want bool
	}{
		{"public, max-age=3600", true},
		{"s-maxage=600", true},
		{"private, max-age=3600", false},
		{"no-store", false},
		{"no-store, public", false},
		{"max-age=0", false},
		{"public, no-store", false},
	}
	for _, tt := range tests {
		got := isCacheable(tt.cc)
		if got != tt.want {
			t.Errorf("isCacheable(%q) = %v, want %v", tt.cc, got, tt.want)
		}
	}
}
