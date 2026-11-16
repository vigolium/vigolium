package infra

import (
	"io"
	"net/http"
	"strings"
	"testing"

	httputil "github.com/projectdiscovery/utils/http"
)

// fillResponseChain builds a filled *httputil.ResponseChain from a status,
// header set, and body, mirroring what the requester hands a module.
func fillResponseChain(t *testing.T, status int, header http.Header, body string) *httputil.ResponseChain {
	t.Helper()
	if header == nil {
		header = http.Header{}
	}
	resp := &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	rc := httputil.NewResponseChain(resp, 0)
	if err := rc.Fill(); err != nil {
		t.Fatalf("fill response chain: %v", err)
	}
	t.Cleanup(rc.Close)
	return rc
}

// TestValidate_ChallengeAndBlockPages exercises the shared block detector,
// focusing on the status-independent challenge detection added to stop a WAF/CDN
// interstitial — which an edge often serves with an ordinary 200 — from being
// read as an application response by a body-matching module. The motivating
// false positive was a Cloudflare challenge whose random per-request tokens
// matched the TiDB error signature and surfaced as Critical/Certain SQLi.
func TestValidate_ChallengeAndBlockPages(t *testing.T) {
	v := GetBlockDetectionValidator()

	tests := []struct {
		name      string
		status    int
		header    http.Header
		body      string
		wantBlock bool
	}{
		{
			name:      "clean 200 application response",
			status:    200,
			body:      `{"status":"ok","rows":[]}`,
			wantBlock: false,
		},
		{
			name:      "429 rate limited",
			status:    429,
			body:      "slow down",
			wantBlock: true,
		},
		{
			// Cloudflare names itself on every response it proxies: an
			// application's own 403/503 behind it is the application answering.
			name:      "403 behind cloudflare without its block page",
			status:    403,
			header:    http.Header{"Server": {"cloudflare"}, "Cf-Ray": {"8a1b2c3d4e5f-AMS"}},
			body:      `{"error":"forbidden"}`,
			wantBlock: false,
		},
		{
			name:      "503 behind cloudflare without its block page",
			status:    503,
			header:    http.Header{"Server": {"cloudflare"}},
			body:      `{"error":"maintenance"}`,
			wantBlock: false,
		},
		{
			name:      "403 behind akamai without its block page",
			status:    403,
			header:    http.Header{"Server": {"AkamaiGHost"}},
			body:      `{"error":"insufficient_scope"}`,
			wantBlock: false,
		},
		{
			name:      "403 cloudflare block page",
			status:    403,
			header:    http.Header{"Server": {"cloudflare"}},
			body:      `<title>Attention Required! | Cloudflare</title><div id="cf-error-details">`,
			wantBlock: true,
		},
		{
			name:      "403 ELB default template",
			status:    403,
			header:    http.Header{"Server": {"awselb/2.0"}},
			body:      "<html><center><h1>403 Forbidden</h1></center></html>",
			wantBlock: true,
		},
		{
			// The same template without the ELB header is nginx's own 403.
			name:      "403 nginx default page is not an edge block",
			status:    403,
			header:    http.Header{"Server": {"nginx"}},
			body:      "<html><center><h1>403 Forbidden</h1></center></html>",
			wantBlock: false,
		},
		{
			name:      "200 challenge via Cf-Mitigated header",
			status:    200,
			header:    http.Header{"Cf-Mitigated": {"challenge"}},
			body:      "<html><title>Just a moment...</title></html>",
			wantBlock: true,
		},
		{
			name:      "200 challenge via cdn-cgi challenge-platform body marker",
			status:    200,
			body:      `<script src="/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1"></script>`,
			wantBlock: true,
		},
		{
			name:      "202 challenge via _cf_chl_opt body marker",
			status:    202,
			body:      `<script>window._cf_chl_opt = {cRay:'a05dba9dfb7deb9e'};</script>`,
			wantBlock: true,
		},
		{
			name:      "200 managed challenge noscript text",
			status:    200,
			body:      `<noscript><span>Enable JavaScript and cookies to continue</span></noscript>`,
			wantBlock: true,
		},
		{
			name:      "200 Incapsula interstitial",
			status:    200,
			body:      `Request unsuccessful. Incapsula incident ID: 1234-5678`,
			wantBlock: true,
		},
		{
			name:   "200 page embedding a real Turnstile widget is not a block",
			status: 200,
			body: `<div class="cf-turnstile" data-sitekey="0xAAA"></div>` +
				`<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>`,
			wantBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := fillResponseChain(t, tt.status, tt.header, tt.body)
			err := v.Validate(rc)
			if (err != nil) != tt.wantBlock {
				t.Fatalf("Validate() err = %v, wantBlock = %v", err, tt.wantBlock)
			}
		})
	}
}

// TestIsErrorSurfaceStatus pins the companion gate to IsBlockedResponse: it
// rejects the no-handler-ran statuses (404 + any 3xx) that let a catch-all/SPA
// 404 shell or a redirect interstitial feed page noise into a body-matching
// module, while accepting the statuses on which a genuine server-side leak can
// ride (2xx, 5xx, and non-404 4xx like 400/422 the app returns with output).
func TestIsErrorSurfaceStatus(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{200, true},
		{201, true},
		{400, true},
		{422, true},
		{500, true},
		{502, true},
		{404, false},
		{301, false},
		{302, false},
		{307, false},
		{308, false},
	}
	for _, c := range cases {
		rc := fillResponseChain(t, c.status, nil, "body")
		if got := IsErrorSurfaceStatus(rc); got != c.want {
			t.Errorf("IsErrorSurfaceStatus(%d) = %v, want %v", c.status, got, c.want)
		}
	}
	if IsErrorSurfaceStatus(nil) {
		t.Error("IsErrorSurfaceStatus(nil) = true, want false")
	}
}

// TestIsBlockedOrThrottled pins the throttle/edge gate the Rails route probes
// use: rate-limit and edge-block statuses count, auth walls and 5xx do not
// (callers gate those themselves), and a vendor challenge counts on any status.
func TestIsBlockedOrThrottled(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{200, false},
		{401, false},
		{403, false},
		{404, false},
		{500, false},
		{503, false},
		{408, true},
		{425, true},
		{429, true},
		{451, true},
	}
	for _, c := range cases {
		rc := fillResponseChain(t, c.status, nil, "body")
		if got := IsBlockedOrThrottled(rc); got != c.want {
			t.Errorf("IsBlockedOrThrottled(%d) = %v, want %v", c.status, got, c.want)
		}
	}
	challenge := fillResponseChain(t, 200, http.Header{"Cf-Mitigated": {"challenge"}}, "<html>Just a moment...</html>")
	if !IsBlockedOrThrottled(challenge) {
		t.Error("Cloudflare challenge page on 200 should count as blocked")
	}
	// A CDN in the path is not a block: the application's own 403 behind
	// Cloudflare reaches the module; Cloudflare's block page does not.
	appBehindCDN := fillResponseChain(t, 403, http.Header{"Server": {"cloudflare"}, "Cf-Ray": {"8a1b-AMS"}}, `{"error":"forbidden"}`)
	if IsBlockedOrThrottled(appBehindCDN) {
		t.Error("application 403 behind Cloudflare counted as an edge block")
	}
	edgePage := fillResponseChain(t, 403, http.Header{"Server": {"cloudflare"}}, "error code: 1020")
	if !IsBlockedOrThrottled(edgePage) {
		t.Error("Cloudflare 1020 block page should count as blocked")
	}
	if IsBlockedOrThrottled(nil) {
		t.Error("IsBlockedOrThrottled(nil) = true, want false")
	}
}
