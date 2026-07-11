package secret_detect

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/secretscan"
)

// webpackBundleWithSecret is a minified webpack-5-style bundle (multiple modules,
// single line) with a real-format Stripe key embedded in an inner module's string
// literal — the kind of thing beautify (webcrack) unpacks into readable modules.
func webpackBundleWithSecret(secret string) []byte {
	return []byte(`(()=>{"use strict";var e={100:(e,t,r)=>{const n=r(200);` +
		`t.pay=function(a){return fetch(n.base+"/charge",{method:"POST",headers:{Authorization:"Bearer ` + secret + `","Content-Type":"application/json"},body:JSON.stringify(a)}).then(x=>x.json())}},` +
		`200:(e,t)=>{t.base="https://api.example.com/v3";t.timeout=3e4;t.retries=2},` +
		`300:(e,t,r)=>{const n=r(200);t.status=function(){return fetch(n.base+"/status")}}},t={};` +
		`function r(n){var a=t[n];if(void 0!==a)return a.exports;var o=t[n]={exports:{}};` +
		`return e[n](o,o.exports,r),o.exports}var n=r(100),s=r(300);console.log(n,s)})();`)
}

func detectsSecret(det *secretscan.Detector, body []byte, secret string) bool {
	for _, m := range det.Detect(body) {
		if m.Secret == secret {
			return true
		}
	}
	return false
}

// TestSecretScanOnBeautifiedBundle verifies the secret detector and jstangle
// beautify compose cleanly: a secret embedded in a minified webpack bundle is
// detected in the RAW bundle AND still detected after jstangle un-minifies /
// unpacks it. This guards against beautify silently dropping or mangling a
// credential (e.g. via string transforms) if a future pipeline scans beautified
// output. Skips when the embedded jstangle binary is unavailable (e.g. a bare
// checkout without `make deps`).
func TestSecretScanOnBeautifiedBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping jstangle beautify integration test in -short mode")
	}
	const secret = "sk_live_f0" + "1c79xuuug7" + "yodgzj5ws0" + "h1x2kyvho3"
	bundle := webpackBundleWithSecret(secret)

	svc, err := jstangle.NewService(nil)
	if err != nil {
		t.Skipf("jstangle service unavailable: %v", err)
	}
	defer func() { _ = svc.Close() }()

	res, err := svc.ScanWithOptions(context.Background(), bundle, jstangle.ScanOptions{Beautify: true})
	if err != nil || res == nil || !res.HasBeautified() {
		t.Skipf("jstangle beautify produced no output (embedded binary likely missing); err=%v", err)
	}
	beautified := res.Beautified.Content
	// Sanity: the bundle was genuinely unminified into multiple lines/modules.
	require.Greater(t, strings.Count(beautified, "\n"), 3, "beautified output should be multi-line")
	t.Logf("beautify: format=%q modules=%d, %d bytes -> %d bytes",
		res.Beautified.Format, res.Beautified.ModuleCount, len(bundle), len(beautified))

	det, err := secretscan.Default()
	require.NoError(t, err)

	assert.True(t, detectsSecret(det, bundle, secret),
		"secret must be detectable in the raw minified bundle")
	assert.True(t, detectsSecret(det, []byte(beautified), secret),
		"secret must survive jstangle beautify and remain detectable")
}

// TestSecretScanParityRawVsBeautified checks that beautify does not lose any of a
// set of embedded secrets: every secret found in the raw bundle is still found
// after beautify (no regressions from the un-minify transform).
func TestSecretScanParityRawVsBeautified(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping jstangle beautify integration test in -short mode")
	}
	secrets := []string{
		"sk_live_f0" + "1c79xuuug7" + "yodgzj5ws0" + "h1x2kyvho3",                              // stripe
		"xoxb-24938" + "27450-2492" + "837401-Ff8" + "3jdkeExamp" + "le920Slack",                    // slack
		"SG.ngeVfQF" + "YQlKU0ufo8" + "x5d1A.TwL2" + "iGABkTgUCC" + "3rmXGw5UQM" + "YtDMzOQMHy" + "kWn7ttUmM", // sendgrid
	}
	// Embed all secrets across modules of one webpack bundle. Each module carries a
	// real function body so the bundle clears jstangle's "worth beautifying" gate.
	bundle := []byte(`(()=>{"use strict";var e={` +
		`100:(e,t,r)=>{const n=r(200);t.stripeKey="` + secrets[0] + `";` +
		`t.charge=function(amt){return fetch(n.base+"/charge",{method:"POST",headers:{Authorization:"Bearer "+t.stripeKey},body:JSON.stringify({amt:amt})}).then(x=>x.json())}},` +
		`200:(e,t)=>{t.base="https://api.example.com/v3";t.timeout=3e4;t.retries=2;t.slackToken="` + secrets[1] + `";t.region="us-east-1"},` +
		`300:(e,t,r)=>{const n=r(200);t.sgKey="` + secrets[2] + `";t.api="https://api.sendgrid.com/v3";` +
		`t.send=function(u){return fetch(t.api+"/mail/send",{method:"POST",headers:{Authorization:"Bearer "+t.sgKey}}).then(x=>x.json())}}},t={};` +
		`function r(n){var a=t[n];if(void 0!==a)return a.exports;var o=t[n]={exports:{}};` +
		`return e[n](o,o.exports,r),o.exports}var a=r(100),b=r(200),c=r(300);console.log(a,b,c)})();`)

	svc, err := jstangle.NewService(nil)
	if err != nil {
		t.Skipf("jstangle service unavailable: %v", err)
	}
	defer func() { _ = svc.Close() }()

	res, err := svc.ScanWithOptions(context.Background(), bundle, jstangle.ScanOptions{Beautify: true})
	if err != nil || res == nil || !res.HasBeautified() {
		t.Skipf("jstangle beautify produced no output (embedded binary likely missing); err=%v", err)
	}

	det, err := secretscan.Default()
	require.NoError(t, err)

	for _, s := range secrets {
		rawOK := detectsSecret(det, bundle, s)
		beautOK := detectsSecret(det, []byte(res.Beautified.Content), s)
		assert.True(t, rawOK, "secret %q should be found in raw bundle", s)
		if rawOK {
			assert.True(t, beautOK, "secret %q found in raw bundle must survive beautify", s)
		}
	}
}
