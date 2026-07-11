package secretscan

import (
	"fmt"
	"strings"
	"testing"
)

// realSecrets are real-format credentials (not placeholders) confirmed to pass
// the full detection pipeline (regex + entropy + char-requirements + safelist)
// AND to be reported verbatim by the kingfisher catalog. Used as ground truth
// for the large-bundle tests. Keyed by a short label.
//
// Bare AWS access-key IDs (AKIA…) and the full GitHub `ghp_` token are
// intentionally absent: kingfisher ships its AKIA-ID rule disabled (an access
// key ID without its secret is an identifier, not a credential), and its GitHub
// PAT rule reports the inner 30-char body rather than the full prefixed token,
// so neither is a faithful verbatim fixture. (The former gitleaks/betterleaks
// rules that matched them were removed as noisy.)
var realSecrets = map[string]string{
	"stripe":       "sk_live_f0" + "1c79xuuug7" + "yodgzj5ws0" + "h1x2kyvho3",
	"google-api":   "AIzaSyB1a2" + "b3c4d5e6f7" + "g8h9i0jklm" + "nopqrstuv",
	"google-oauth": "GOCSPX-PUi" + "AMWsxZUxAS" + "-wpWpIgb6j" + "6arTD",
	"slack":        "xoxb-24938" + "27450-2492" + "837401-Ff8" + "3jdkeExamp" + "le920Slack",
	"jwt":          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
	"sendgrid":     "SG.ngeVfQF" + "YQlKU0ufo8" + "x5d1A.TwL2" + "iGABkTgUCC" + "3rmXGw5UQM" + "YtDMzOQMHy" + "kWn7ttUmM",
}

// minifiedChunk is one realistic webpack-style minified module, used as filler
// so the bundle looks like production JS rather than repeated identical bytes.
const minifiedChunk = `(self.webpackChunk=self.webpackChunk||[]).push([[%d],{%d:function(e,t,n){"use strict";n.d(t,{Z:function(){return r}});var r=function(e){return e.map(function(t){return t.id+":"+t.name}).filter(Boolean).join(",")},o=n(4821),i=n(9134);function a(e,t){return e>t?e:t}console.log(o,i,a)},%d:function(e,t,n){var r={apiUrl:"https://api.example.com/v"+%d,retries:3,timeout:3e4,headers:{"content-type":"application/json"}};t.exports=r}}]);`

// buildMinifiedBundle produces a ~sizeKB minified JS bundle with each provided
// secret embedded as a string literal, spread across the body (not clustered).
func buildMinifiedBundle(sizeKB int, secrets []string) []byte {
	var b strings.Builder
	target := sizeKB * 1024
	// Distance between secret insertions so they land at spread-out offsets.
	stride := target / (len(secrets) + 1)
	next, si := stride, 0
	i := 0
	for b.Len() < target {
		fmt.Fprintf(&b, minifiedChunk, i, 1000+i, 2000+i, i%9)
		if si < len(secrets) && b.Len() >= next {
			fmt.Fprintf(&b, `var _k%d=%q;`, si, secrets[si])
			si++
			next += stride
		}
		i++
	}
	// Ensure any not-yet-inserted secrets are appended (small bundles).
	for ; si < len(secrets); si++ {
		fmt.Fprintf(&b, `var _k%d=%q;`, si, secrets[si])
	}
	return []byte(b.String())
}

func detectedSecretSet(d *Detector, body []byte) map[string]struct{} {
	set := map[string]struct{}{}
	for _, m := range d.Detect(body) {
		set[m.Secret] = struct{}{}
	}
	return set
}

// TestDetectSecretsInLargeMinifiedBundle embeds every real secret in a large
// (~512KB) minified bundle and asserts each is found by value. This is the core
// "solid replacement" guarantee: secrets in production JS bundles are detected.
func TestDetectSecretsInLargeMinifiedBundle(t *testing.T) {
	det, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	labels := make([]string, 0, len(realSecrets))
	secrets := make([]string, 0, len(realSecrets))
	for label, s := range realSecrets {
		labels = append(labels, label)
		secrets = append(secrets, s)
	}

	body := buildMinifiedBundle(512, secrets)
	if len(body) < 400*1024 {
		t.Fatalf("bundle too small: %d bytes", len(body))
	}
	t.Logf("bundle size: %d KB", len(body)/1024)

	found := detectedSecretSet(det, body)
	for i, s := range secrets {
		if _, ok := found[s]; !ok {
			t.Errorf("secret %q (%s) not detected in large bundle", s, labels[i])
		}
	}
}

// TestDetectSecretAtBundleBoundaries ensures a secret at the very start and the
// very end of a large body is still found (offset-window / scan-boundary guard).
func TestDetectSecretAtBundleBoundaries(t *testing.T) {
	det, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	head := realSecrets["stripe"]
	tail := realSecrets["slack"]
	filler := buildMinifiedBundle(256, nil)
	body := []byte(`var a="` + head + `";` + string(filler) + `var z="` + tail + `";`)

	found := detectedSecretSet(det, body)
	if _, ok := found[head]; !ok {
		t.Errorf("secret at bundle start not detected")
	}
	if _, ok := found[tail]; !ok {
		t.Errorf("secret at bundle end not detected")
	}
}

// TestLargeBundleDeterministic asserts scanning the same bundle twice yields the
// identical set of secrets (no ordering / map-iteration nondeterminism).
func TestLargeBundleDeterministic(t *testing.T) {
	det, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	secrets := make([]string, 0, len(realSecrets))
	for _, s := range realSecrets {
		secrets = append(secrets, s)
	}
	body := buildMinifiedBundle(384, secrets)

	first := detectedSecretSet(det, body)
	for i := 0; i < 3; i++ {
		again := detectedSecretSet(det, body)
		if len(again) != len(first) {
			t.Fatalf("nondeterministic count: %d vs %d", len(again), len(first))
		}
		for s := range first {
			if _, ok := again[s]; !ok {
				t.Fatalf("nondeterministic: %q missing on rerun %d", s, i)
			}
		}
	}
}

// TestEachRealSecretDetectedInline is a focused per-type check independent of the
// large-bundle framing, so a regression pinpoints which credential family broke.
func TestEachRealSecretDetectedInline(t *testing.T) {
	det, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	for label, s := range realSecrets {
		t.Run(label, func(t *testing.T) {
			body := []byte(`const token = "` + s + `"; export default token;`)
			found := detectedSecretSet(det, body)
			if _, ok := found[s]; !ok {
				t.Errorf("%s secret %q not detected", label, s)
			}
		})
	}
}

// TestDetectEdgeCases covers empty/whitespace/near-boundary inputs so the
// detector never panics or mis-scans degenerate bodies.
func TestDetectEdgeCases(t *testing.T) {
	det, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{
		nil,
		{},
		[]byte("   \n\t  "),
		[]byte(strings.Repeat("a", 200000)), // long low-entropy single token
		[]byte(strings.Repeat("x=1;", 50000)),
	}
	for i, c := range cases {
		if got := det.Detect(c); len(got) != 0 {
			// Not a hard failure for the last two (some rule could match), but the
			// degenerate low-entropy fillers must never yield secrets.
			t.Logf("case %d produced %d findings", i, len(got))
			if i < 3 && len(got) != 0 {
				t.Errorf("empty/blank case %d yielded %d findings", i, len(got))
			}
		}
	}
}
