package secret_detect

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// bundleSecrets are real-format credentials confirmed to pass the full pipeline
// and be reported verbatim by the kingfisher catalog, used to prove the passive
// module finds secrets embedded in production JS. (Bare AWS access-key IDs and
// the full GitHub `ghp_` token are omitted — see the note in
// pkg/secretscan/bundle_test.go realSecrets.)
var bundleSecrets = map[string]string{
	"stripe":   "sk_live_f0" + "1c79xuuug7" + "yodgzj5ws0" + "h1x2kyvho3",
	"slack":    "xoxb-24938" + "27450-2492" + "837401-Ff8" + "3jdkeExamp" + "le920Slack",
	"sendgrid": "SG.ngeVfQF" + "YQlKU0ufo8" + "x5d1A.TwL2" + "iGABkTgUCC" + "3rmXGw5UQM" + "YtDMzOQMHy" + "kWn7ttUmM",
}

// bigMinifiedJS builds a ~sizeKB minified webpack-style bundle with each secret
// embedded as a string literal, spread across the body.
func bigMinifiedJS(sizeKB int, secrets []string) string {
	var b strings.Builder
	chunk := `(self.webpackChunk=self.webpackChunk||[]).push([[%d],{%d:function(e,t,n){"use strict";var r=n(482),o=n(913);function i(e){return e>0?e:0}t.exports={run:i,dep:[r,o]}}}]);`
	target := sizeKB * 1024
	stride := target / (len(secrets) + 1)
	next, si, i := stride, 0, 0
	for b.Len() < target {
		fmt.Fprintf(&b, chunk, i, 1000+i)
		if si < len(secrets) && b.Len() >= next {
			fmt.Fprintf(&b, `var _s%d="%s";`, si, secrets[si])
			si++
			next += stride
		}
		i++
	}
	for ; si < len(secrets); si++ {
		fmt.Fprintf(&b, `var _s%d="%s";`, si, secrets[si])
	}
	return b.String()
}

// TestModule_DetectsSecretsInJSBundle is the headline module test: a large
// minified JS bundle response yields a finding for every embedded secret.
func TestModule_DetectsSecretsInJSBundle(t *testing.T) {
	m := New()
	secrets := make([]string, 0, len(bundleSecrets))
	for _, s := range bundleSecrets {
		secrets = append(secrets, s)
	}
	body := bigMinifiedJS(300, secrets)
	require.Greater(t, len(body), 250*1024, "bundle should be large")

	ctx := makeHTTPCtx("application/javascript", body)
	require.True(t, m.CanProcess(ctx))

	findings, err := m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	got := map[string]bool{}
	for _, f := range findings {
		for _, r := range f.ExtractedResults {
			got[r] = true
		}
	}
	for label, s := range bundleSecrets {
		assert.True(t, got[s], "secret %s (%q) missing from bundle findings", label, s)
	}
}

// TestModule_EvidenceIsWindowed asserts a finding from a huge bundle carries a
// compact windowed response, not the whole multi-hundred-KB body.
func TestModule_EvidenceIsWindowed(t *testing.T) {
	m := New()
	body := bigMinifiedJS(300, []string{bundleSecrets["stripe"]})
	ctx := makeHTTPCtx("application/javascript", body)

	findings, err := m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	f := findings[0]
	assert.NotEmpty(t, f.Response, "finding must carry response evidence")
	assert.Less(t, len(f.Response), len(body)/4,
		"evidence should be windowed (%d) far smaller than the %d-byte bundle", len(f.Response), len(body))
	assert.Contains(t, f.Response, bundleSecrets["stripe"], "windowed evidence must include the secret")
}

// TestModule_DedupAcrossPasses asserts the same secret on the same URL is
// reported once even when the response is scanned again within one scan
// (discovery + spider + dynamic-assessment all re-observe the same page). The
// dedup is scan-scoped: it hangs off the per-run dedup Manager on the ScanContext.
func TestModule_DedupAcrossPasses(t *testing.T) {
	m := New()
	mgr := dedup.NewManager()
	defer mgr.Close()
	sc := &modkit.ScanContext{DedupManager: mgr}

	body := `const k = "` + bundleSecrets["stripe"] + `";`
	ctx := makeHTTPCtx("application/javascript", body)

	first, err := m.ScanPerRequest(ctx, sc)
	require.NoError(t, err)
	require.Len(t, first, 1, "first pass should report the secret once")

	second, err := m.ScanPerRequest(ctx, sc)
	require.NoError(t, err)
	assert.Empty(t, second, "re-scanning the same secret/URL must not duplicate the finding")
}

// TestModule_DedupIsScanScoped asserts the dedup state does NOT leak across
// scans: the SAME registry-singleton module, run under a fresh dedup Manager (a
// new scan/project), reports a secret it already reported in an earlier scan.
// This is the isolation the former process-wide map lacked.
func TestModule_DedupIsScanScoped(t *testing.T) {
	m := New()
	body := `const k = "` + bundleSecrets["stripe"] + `";`
	ctx := makeHTTPCtx("application/javascript", body)

	mgr1 := dedup.NewManager()
	first, err := m.ScanPerRequest(ctx, &modkit.ScanContext{DedupManager: mgr1})
	require.NoError(t, err)
	require.Len(t, first, 1, "scan 1 should report the secret")
	mgr1.Close()

	mgr2 := dedup.NewManager()
	defer mgr2.Close()
	second, err := m.ScanPerRequest(ctx, &modkit.ScanContext{DedupManager: mgr2})
	require.NoError(t, err)
	assert.Len(t, second, 1, "a new scan must re-report the secret — dedup must not survive across scans")
}

// TestModule_PlaceholderSuppressed ensures obvious placeholder credentials
// (safelist) are not reported.
func TestModule_PlaceholderSuppressed(t *testing.T) {
	m := New()
	body := `aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"; // sample only`
	ctx := makeHTTPCtx("application/javascript", body)

	findings, err := m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	for _, f := range findings {
		for _, r := range f.ExtractedResults {
			assert.NotEqual(t, "AKIAIOSFODNN7EXAMPLE", r, "placeholder AKIA…EXAMPLE must be suppressed")
		}
	}
}

// TestModule_SeverityTierSplit checks the rule identity drives severity: a plain
// secret matched by a curated high-confidence (trusted) kingfisher rule grades
// High/Firm, while a recognisable NAMED provider family matched by a
// medium-confidence rule (the vast majority) grades High/Tentative — surfaced at
// full weight for triage, its Tentative confidence flagging it is unverified. Only
// the generic, family-less matchers grade Suspect (covered by
// TestSecretFindingSeverity's generic tier).
func TestModule_SeverityTierSplit(t *testing.T) {
	cases := []struct {
		name     string
		secret   string
		wantSev  severity.Severity
		wantConf severity.Confidence
	}{
		// Apify API token — a high-confidence (trusted) kingfisher rule.
		{"high-confidence rule grades High/Firm", "apify_api_" + "NcjXcxEz2X" + "L1irjppyWS" + "HvjghalQOd" + "1LXOHv", severity.High, severity.Firm},
		// Stripe live secret key — a named provider family on a medium-confidence rule.
		{"named medium-confidence family grades High/Tentative", bundleSecrets["stripe"], severity.High, severity.Tentative},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := New()
			body := `var token = "` + c.secret + `";`
			ctx := makeHTTPCtx("application/javascript", body)

			findings, err := m.ScanPerRequest(ctx, nil)
			require.NoError(t, err)
			require.NotEmpty(t, findings)

			var found bool
			for _, f := range findings {
				if len(f.ExtractedResults) > 0 && f.ExtractedResults[0] == c.secret {
					found = true
					assert.Equal(t, c.wantSev, f.Info.Severity)
					assert.Equal(t, c.wantConf, f.Info.Confidence)
					assert.True(t, secretTag(f.Info.Tags), "finding should be tagged as secret")
				}
			}
			assert.True(t, found, "%s should be reported", c.secret)
		})
	}
}

func secretTag(tags []string) bool {
	for _, t := range tags {
		if t == "secret" {
			return true
		}
	}
	return false
}

// TestModule_CleanBundleNoFlood guards against false-positive floods: a large
// minified bundle with NO real credentials (only code + content-hash chunk ids)
// should produce very few findings.
func TestModule_CleanBundleNoFlood(t *testing.T) {
	m := New()
	// Minified code plus a webpack content-hash manifest of many same-width hex ids
	// — a classic false-positive trap for entropy-only detectors.
	var b strings.Builder
	b.WriteString(bigMinifiedJS(200, nil))
	b.WriteString(`var __manifest={`)
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, `"%d":"%08x%08x",`, i, i*2654435761, i*40503)
	}
	b.WriteString(`};`)
	ctx := makeHTTPCtx("application/javascript", b.String())

	findings, err := m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(findings), 3,
		"clean bundle should not flood findings, got %d: %v", len(findings), findingValues(findings))
}

// TestModule_RealMinifiedJQueryNoFlood scans real minified jQuery (a large,
// entropy-dense, secret-free production file) and asserts the detector + FP
// guards do not flood findings. This is the strongest false-positive signal:
// 1,200+ rules over 80KB of real minified code must stay quiet.
func TestModule_RealMinifiedJQueryNoFlood(t *testing.T) {
	body, err := os.ReadFile("testdata/jquery.min.js")
	require.NoError(t, err)
	require.Greater(t, len(body), 50*1024, "expected a large minified fixture")

	m := New()
	ctx := makeHTTPCtx("application/javascript", string(body))
	require.True(t, m.CanProcess(ctx))

	findings, err := m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	assert.LessOrEqualf(t, len(findings), 3,
		"real minified jQuery should not flood findings, got %d: %v", len(findings), findingValues(findings))
}

// TestModule_SecretInRealMinifiedJQuery injects a real secret into genuine
// minified jQuery and confirms it is detected amid real-world code — a true
// positive in a realistic large-bundle context.
func TestModule_SecretInRealMinifiedJQuery(t *testing.T) {
	body, err := os.ReadFile("testdata/jquery.min.js")
	require.NoError(t, err)

	const secret = "sk_live_f0" + "1c79xuuug7" + "yodgzj5ws0" + "h1x2kyvho3"
	injected := string(body) + `;window.__stripe="` + secret + `";`

	m := New()
	ctx := makeHTTPCtx("application/javascript", injected)
	findings, err := m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)

	var found bool
	for _, f := range findings {
		if len(f.ExtractedResults) > 0 && f.ExtractedResults[0] == secret {
			found = true
		}
	}
	assert.True(t, found, "secret injected into real minified jQuery must be detected")
}

func findingValues(fs []*output.ResultEvent) []string {
	var out []string
	for _, f := range fs {
		if len(f.ExtractedResults) > 0 {
			out = append(out, f.ExtractedResults[0])
		}
	}
	return out
}
