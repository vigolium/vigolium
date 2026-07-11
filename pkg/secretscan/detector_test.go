package secretscan

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"testing"

	"github.com/vigolium/vigolium/pkg/secretscan/catalog"
)

func loadExamples(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile("testdata/examples.json")
	if err != nil {
		t.Fatalf("read examples corpus: %v", err)
	}
	var ex map[string][]string
	if err := json.Unmarshal(raw, &ex); err != nil {
		t.Fatalf("parse examples corpus: %v", err)
	}
	// The corpus is stored XOR-obfuscated then base64-encoded so the on-disk
	// fixture isn't a live blob of provider-shaped secrets. Plain base64 is not
	// enough — secret scanners decode base64 and match the plaintext — so the
	// bytes are XOR'd with a fixed key first. See secretgen for the writer.
	for id, vals := range ex {
		for i, v := range vals {
			dec, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				t.Fatalf("decode example %s[%d]: %v", id, i, err)
			}
			for j := range dec {
				dec[j] ^= 0x5A
			}
			ex[id][i] = string(dec)
		}
	}
	return ex
}

// TestCatalogCompiles asserts every catalog rule (including invisible) compiles
// under go-re2 — the runtime engine — not just the RE2 parser used by secretgen.
func TestCatalogCompiles(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	det, err := New(cat, Options{IncludeInvisible: true})
	if err != nil {
		t.Fatal(err)
	}
	if det.RuleCount() < 900 {
		t.Fatalf("expected >=900 rules, got %d", det.RuleCount())
	}
	t.Logf("compiled %d rules (all, incl. invisible)", det.RuleCount())
}

// TestDefaultDetector checks the default (visible-only) detector loads and has a
// substantial rule set.
func TestDefaultDetector(t *testing.T) {
	det, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if det.RuleCount() < 800 {
		t.Fatalf("expected >=800 visible rules, got %d", det.RuleCount())
	}
}

// TestPortedRulesMatchExamples validates the port against each rule's own
// kingfisher examples at two tiers:
//
//   - REGEX fidelity (asserted): does the normalized pattern match the example?
//     This is exactly the check kingfisher's own rule linter runs
//     (src/main.rs: re.is_match(example)), so it is the ground-truth measure of
//     normalization correctness. A hard floor guards against regressions.
//   - PIPELINE detection (informational): does the full Detect() — including the
//     entropy, character-requirement, and benign-placeholder gates — fire? This
//     is intentionally lower: kingfisher's example fixtures are synthetic
//     placeholders (e.g. "...123456789012", low-entropy demo values) that those
//     gates are designed to reject, exactly as kingfisher's own pipeline would.
func TestPortedRulesMatchExamples(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]catalog.Rule, len(cat.Rules))
	for _, r := range cat.Rules {
		byID[r.ID] = r
	}
	examples := loadExamples(t)

	var total, regexHit, pipelineHit int
	var regexFail []string
	for id, exs := range examples {
		r, ok := byID[id]
		if !ok || len(exs) == 0 {
			continue
		}
		total++

		re := regexp.MustCompile(r.Re)
		matchedRegex := false
		for _, ex := range exs {
			if re.MatchString(ex) {
				matchedRegex = true
				break
			}
		}
		if matchedRegex {
			regexHit++
		} else {
			regexFail = append(regexFail, id)
		}

		det, err := New(&catalog.Catalog{Rules: []catalog.Rule{r}}, Options{IncludeInvisible: true})
		if err != nil {
			t.Fatalf("build single-rule detector for %s: %v", id, err)
		}
		for _, ex := range exs {
			if len(det.Detect([]byte(ex))) > 0 {
				pipelineHit++
				break
			}
		}
	}

	if total == 0 {
		t.Fatal("no rules with examples found")
	}
	regexRate := float64(regexHit) / float64(total)
	t.Logf("regex fidelity:      %d/%d rules (%.1f%%)", regexHit, total, 100*regexRate)
	t.Logf("pipeline detection:  %d/%d rules (%.1f%%) [informational — synthetic examples are gated]", pipelineHit, total, 100*float64(pipelineHit)/float64(total))

	sort.Strings(regexFail)
	if len(regexFail) > 0 {
		t.Logf("regex non-matches (%d, faithful edge cases): %v", len(regexFail), regexFail)
	}

	// kingfisher's own linter requires examples to match the regex; we match that
	// bar within a small margin for the handful of RE2-clamped / word-boundary /
	// multiline-proximity fixtures that also fail in kingfisher's engine.
	const regexFloor = 0.98
	if regexRate < regexFloor {
		t.Fatalf("regex fidelity %.1f%% below floor %.0f%%", 100*regexRate, 100*regexFloor)
	}
}

// TestDetectKnownSecrets is an end-to-end smoke test through the default
// detector for a few well-known credential shapes.
func TestDetectKnownSecrets(t *testing.T) {
	det, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		body string
	}{
		{"slack-bot-token", `slack = "xoxb-24938` + `27450-2492` + `837401-Ff8` + `3jdkeExamp` + `le920Slack"`},
		{"stripe-secret", `stripe_key = "sk_live_f0` + `1c79xuuug7` + `yodgzj5ws0` + `h1x2kyvho3"`},
		{"google-oauth-secret", `const SECRET = "GOCSPX-PUi` + `AMWsxZUxAS` + `-wpWpIgb6j` + `6arTD"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ms := det.Detect([]byte(c.body))
			if len(ms) == 0 {
				t.Errorf("expected a secret in %q, got none", c.body)
			}
			for _, m := range ms {
				t.Logf("  %s [%s/%s] secret=%q entropy=%.2f", m.RuleID, m.Source, m.Confidence, m.Secret, m.Entropy)
			}
		})
	}
}

// TestSafelistSuppressesPlaceholders ensures obvious placeholders are dropped.
// The safelist runs against the secret capture only, so fixtures must be
// self-contained placeholders.
func TestSafelistSuppressesPlaceholders(t *testing.T) {
	benign := []string{
		"AKIAIOSFODNN7EXAMPLE", // AKIA…EXAMPLE placeholder
		"classpath://config",   // classpath reference
		"<secretmanager>",      // literal placeholder tag
		"abc123456789def",      // obvious 123456789 sequence
	}
	for _, s := range benign {
		if !isBenign([]byte(s)) {
			t.Errorf("expected %q to be treated as benign", s)
		}
	}
	// A real-looking token must NOT be suppressed.
	if isBenign([]byte("sk_live_f0" + "1c79xuuug7" + "yodgzj5ws0" + "h1x2kyvho3")) {
		t.Error("real-looking Stripe key wrongly flagged benign")
	}
}
