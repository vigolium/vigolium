package suspect_transform

import (
	"strings"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestNew(t *testing.T) {
	module := New()

	if module.ID() != "active-suspect-transform" {
		t.Errorf("expected ID 'active-suspect-transform', got %s", module.ID())
	}

	if module.Name() != "Suspect Transform Detection" {
		t.Errorf("expected Name 'Suspect Transform Detection', got %s", module.Name())
	}

	if len(module.checks) != 12 {
		t.Errorf("expected 12 checks, got %d", len(module.checks))
	}
}

func TestRandomString(t *testing.T) {
	s1 := randomString(6)
	s2 := randomString(6)

	if len(s1) != 6 {
		t.Errorf("expected length 6, got %d", len(s1))
	}

	if s1 == s2 {
		t.Error("random strings should be different")
	}
}

func TestDetectQuoteConsumption(t *testing.T) {
	probe, expects := detectQuoteConsumption()

	if !strings.Contains(probe, "''") {
		t.Errorf("probe should contain double quotes, got %s", probe)
	}

	if len(expects) != 1 {
		t.Errorf("expected 1 expect, got %d", len(expects))
	}

	if !strings.Contains(expects[0], "'") || strings.Contains(expects[0], "''") {
		t.Errorf("expect should contain single quote but not double, got %s", expects[0])
	}
}

func TestDetectArithmetic(t *testing.T) {
	probe, expects := detectArithmetic()

	if !strings.Contains(probe, "*") {
		t.Errorf("probe should contain multiplication, got %s", probe)
	}

	if len(expects) != 1 {
		t.Errorf("expected 1 expect, got %d", len(expects))
	}

	// The result should be a number (product of two numbers 99-9999)
	if len(expects[0]) < 5 {
		t.Errorf("expected product to have at least 5 digits, got %s", expects[0])
	}
}

func TestDetectExpression(t *testing.T) {
	probe, _ := detectExpression()

	if !strings.HasPrefix(probe, "${") || !strings.HasSuffix(probe, "}") {
		t.Errorf("probe should be wrapped in ${}, got %s", probe)
	}
}

func TestDetectRazorExpression(t *testing.T) {
	probe, _ := detectRazorExpression()

	if !strings.HasPrefix(probe, "@(") || !strings.HasSuffix(probe, ")") {
		t.Errorf("probe should be wrapped in @(), got %s", probe)
	}
}

func TestDetectAltExpression(t *testing.T) {
	probe, _ := detectAltExpression()

	if !strings.HasPrefix(probe, "%{") || !strings.HasSuffix(probe, "}") {
		t.Errorf("probe should be wrapped in %%{}, got %s", probe)
	}
}

func TestDetectUnicodeNormalisation(t *testing.T) {
	probe, expects := detectUnicodeNormalisation()

	if !strings.Contains(probe, "\u212a") {
		t.Errorf("probe should contain KELVIN SIGN, got %s", probe)
	}

	if !strings.Contains(expects[0], "K") {
		t.Errorf("expect should contain K, got %s", expects[0])
	}
}

func TestDetectUnicodeByteTruncation(t *testing.T) {
	probe, expects := detectUnicodeByteTruncation()

	if !strings.Contains(probe, "\ucf7b") {
		t.Errorf("probe should contain U+CF7B, got %s", probe)
	}

	if !strings.Contains(expects[0], "{") {
		t.Errorf("expect should contain {, got %s", expects[0])
	}
}

func TestDetectUnicodeCaseConversion(t *testing.T) {
	probe, expects := detectUnicodeCaseConversion()

	if !strings.Contains(probe, "\u0131") {
		t.Errorf("probe should contain DOTLESS I, got %s", probe)
	}

	if !strings.Contains(expects[0], "I") {
		t.Errorf("expect should contain I, got %s", expects[0])
	}
}

func TestDetectURLDecodeError(t *testing.T) {
	probe, expects := detectURLDecodeError()

	if !strings.Contains(probe, "\u0391") {
		t.Errorf("probe should contain GREEK ALPHA, got %s", probe)
	}

	if len(expects) != 1 {
		t.Errorf("expected 1 expect, got %d", len(expects))
	}
}

func TestDetectUnicodeCombiningDiacritic(t *testing.T) {
	probe, expects := detectUnicodeCombiningDiacritic()

	if !strings.HasPrefix(probe, "\u0338") {
		t.Errorf("probe should start with COMBINING LONG SOLIDUS OVERLAY, got %s", probe)
	}

	if !strings.HasPrefix(expects[0], "\u226f") {
		t.Errorf("expect should start with NOT GREATER-THAN, got %s", expects[0])
	}
}

func TestBuildChecks(t *testing.T) {
	checks := buildChecks()

	expectedNames := []string{
		"quote consumption",
		"arithmetic evaluation",
		"expression evaluation",
		"template evaluation",
		"EL evaluation",
		"unicode normalisation",
		"url decoding error",
		"unicode byte truncation",
		"unicode case conversion",
		"unicode combining diacritic",
		"Jinja2 template evaluation",
		"Twig template evaluation",
	}

	if len(checks) != len(expectedNames) {
		t.Errorf("expected %d checks, got %d", len(expectedNames), len(checks))
	}

	for i, check := range checks {
		if check.Name != expectedNames[i] {
			t.Errorf("expected check %d to be %s, got %s", i, expectedNames[i], check.Name)
		}

		// Verify GetProbe returns valid values
		probe, expects := check.GetProbe()
		if probe == "" {
			t.Errorf("check %s returned empty probe", check.Name)
		}
		if len(expects) == 0 {
			t.Errorf("check %s returned no expects", check.Name)
		}
	}
}

func TestChecksHaveCorrectLinks(t *testing.T) {
	checks := buildChecks()

	// Checks with expected links
	checksWithLinks := map[string][]string{
		"expression evaluation":       {"https://portswigger.net/research/server-side-template-injection"},
		"template evaluation":         {"https://portswigger.net/research/server-side-template-injection"},
		"EL evaluation":               {"https://portswigger.net/research/server-side-template-injection"},
		"unicode normalisation":       {"https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/"},
		"url decoding error":          {"https://cwe.mitre.org/data/definitions/172.html"},
		"unicode byte truncation":     {"https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows"},
		"unicode case conversion":     {"https://www.unicode.org/charts/case/index.html"},
		"unicode combining diacritic":   {"https://codepoints.net/combining_diacritical_marks?lang=en"},
		"Jinja2 template evaluation":    {"https://portswigger.net/research/server-side-template-injection"},
		"Twig template evaluation":      {"https://portswigger.net/research/server-side-template-injection"},
	}

	for _, check := range checks {
		expectedLinks, hasExpectedLinks := checksWithLinks[check.Name]
		if hasExpectedLinks {
			if len(check.Links) != len(expectedLinks) {
				t.Errorf("check %s: expected %d links, got %d", check.Name, len(expectedLinks), len(check.Links))
			}
			for i, link := range expectedLinks {
				if i < len(check.Links) && check.Links[i] != link {
					t.Errorf("check %s: expected link %s, got %s", check.Name, link, check.Links[i])
				}
			}
		} else {
			// Checks without links
			if len(check.Links) != 0 {
				t.Errorf("check %s: expected no links, got %d", check.Name, len(check.Links))
			}
		}
	}
}

func TestRandomAnchorsAreDifferentBetweenCalls(t *testing.T) {
	// Run detection functions multiple times and verify anchors differ
	probes := make([]string, 5)
	for i := range 5 {
		probe, _ := detectQuoteConsumption()
		probes[i] = probe
	}

	// At least some probes should be different
	allSame := true
	for i := 1; i < len(probes); i++ {
		if probes[i] != probes[0] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("all probes should have different random anchors")
	}
}
