package infra

import (
	"strings"
	"testing"
)

func TestAuthorityConfusionPayloads(t *testing.T) {
	const decoy, effective = "trusted.example", "evil.test"
	payloads := AuthorityConfusionPayloads(decoy, effective)

	// 8 quirks × 2 schemes.
	if want := 16; len(payloads) != want {
		t.Fatalf("AuthorityConfusionPayloads count = %d, want %d", len(payloads), want)
	}

	var sawHTTPS, sawHTTP, sawAt, sawHash, sawSpace, sawBackslash, sawMultiAt bool
	for _, p := range payloads {
		// Every payload must mention both hosts so a validator-vs-fetcher
		// disagreement is actually possible.
		if !strings.Contains(p.Value, decoy) || !strings.Contains(p.Value, effective) {
			t.Errorf("payload %q does not contain both decoy and effective hosts", p.Value)
		}
		if p.Class != ConfusionAuthority {
			t.Errorf("payload %q has class %q, want %q", p.Value, p.Class, ConfusionAuthority)
		}
		if p.Label == "" {
			t.Errorf("payload %q has empty label", p.Value)
		}
		switch {
		case strings.HasPrefix(p.Value, "https://"):
			sawHTTPS = true
		case strings.HasPrefix(p.Value, "http://"):
			sawHTTP = true
		default:
			t.Errorf("payload %q has unexpected scheme", p.Value)
		}
		// No payload may carry a pre-percent-encoded sequence — the delivery
		// contract is literal characters only.
		if strings.Contains(p.Value, "%") {
			t.Errorf("payload %q contains a percent sequence; ladder must use literal chars only", p.Value)
		}
		if strings.Contains(p.Value, "@") {
			sawAt = true
		}
		if strings.Contains(p.Value, "#") {
			sawHash = true
		}
		if strings.Contains(p.Value, " ") {
			sawSpace = true
		}
		if strings.Contains(p.Value, `\`) {
			sawBackslash = true
		}
		if strings.Count(p.Value, "@") >= 2 {
			sawMultiAt = true
		}
	}

	for name, ok := range map[string]bool{
		"https scheme": sawHTTPS,
		"http scheme":  sawHTTP,
		"userinfo @":   sawAt,
		"fragment #":   sawHash,
		"space":        sawSpace,
		"backslash":    sawBackslash,
		"multiple @":   sawMultiAt,
	} {
		if !ok {
			t.Errorf("ladder is missing the %q quirk", name)
		}
	}
}
