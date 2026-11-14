package config

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"golang.org/x/net/publicsuffix"
)

// hostMatchesOriginReference is the pre-index implementation: one pass over every
// origin target, deriving the candidate's registrable domain inside the loop.
//
// Kept verbatim as the equivalence oracle, taking the parsed target slice as a
// parameter because the matcher no longer retains one - the index replaced it.
// originIndex exists purely to answer the same question without the per-target
// work, so the only thing that proves it correct is agreeing with this on every
// input - including the ones the hand-written table tests do not think to cover.
func hostMatchesOriginReference(m *ScopeMatcher, targets []originTarget, host string) bool {
	if m.originMode == "all" || len(targets) == 0 {
		return true
	}
	hostLower := strings.ToLower(host)
	for i := range targets {
		ot := &targets[i]
		var match bool
		switch {
		case ot.isIP:
			match = hostLower == ot.exactHost
		case m.originMode == "strict":
			match = hostLower == ot.exactHost
		case m.originMode == "balanced":
			if ot.etldPlus1 == "" {
				match = hostLower == ot.exactHost
				break
			}
			hostETLD, err := publicsuffix.EffectiveTLDPlusOne(hostLower)
			match = err == nil && hostETLD == ot.etldPlus1
		case m.originMode == "relaxed":
			if len(ot.keyword) < minRelaxedKeywordLen {
				match = hostLower == ot.exactHost
				break
			}
			hostETLD, err := publicsuffix.EffectiveTLDPlusOne(hostLower)
			match = err == nil && strings.Contains(leadingLabel(hostETLD), ot.keyword)
		default:
			match = hostLower == ot.exactHost
		}
		if match {
			return true
		}
	}
	return false
}

// originEquivalenceCorpus is deliberately awkward: single-label hosts with no
// registrable domain, multi-part TLDs, IPs, brand-substring near misses, and
// hosts that are a target's exact name while belonging to another target's
// domain. Those are the cases where the set-based and loop-based answers could
// diverge.
var originEquivalenceCorpus = []string{
	"example.com", "www.example.com", "api.example.com", "EXAMPLE.COM",
	"example.co.uk", "shop.example.co.uk", "example.io", "examplegroup.com",
	"notexample.com", "example.com.evil.net", "evil.net",
	"internal", "localhost", "db-primary",
	"192.0.2.1", "192.0.2.2", "203.0.113.10",
	"acme.test", "acme-corp.test", "corp.acme.test",
	"example.s3.amazonaws.com", "example.github.io", "other.github.io",
	"xn--80ak6aa92e.com", "a.b.c.d.example.com", "",
}

func TestOriginIndexMatchesReference(t *testing.T) {
	targetSets := [][]string{
		{"https://example.com"},
		{"example.com", "example.co.uk"},
		{"www.example.com", "192.0.2.1", "internal"},
		{"acme.test", "example.github.io", "localhost"},
		{"https://api.example.com:8443/path", "http://evil.net", "203.0.113.10"},
		{"internal", "db-primary"},
		{"example.com", "example.com", "EXAMPLE.COM"},
	}
	modes := []string{"strict", "balanced", "relaxed", "all", "typo-mode", ""}

	for _, targets := range targetSets {
		for _, mode := range modes {
			cfg := *DefaultScopeConfig()
			cfg.CLIOriginMode = mode
			m := NewScopeMatcher(cfg, targets...)
			for _, host := range originEquivalenceCorpus {
				got := m.hostMatchesOrigin(host)
				want := hostMatchesOriginReference(m, parseOriginTargets(targets), host)
				if got != want {
					t.Errorf("mode=%q targets=%v host=%q: index=%v reference=%v",
						mode, targets, host, got, want)
				}
			}
		}
	}
}

func TestOriginIndexMatchesReferenceRandomized(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5c09e))
	labels := []string{"example", "acme", "acmecorp", "shop", "api", "www", "internal", "ex"}
	suffixes := []string{"com", "co.uk", "io", "test", "github.io", ""}

	randomHost := func() string {
		switch rng.Intn(10) {
		case 0:
			return fmt.Sprintf("192.0.2.%d", rng.Intn(4))
		case 1:
			return labels[rng.Intn(len(labels))] // single label, no eTLD+1
		}
		host := labels[rng.Intn(len(labels))]
		if rng.Intn(2) == 0 {
			host = labels[rng.Intn(len(labels))] + "." + host
		}
		if suffix := suffixes[rng.Intn(len(suffixes))]; suffix != "" {
			host += "." + suffix
		}
		return host
	}

	modes := []string{"strict", "balanced", "relaxed"}
	for range 300 {
		targets := make([]string, 1+rng.Intn(4))
		for i := range targets {
			targets[i] = randomHost()
		}
		mode := modes[rng.Intn(len(modes))]

		cfg := *DefaultScopeConfig()
		cfg.CLIOriginMode = mode
		m := NewScopeMatcher(cfg, targets...)

		for range 20 {
			host := randomHost()
			got := m.hostMatchesOrigin(host)
			want := hostMatchesOriginReference(m, parseOriginTargets(targets), host)
			if got != want {
				t.Fatalf("mode=%q targets=%v host=%q: index=%v reference=%v",
					mode, targets, host, got, want)
			}
		}
	}
}

// BenchmarkHostMatchesOrigin measures the case the index exists for: a sweep
// where every candidate host is distinct, so the repeat-host cache never helps
// and first-visit cost is what the scan pays.
func BenchmarkHostMatchesOrigin(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		targets := make([]string, n)
		for i := range targets {
			targets[i] = fmt.Sprintf("host%d.example%d.com", i, i)
		}
		cfg := *DefaultScopeConfig()
		cfg.CLIOriginMode = "balanced"
		m := NewScopeMatcher(cfg, targets...)
		parsed := parseOriginTargets(targets)

		b.Run(fmt.Sprintf("index/targets=%d", n), func(b *testing.B) {
			for i := 0; b.Loop(); i++ {
				m.hostMatchesOrigin(fmt.Sprintf("probe%d.other%d.net", i, i))
			}
		})
		b.Run(fmt.Sprintf("reference/targets=%d", n), func(b *testing.B) {
			for i := 0; b.Loop(); i++ {
				hostMatchesOriginReference(m, parsed, fmt.Sprintf("probe%d.other%d.net", i, i))
			}
		})
	}
}
