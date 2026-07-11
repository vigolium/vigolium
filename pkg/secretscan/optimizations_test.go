package secretscan

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/secretscan/catalog"
)

// TestDetect_AcceptCapNotRawCap asserts the per-rule cap bounds ACCEPTED matches,
// not raw regex matches. A real, high-entropy secret sitting past the old 100
// raw-match cap — behind a flood of low-entropy placeholders the same rule matches
// and the entropy gate rejects — must still be detected.
func TestDetect_AcceptCapNotRawCap(t *testing.T) {
	rule := catalog.Rule{
		ID: "test.accept-cap", Name: "Test Accept Cap", Src: "test",
		Re:         `SECRET_[A-Za-z0-9]{20}`,
		Entropy:    2.5, // rejects the repeated-'A' placeholder, accepts a random value
		Confidence: "high",
		Visible:    true,
	}
	det, err := New(&catalog.Catalog{Rules: []catalog.Rule{rule}}, Options{})
	require.NoError(t, err)

	placeholder := "SECRET_" + strings.Repeat("A", 20) // low entropy → gated out
	real := "SECRET_aB3xK9mP2qR7sT1vW5yZ"               // "SECRET_" + 20 mixed chars → high entropy

	var sb strings.Builder
	for i := 0; i < 150; i++ { // 150 > old 100-raw cap, < rawCeiling
		sb.WriteString(placeholder + " ")
	}
	sb.WriteString(real)
	body := []byte(sb.String())

	matches := det.Detect(body)
	require.Len(t, matches, 1, "the real secret behind 150 gated placeholders must surface")
	assert.Equal(t, real, matches[0].Secret)
	// The reported offset must point at the real occurrence, not a placeholder.
	assert.Equal(t, real, string(body[matches[0].Start:matches[0].End]))
}

// TestDetect_BodyCacheMatchesUncached asserts the body-SHA cache returns the exact
// same matches as an uncached detector — on both the compute (miss) and the served
// (hit) call — and does not leak one body's result to another.
func TestDetect_BodyCacheMatchesUncached(t *testing.T) {
	rule := catalog.Rule{
		ID: "test.cache", Name: "Test Cache", Src: "test",
		Re: `SECRET_[A-Za-z0-9]{20}`, Confidence: "high", Visible: true,
	}
	cat := &catalog.Catalog{Rules: []catalog.Rule{rule}}

	uncached, err := New(cat, Options{})
	require.NoError(t, err)
	cached, err := New(cat, Options{BodyCacheSize: 8})
	require.NoError(t, err)
	require.NotNil(t, cached.cache, "BodyCacheSize>0 must enable the cache")

	body := []byte(`const k = "SECRET_aB3xK9mP2qR7sT1vW5yZ";`)
	want := uncached.Detect(body)
	require.Len(t, want, 1)

	got1 := cached.Detect(body) // miss → compute + store
	got2 := cached.Detect(body) // hit → served from cache
	assert.Equal(t, want, got1)
	assert.Equal(t, want, got2)

	// A different body must not be served the cached result.
	assert.Empty(t, cached.Detect([]byte(`nothing here`)))
}

// TestSetPrefilter_EquivalentToBaseline asserts the experimental regex-Set
// prefilter changes performance, never results: over every rule's own example
// corpus, a Set-enabled detector reports exactly what the baseline does. Set
// pruning only removes rules whose pattern cannot match, so this must hold.
func TestSetPrefilter_EquivalentToBaseline(t *testing.T) {
	cat, err := LoadCatalog()
	require.NoError(t, err)
	base, err := New(cat, Options{})
	require.NoError(t, err)
	withSet, err := New(cat, Options{UseRegexSet: true})
	require.NoError(t, err)
	require.NotNil(t, withSet.set, "regex Set must compile for the real catalog (else this test is vacuous)")

	examples := loadExamples(t)
	checked := 0
	for id, exs := range examples {
		for _, ex := range exs {
			b := []byte(ex)
			require.Equal(t, base.Detect(b), withSet.Detect(b),
				"rule %s example %q: Set prefilter changed detection", id, ex)
			checked++
		}
	}
	require.Greater(t, checked, 100, "expected a substantial example corpus")
	t.Logf("Set prefilter equivalence verified over %d example bodies", checked)
}

// TestSetPrefilter_ConcurrentSafe exercises the Set prefilter and body cache from
// many goroutines; run with -race it guards the concurrency contract Detect
// documents.
func TestSetPrefilter_ConcurrentSafe(t *testing.T) {
	cat, err := LoadCatalog()
	require.NoError(t, err)
	det, err := New(cat, Options{UseRegexSet: true, BodyCacheSize: 64})
	require.NoError(t, err)
	require.NotNil(t, det.set)

	bodies := [][]byte{
		[]byte(realSecrets["stripe"]),
		[]byte(realSecrets["google-api"]),
		[]byte(`nothing to see here, move along`),
		[]byte(strings.Repeat("padding tokens and words ", 400)),
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				det.Detect(bodies[(n+j)%len(bodies)])
			}
		}(i)
	}
	wg.Wait()
}

// benchBody builds a medium JS-like body with a couple of real secrets embedded,
// representative of a minified bundle that reaches the detector.
func benchBody() []byte {
	var sb strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&sb, "function f%d(){return %d*2;}\n", i, i)
	}
	sb.WriteString(`const stripe="` + realSecrets["stripe"] + `";`)
	sb.WriteString(`const g="` + realSecrets["google-api"] + `";`)
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&sb, "var x%d = 'lorem ipsum dolor sit amet %d';\n", i, i)
	}
	return []byte(sb.String())
}

// BenchmarkDetectVariants compares the four detector configurations. "cache" and
// "set+cache" repeatedly scan the SAME body, so they measure the cache-hit path
// (the repeated-body scenario the cache targets); "baseline" and "set" recompute
// every iteration.
func BenchmarkDetectVariants(b *testing.B) {
	cat, err := LoadCatalog()
	if err != nil {
		b.Fatal(err)
	}
	body := benchBody()

	variants := []struct {
		name string
		opts Options
	}{
		{"baseline", Options{}},
		{"cache", Options{BodyCacheSize: 1024}},
		{"set", Options{UseRegexSet: true}},
		{"set+cache", Options{UseRegexSet: true, BodyCacheSize: 1024}},
	}
	for _, v := range variants {
		det, err := New(cat, v.opts)
		if err != nil {
			b.Fatalf("build %s: %v", v.name, err)
		}
		b.Run(v.name, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				det.Detect(body)
			}
		})
	}
}
