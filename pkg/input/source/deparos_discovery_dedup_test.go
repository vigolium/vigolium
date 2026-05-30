package source

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// rec is a test helper building a collectedRecord with a non-nil rr placeholder
// (capNearIdenticalClusters never dereferences rr, but compaction treats nil as
// a tombstone, so keep it non-nil to mirror real survivors).
func rec(path, host string, status int, ctype string, size, words int64) collectedRecord {
	return collectedRecord{
		rr:     &httpmsg.HttpRequestResponse{},
		path:   path,
		host:   host,
		status: status,
		ctype:  ctype,
		size:   size,
		words:  words,
	}
}

func keptPaths(records []collectedRecord) []string {
	paths := make([]string, 0, len(records))
	for _, r := range records {
		paths = append(paths, r.path)
	}
	return paths
}

func TestWithinDedupTolerance(t *testing.T) {
	cases := []struct {
		a, b int64
		want bool
	}{
		{1236, 1236, true},   // identical
		{1236, 1234, true},   // word wobble, ~0.16%
		{74100, 74400, true}, // ~0.4% size drift
		{74100, 74600, false},
		{0, 0, true}, // both zero (empty bodies)
		{0, 100, false},
		{200, 201, true},  // 1/201 = 0.497%, just inside the band
		{200, 203, false}, // 3/203 = 1.48%, small bodies need a near-exact match
		{1000, 1004, true},
		{1000, 1006, false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d_vs_%d", c.a, c.b), func(t *testing.T) {
			assert.Equal(t, c.want, withinDedupTolerance(c.a, c.b))
			assert.Equal(t, c.want, withinDedupTolerance(c.b, c.a), "must be symmetric")
		})
	}
}

func TestResolveClusterCap(t *testing.T) {
	assert.Equal(t, defaultDedupClusterCap, DeparosDiscoveryConfig{DedupClusterCap: 0}.resolveClusterCap(), "0 => default")
	assert.Equal(t, 0, DeparosDiscoveryConfig{DedupClusterCap: -1}.resolveClusterCap(), "negative => disabled")
	assert.Equal(t, 5, DeparosDiscoveryConfig{DedupClusterCap: 5}.resolveClusterCap(), "positive => that value")
}

// TestCapNearIdenticalClusters_SPAFlood reproduces the navify-portal case: a
// catch-all SPA answering 200 with the same ~74KB page (tiny word wobble) for
// every path. The cap should keep only `cap` representatives.
func TestCapNearIdenticalClusters_SPAFlood(t *testing.T) {
	const host = "www.navifyportal.roche.com"
	var records []collectedRecord
	for i := 0; i < 50; i++ {
		// Sizes/words drift within 0.5% to mimic per-request minification noise.
		size := int64(74100 + (i % 5)) // 74100..74104
		words := int64(1236 - (i % 3)) // 1234..1236
		records = append(records, rec(fmt.Sprintf("/roche_logo16/path%02d", i), host, 200, "text/html", size, words))
	}

	kept, capped, codes := capNearIdenticalClusters(records, 10)

	assert.Len(t, kept, 10, "only the cap is kept")
	assert.Equal(t, 40, capped)
	assert.Equal(t, 40, codes[1], "all capped records are 2xx")
}

func TestCapNearIdenticalClusters_KeepsShortestPaths(t *testing.T) {
	const host = "h"
	records := []collectedRecord{
		rec("/a/b/c/d/e", host, 200, "text/html", 74100, 1236),
		rec("/a/b/c/d", host, 200, "text/html", 74100, 1236),
		rec("/a/b/c", host, 200, "text/html", 74100, 1236),
		rec("/a/b", host, 200, "text/html", 74100, 1236),
		rec("/a", host, 200, "text/html", 74100, 1236),
	}

	kept, capped, _ := capNearIdenticalClusters(records, 2)

	assert.Equal(t, 3, capped)
	// Shortest two paths survive.
	assert.ElementsMatch(t, []string{"/a", "/a/b"}, keptPaths(kept))
}

func TestCapNearIdenticalClusters_DistinctSizesAllKept(t *testing.T) {
	const host = "h"
	records := []collectedRecord{
		rec("/p1", host, 200, "text/html", 1000, 100),
		rec("/p2", host, 200, "text/html", 5000, 500),
		rec("/p3", host, 200, "text/html", 20000, 2000),
		rec("/p4", host, 200, "text/html", 60000, 6000),
	}

	kept, capped, _ := capNearIdenticalClusters(records, 1)

	assert.Equal(t, 0, capped, "distinct shapes never cluster, so none are capped")
	assert.Len(t, kept, 4)
}

func TestCapNearIdenticalClusters_SeparatedByKey(t *testing.T) {
	const host = "h"
	// Same size/words but different status / content-type / host must not cluster.
	records := []collectedRecord{
		rec("/a", host, 200, "text/html", 74100, 1236),
		rec("/b", host, 404, "text/html", 74100, 1236),        // different status
		rec("/c", host, 200, "application/json", 74100, 1236), // different ctype
		rec("/d", "other", 200, "text/html", 74100, 1236),     // different host
	}

	kept, capped, _ := capNearIdenticalClusters(records, 1)

	assert.Equal(t, 0, capped, "each lands in its own cluster")
	assert.Len(t, kept, 4)
}

func TestCapNearIdenticalClusters_NoResponseBypass(t *testing.T) {
	const host = "h"
	records := []collectedRecord{
		rec("/ok1", host, 200, "text/html", 74100, 1236),
		rec("/ok2", host, 200, "text/html", 74101, 1235),
		rec("/ok3", host, 200, "text/html", 74102, 1236),
		// status 0 = no response captured; must always be kept regardless of shape.
		rec("/err1", host, 0, "", 0, 0),
		rec("/err2", host, 0, "", 0, 0),
		rec("/err3", host, 0, "", 0, 0),
	}

	kept, capped, _ := capNearIdenticalClusters(records, 1)

	assert.Equal(t, 2, capped, "two of the three 200s are capped")
	// All three no-response records survive plus one 200 representative.
	assert.ElementsMatch(t, []string{"/err1", "/err2", "/err3", "/ok1"}, keptPaths(kept))
}

func TestCapNearIdenticalClusters_DisabledPassthrough(t *testing.T) {
	const host = "h"
	records := []collectedRecord{
		rec("/a", host, 200, "text/html", 74100, 1236),
		rec("/b", host, 200, "text/html", 74100, 1236),
	}

	kept, capped, _ := capNearIdenticalClusters(records, 0)

	assert.Equal(t, 0, capped)
	assert.Len(t, kept, 2, "cap<=0 returns records untouched")
}
