package source

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TestClassifyDiscoverySource locks in the provenance→source-label mapping that
// keeps code-referenced discovery records out of the fuzz-noise cleanup. Only
// the high-precision, method/body-bearing classes (JSTangle-extracted requests
// and submitted HTML forms) get a distinct label; every other provenance —
// including spider-referenced links, which are the catch-all flood surface the
// deparos passes exist to tame — stays under crawlRecordSource.
func TestClassifyDiscoverySource(t *testing.T) {
	cases := []struct {
		foundBy string
		want    string
	}{
		{"js-extracted", jstangleRecordSource},
		{"form", formRecordSource},
		// Everything below must remain the fuzz/crawl class (crawlRecordSource) so
		// the source='deparos' dedup/status/cluster-cap passes still apply.
		{"spider", crawlRecordSource},
		{"spider-file", crawlRecordSource},
		{"wordlist", crawlRecordSource},
		{"fuzz", crawlRecordSource},
		{"numeric", crawlRecordSource},
		{"observed-no-ext", crawlRecordSource},
		{"jsfetch", crawlRecordSource},
		{"asset", crawlRecordSource},
		{"manifest", crawlRecordSource},
		{"nextjs", crawlRecordSource},
		{"robots", crawlRecordSource},
		{"source-map", crawlRecordSource},
		{"", crawlRecordSource},
		{"totally-unknown-task", crawlRecordSource},
	}
	for _, tc := range cases {
		assert.Equalf(t, tc.want, classifyDiscoverySource(tc.foundBy),
			"classifyDiscoverySource(%q)", tc.foundBy)
	}

	// The referenced labels must all be distinct from each other and from the
	// crawl/spec labels — that distinctness is exactly what exempts them from the
	// source='deparos' passes.
	labels := []string{crawlRecordSource, specRecordSource, jstangleRecordSource, formRecordSource}
	seen := map[string]bool{}
	for _, l := range labels {
		assert.Falsef(t, seen[l], "source label %q must be unique", l)
		seen[l] = true
	}
}

func recWithSource(source string) collectedRecord {
	// A non-nil rr is required for the record to survive grouping.
	rr, err := httpmsg.GetRawRequestFromURL("https://api.example.com/x")
	if err != nil {
		panic(err)
	}
	return collectedRecord{rr: rr, source: source}
}

// TestGroupCollectedBySource verifies records bucket by label, first-seen order
// is preserved (fuzz leads because it is appended first upstream), nil-rr
// tombstones are dropped, and the flat list spans every group.
func TestGroupCollectedBySource(t *testing.T) {
	records := []collectedRecord{
		recWithSource(crawlRecordSource),
		recWithSource(crawlRecordSource),
		recWithSource(jstangleRecordSource),
		{rr: nil, source: crawlRecordSource}, // tombstone: must be skipped
		recWithSource(formRecordSource),
		recWithSource(jstangleRecordSource),
	}

	order, bySource, flat := groupCollectedBySource(records)

	assert.Equal(t, []string{crawlRecordSource, jstangleRecordSource, formRecordSource}, order,
		"labels ordered by first appearance")
	assert.Len(t, bySource[crawlRecordSource], 2)
	assert.Len(t, bySource[jstangleRecordSource], 2)
	assert.Len(t, bySource[formRecordSource], 1)
	assert.Len(t, flat, 5, "flat list must span every group minus the tombstone")
}

// TestGroupCollectedBySource_EmptySourceDefaultsToCrawl guards the zero-value
// fallback: a record with no explicit source label lands under crawlRecordSource
// rather than an empty-string bucket that no dedup pass would ever match.
func TestGroupCollectedBySource_EmptySourceDefaultsToCrawl(t *testing.T) {
	order, bySource, _ := groupCollectedBySource([]collectedRecord{recWithSource("")})
	assert.Equal(t, []string{crawlRecordSource}, order)
	assert.Len(t, bySource[crawlRecordSource], 1)
	assert.Empty(t, bySource[""], "no records should land under the empty-string label")
}
