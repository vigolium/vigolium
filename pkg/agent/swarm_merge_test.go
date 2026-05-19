package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeSwarmPlans_SinglePlan(t *testing.T) {
	plan := &SwarmPlan{
		ModuleTags: []string{"xss", "sqli"},
		ModuleIDs:  []string{"sqli-error-based"},
		FocusAreas: []string{"SQL injection in query params"},
		Notes:      "single batch",
	}

	merged, prov := mergeSwarmPlans([]*SwarmPlan{plan})

	assert.Contains(t, merged.ModuleTags, "xss")
	assert.Contains(t, merged.ModuleTags, "sqli")
	assert.Contains(t, merged.ModuleIDs, "sqli-error-based")
	assert.Contains(t, merged.FocusAreas, "SQL injection in query params")
	assert.Equal(t, "single batch", merged.Notes)
	// Single plan should not produce provenance
	assert.Nil(t, prov)
}

func TestMergeSwarmPlans_DeduplicatesTags(t *testing.T) {
	plans := []*SwarmPlan{
		{ModuleTags: []string{"xss", "sqli", "injection"}, FocusAreas: []string{"area1"}},
		{ModuleTags: []string{"sqli", "csrf", "injection"}, FocusAreas: []string{"area2"}},
	}

	merged, prov := mergeSwarmPlans(plans)

	// Should have union of all tags, no duplicates
	assert.ElementsMatch(t, []string{"csrf", "injection", "sqli", "xss"}, merged.ModuleTags)
	assert.ElementsMatch(t, []string{"area1", "area2"}, merged.FocusAreas)

	// Provenance should track first batch that introduced each tag
	require.NotNil(t, prov)
	assert.Equal(t, 1, prov.ModuleTags["xss"])
	assert.Equal(t, 1, prov.ModuleTags["sqli"])
	assert.Equal(t, 2, prov.ModuleTags["csrf"])
}

func TestMergeSwarmPlans_DeduplicatesModuleIDs(t *testing.T) {
	plans := []*SwarmPlan{
		{ModuleIDs: []string{"mod-a", "mod-b"}},
		{ModuleIDs: []string{"mod-b", "mod-c"}},
		{ModuleIDs: []string{"mod-c", "mod-d"}},
	}

	merged, prov := mergeSwarmPlans(plans)

	assert.ElementsMatch(t, []string{"mod-a", "mod-b", "mod-c", "mod-d"}, merged.ModuleIDs)

	require.NotNil(t, prov)
	assert.Equal(t, 1, prov.ModuleIDs["mod-a"])
	assert.Equal(t, 1, prov.ModuleIDs["mod-b"])
	assert.Equal(t, 2, prov.ModuleIDs["mod-c"])
	assert.Equal(t, 3, prov.ModuleIDs["mod-d"])
}

func TestMergeSwarmPlans_ExtensionCollisionRename(t *testing.T) {
	plans := []*SwarmPlan{
		{Extensions: []GeneratedExtension{
			{Filename: "custom-check.js", Code: "code-v1", Reason: "batch 1"},
		}},
		{Extensions: []GeneratedExtension{
			{Filename: "custom-check.js", Code: "code-v2", Reason: "batch 2"},
		}},
	}

	merged, prov := mergeSwarmPlans(plans)

	// Should have 2 extensions (one renamed due to collision)
	require.Len(t, merged.Extensions, 2)

	filenames := make(map[string]bool)
	for _, ext := range merged.Extensions {
		filenames[ext.Filename] = true
	}
	// Original name should be present (from batch 1 or batch 2)
	assert.True(t, filenames["custom-check.js"], "expected original filename")
	// A renamed variant should exist
	assert.Equal(t, 2, len(filenames), "expected 2 unique filenames after collision rename")

	require.NotNil(t, prov)
	assert.Len(t, prov.Extensions, 2)
}

func TestMergeSwarmPlans_ExtensionSameCodeNoDuplicate(t *testing.T) {
	// When two batches produce the same extension with identical code, no rename needed
	plans := []*SwarmPlan{
		{Extensions: []GeneratedExtension{
			{Filename: "common.js", Code: "same-code", Reason: "batch 1"},
		}},
		{Extensions: []GeneratedExtension{
			{Filename: "common.js", Code: "same-code", Reason: "batch 2"},
		}},
	}

	merged, _ := mergeSwarmPlans(plans)

	// Same code = no collision rename, last one wins
	require.Len(t, merged.Extensions, 1)
	assert.Equal(t, "common.js", merged.Extensions[0].Filename)
}

func TestMergeSwarmPlans_QuickChecksAndSnippets(t *testing.T) {
	plans := []*SwarmPlan{
		{
			QuickChecks: []QuickCheck{
				{ID: "ssti-check", Scan: "per_insertion_point", Severity: "high"},
			},
			Snippets: []Snippet{
				{ID: "custom-scan", Scan: "per_request", Body: "return null;"},
			},
		},
		{
			QuickChecks: []QuickCheck{
				{ID: "ssti-check", Scan: "per_insertion_point", Severity: "critical"}, // same ID, should override
				{ID: "rce-check", Scan: "per_request", Severity: "critical"},
			},
			Snippets: []Snippet{
				{ID: "another-scan", Scan: "per_host", Body: "return [];"},
			},
		},
	}

	merged, _ := mergeSwarmPlans(plans)

	// Quick checks merged by ID (last wins)
	assert.Len(t, merged.QuickChecks, 2)
	qcMap := make(map[string]QuickCheck)
	for _, qc := range merged.QuickChecks {
		qcMap[qc.ID] = qc
	}
	assert.Equal(t, "critical", qcMap["ssti-check"].Severity, "last batch should win for same ID")
	assert.Equal(t, "critical", qcMap["rce-check"].Severity)

	// Snippets merged by ID
	assert.Len(t, merged.Snippets, 2)
}

func TestMergeSwarmPlans_NotesConcatenated(t *testing.T) {
	plans := []*SwarmPlan{
		{Notes: "batch 1 notes"},
		{Notes: "batch 2 notes"},
		{Notes: ""},
	}

	merged, _ := mergeSwarmPlans(plans)

	assert.Contains(t, merged.Notes, "batch 1 notes")
	assert.Contains(t, merged.Notes, "batch 2 notes")
}

func TestMergeSwarmPlans_EmptyPlans(t *testing.T) {
	merged, prov := mergeSwarmPlans([]*SwarmPlan{{}, {}})

	assert.Empty(t, merged.ModuleTags)
	assert.Empty(t, merged.ModuleIDs)
	assert.Empty(t, merged.FocusAreas)
	assert.Empty(t, merged.Extensions)
	require.NotNil(t, prov) // 2 plans = provenance is tracked
}

func TestAggregateFollowUps_MergesTagsAndIDs(t *testing.T) {
	followUps := []FollowUpScan{
		{
			URL:        "http://localhost/api/users",
			ModuleTags: []string{"sqli", "xss"},
			ModuleIDs:  []string{"sqli-error-based"},
		},
		{
			URL:        "http://localhost/api/products",
			ModuleTags: []string{"xss", "csrf"},
			ModuleIDs:  []string{"csrf-token-check", "sqli-error-based"},
		},
	}

	req := aggregateFollowUps(followUps)

	assert.ElementsMatch(t, []string{"sqli", "xss", "csrf"}, req.ModuleTags)
	assert.ElementsMatch(t, []string{"sqli-error-based", "csrf-token-check"}, req.ModuleIDs)
	assert.True(t, req.IsRescan)
}

func TestAggregateFollowUps_Empty(t *testing.T) {
	req := aggregateFollowUps(nil)

	assert.Empty(t, req.ModuleTags)
	assert.Empty(t, req.ModuleIDs)
	assert.True(t, req.IsRescan)
}
