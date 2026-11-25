package cli

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// scan.finished names the capabilities the configuration switched off, with
// the modules each removed, and they do not make a complete scan curtailed.
func TestScanFinishedCaveatsNameDisabledCapabilities(t *testing.T) {
	row := &database.Scan{
		Completeness: database.CompletenessComplete,
		PhaseOutcomes: []database.PhaseOutcome{{
			Phase: "dynamic-assessment", State: database.PhaseCompleted,
			Notes: []string{database.LimitOASTDisabled, database.LimitModuleTierCapped, database.LimitRiskyPayloadsDisabled},
			NoteModules: map[string][]string{
				database.LimitModuleTierCapped:      {"heavy-one"},
				database.LimitRiskyPayloadsDisabled: {"php2shell"},
			},
		}},
	}
	ev := scanevents.Event{Status: scanevents.StatusCompleted}
	applyScanCompletion(&ev, row)
	assert.Equal(t, scanevents.StatusCompleted, ev.Status, "a disabled capability is a caveat, not a curtailment")

	got := map[string]scanevents.Caveat{}
	for _, c := range ev.Caveats {
		got[c.Code] = c
	}
	require.Contains(t, got, "oast_disabled")
	assert.Equal(t, []string{"heavy-one"}, got["module_tier_capped"].Modules)
	assert.Equal(t, []string{"php2shell"}, got["risky_payloads_disabled"].Modules)

	// The wire line carries them under caveats[].code / caveats[].modules.
	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	var line map[string]any
	require.NoError(t, json.Unmarshal(raw, &line))
	caveats, _ := line["caveats"].([]any)
	var codes []string
	for _, c := range caveats {
		codes = append(codes, c.(map[string]any)["code"].(string))
	}
	for _, want := range []string{"oast_disabled", "module_tier_capped", "risky_payloads_disabled"} {
		assert.True(t, slices.Contains(codes, want), "caveats %v carry %s", codes, want)
	}
	s, err := contract.EventSchema(scanevents.TypeScanFinished)
	require.NoError(t, err)
	schema, _ := json.Marshal(s)
	assert.Contains(t, string(schema), `"caveats"`)
}

// A dynamic assessment named with --only that admitted nothing: the scan is
// curtailed, scan.finished's reasons carry no_inputs, and its caveats say so.
// Brought along by the plan, the same skip is the plan working.
func TestScanFinishedNoInputs(t *testing.T) {
	phase := database.PhaseOutcome{Phase: "dynamic-assessment", State: database.PhaseSkipped,
		Reasons: []string{database.ReasonNoInputs}, Explicit: true}
	row := &database.Scan{Completeness: database.CompletenessPartial, PhaseOutcomes: []database.PhaseOutcome{phase}}
	ev := scanevents.Event{Status: scanevents.StatusCompleted}
	applyScanCompletion(&ev, row)
	assert.Equal(t, scanevents.StatusCurtailed, ev.Status)
	assert.Equal(t, []string{"no_inputs"}, ev.Reasons)
	require.Len(t, ev.Caveats, 1)
	assert.Equal(t, "no_inputs", ev.Caveats[0].Code)

	phase.Explicit = false
	row = &database.Scan{Completeness: database.CompletenessComplete, PhaseOutcomes: []database.PhaseOutcome{phase}}
	ev = scanevents.Event{Status: scanevents.StatusCompleted}
	applyScanCompletion(&ev, row)
	assert.Equal(t, scanevents.StatusCompleted, ev.Status)
	assert.Empty(t, ev.Reasons)
	assert.Empty(t, ev.Caveats)
}

// phase.finished publishes skipped as a status.
func TestPhaseFinishedSchemaNamesSkipped(t *testing.T) {
	s, err := contract.EventSchema(scanevents.TypePhaseFinished)
	require.NoError(t, err)
	raw, _ := json.Marshal(s)
	assert.Contains(t, string(raw), "skipped")
	assert.Equal(t, "skipped", scanevents.StatusSkipped)
}
