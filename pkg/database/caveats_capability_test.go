package database

import (
	"slices"
	"strings"
	"testing"
)

// A capability the configuration switched off is a caveat naming the modules
// it removed, and it is reported even when the phase it rode on found nothing
// to do: a tier cap that removed every module is why the phase had none.
func TestCoverageCaveatsDisabledCapabilities(t *testing.T) {
	phases := []PhaseOutcome{{
		Phase:   "dynamic-assessment",
		State:   PhaseSkipped,
		Reasons: []string{ReasonNoModules},
		Notes:   []string{LimitModuleTierCapped, LimitOASTDisabled, LimitRiskyPayloadsDisabled},
		NoteModules: map[string][]string{
			LimitModuleTierCapped:      {"heavy-a", "heavy-b"},
			LimitRiskyPayloadsDisabled: {"risky-x"},
		},
	}}
	got := CoverageCaveats(ScanCompletion{Phases: phases}, nil)
	byCode := map[string]Caveat{}
	for _, c := range got {
		byCode[c.Code] = c
	}
	if c := byCode[LimitModuleTierCapped]; !slices.Equal(c.Modules, []string{"heavy-a", "heavy-b"}) || c.Count != 2 || c.Phase != "dynamic-assessment" {
		t.Errorf("module_tier_capped caveat = %+v", c)
	}
	if c := byCode[LimitRiskyPayloadsDisabled]; !slices.Equal(c.Modules, []string{"risky-x"}) {
		t.Errorf("risky_payloads_disabled caveat = %+v", c)
	}
	if c, ok := byCode[LimitOASTDisabled]; !ok || len(c.Modules) != 0 || !strings.Contains(c.Message, "out-of-band") {
		t.Errorf("oast_disabled caveat = %+v (present %v)", c, ok)
	}
	if _, ok := byCode[ReasonNoModules]; ok {
		t.Error("a benign skip's reason is not a caveat")
	}
	if line := byCode[LimitModuleTierCapped].Line(); !strings.Contains(line, "heavy-a, heavy-b") || !strings.HasSuffix(line, "[module_tier_capped]") {
		t.Errorf("caveat line = %q", line)
	}
}

// An explicitly selected phase that admitted nothing is a caveat; the same
// phase brought along by the plan is not.
func TestCoverageCaveatsNoInputs(t *testing.T) {
	named := PhaseOutcome{Phase: "dynamic-assessment", State: PhaseSkipped, Reasons: []string{ReasonNoInputs}, Explicit: true}
	got := CoverageCaveats(ScanCompletion{Phases: []PhaseOutcome{named}}, nil)
	if len(got) != 1 || got[0].Code != ReasonNoInputs {
		t.Fatalf("named no_inputs caveats = %+v", got)
	}
	named.Explicit = false
	if got := CoverageCaveats(ScanCompletion{Phases: []PhaseOutcome{named}}, nil); len(got) != 0 {
		t.Fatalf("plan-brought no_inputs caveats = %+v, want none", got)
	}
}
