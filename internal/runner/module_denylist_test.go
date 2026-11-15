package runner

import (
	"slices"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/types"
)

// The enabled_modules deny-list subtracts from an "all" selection; an explicit
// -m naming a disabled module still runs it.
func TestFilterModulesForRunAppliesDenyList(t *testing.T) {
	ids := modules.GetActiveModulesID()
	settings := config.DefaultSettings()
	settings.DynamicAssessment.EnabledModules.DisabledActiveModules = []string{ids[0]}

	opts := types.DefaultOptions()
	opts.Modules = []string{"all"}
	opts.Intensity = "deep"
	allow := true
	opts.AllowRiskyPayloads = &allow
	sel := FilterModulesForRun(opts, settings)
	for _, m := range sel.Active {
		if m.ID() == ids[0] {
			t.Fatalf("%s is on the deny-list but selected", ids[0])
		}
	}
	if !slices.Contains(sel.ConfigDisabled, ids[0]) {
		t.Fatalf("ConfigDisabled = %v", sel.ConfigDisabled)
	}

	opts.Modules = []string{ids[0]}
	sel = FilterModulesForRun(opts, settings)
	if len(sel.Active) != 1 || sel.Active[0].ID() != ids[0] {
		t.Fatalf("explicit -m %s dropped", ids[0])
	}
}

func TestValidateRejectsEmptyAllowList(t *testing.T) {
	s := config.DefaultSettings()
	s.DynamicAssessment.EnabledModules.ActiveModules = []string{}
	found := false
	for _, is := range config.ValidateSettings(s) {
		if is.Key == "dynamic-assessment.enabled_modules.active_modules" && is.Severity == config.SeverityError {
			found = true
		}
	}
	if !found {
		t.Fatal("empty active_modules allow-list not reported")
	}
}
