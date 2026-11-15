package runner

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

// plan.scope names every rule that narrows anything, not only host and path.
func TestPlanScopeListsNonDefaultRules(t *testing.T) {
	s := *config.DefaultScopeConfig()
	if got := planScope(s).Rules; len(got) != 0 {
		t.Fatalf("default scope lists rules: %+v", got)
	}
	s.ResponseContentType.Exclude = []string{"*"}
	got := planScope(s).Rules
	if len(got) != 1 || got[0].Class != config.ScopeClassResponseContentType || got[0].Exclude[0] != "*" {
		t.Fatalf("rules = %+v", got)
	}
}
