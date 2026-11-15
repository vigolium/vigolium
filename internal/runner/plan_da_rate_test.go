package runner

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
)

// Dynamic assessment has no phase-local rate; the plan reports the scan-wide
// limit that paces it instead of 0, which reads as "unlimited".
func TestPlanPhasePaceDynamicAssessmentReportsScanRate(t *testing.T) {
	opts := types.DefaultOptions()
	opts.RateLimit = 2
	got := planPhasePace(config.DefaultSettings(), opts, string(PhaseDynamicAssessment))
	if got == nil || got.RateLimit != 2 {
		t.Fatalf("dynamic-assessment pace = %+v, want rate_limit 2", got)
	}
}
