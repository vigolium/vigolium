package runner

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanplan"
	"github.com/vigolium/vigolium/pkg/types"
)

// syntheticPlan is a plan with fixed module counts and wordlist sizes, so the
// estimator can be checked without the registry or the embedded lists.
func syntheticPlan(phases ...NativePhase) *scanplan.Plan {
	ten, twenty := int64(10), int64(20)
	p := &scanplan.Plan{
		Budgets: scanplan.Budgets{RateLimit: 10},
		Modules: scanplan.Modules{
			TierCeiling: "intrusive",
			ByScope:     map[string]int{scanplan.ScopeInsertionPoint: 3, scanplan.ScopeRequest: 2, scanplan.ScopeHost: 1},
		},
		Discovery: &scanplan.Discovery{
			Wordlists: []scanplan.Wordlist{
				{Slot: wordlistSlotShortFile, Lines: &ten},
				{Slot: wordlistSlotShortDir, Lines: &twenty},
			},
			RecursionEnabled:  true,
			RecursionMaxDepth: 5,
			TargetConcurrency: 1,
		},
	}
	for _, id := range phases {
		p.Phases = append(p.Phases, scanplan.Phase{ID: string(id), Enabled: true, SendsTarget: id != PhaseExternalHarvest})
	}
	return p
}

func estimateFor(p *scanplan.Plan, targets, records int64) scanplan.Estimate {
	return estimatePlan(p, planEstimateInput{
		settings: config.DefaultSettings(),
		opts:     types.DefaultOptions(),
		targets:  targets,
		records:  records,
	})
}

// TestEstimateDiscoveryAndAssessment pins the arithmetic of the two phases
// that dominate a scan.
func TestEstimateDiscoveryAndAssessment(t *testing.T) {
	p := syntheticPlan(PhaseDiscovery, PhaseDynamicAssessment)
	est := estimateFor(p, 2, 100)

	disc := est.ByPhase[string(PhaseDiscovery)]
	// 2 targets × 30 words; high × recursion 3 (capped) + 2 × 200 observed.
	if disc.Low != 60 || disc.High != 60*3+2*estObservedWordsPerTarget {
		t.Errorf("discovery = %+v", disc)
	}
	da := est.ByPhase[string(PhaseDynamicAssessment)]
	// low: 100 records × (2 request + 3 IP modules × 4 default IPs) + 1 host
	// module × 2 hosts.
	if da.Low != 100*(2+3*4)+2 {
		t.Errorf("dynamic-assessment low = %d", da.Low)
	}
	if da.High <= da.Low {
		t.Errorf("dynamic-assessment high %d <= low %d", da.High, da.Low)
	}
	if est.Low != disc.Low+da.Low || est.High != disc.High+da.High {
		t.Errorf("totals %d-%d do not sum the phases", est.Low, est.High)
	}
	if est.Confidence != scanplan.ConfidenceRough || est.Basis == "" || da.Basis == "" {
		t.Errorf("confidence/basis missing: %+v", est)
	}
}

// TestEstimateUsesInsertionPointSample: a sampled record shape replaces the
// default insertion-point count.
func TestEstimateUsesInsertionPointSample(t *testing.T) {
	p := syntheticPlan(PhaseDynamicAssessment)
	est := estimatePlan(p, planEstimateInput{
		settings: config.DefaultSettings(), opts: types.DefaultOptions(), targets: 1, records: 10,
		sample: database.InsertionPointSample{Records: 10, AvgParams: 6, AvgPathSegments: 2},
	})
	// 10 × (2 + 3 × (6 + 2 + 2 headers)) + 1 host module.
	if got := est.ByPhase[string(PhaseDynamicAssessment)].Low; got != 10*(2+3*10)+1 {
		t.Errorf("low = %d", got)
	}
}

// TestEstimateMonotonicInTargets: more targets (or more records) never lower
// any phase's estimate or the total.
func TestEstimateMonotonicInTargets(t *testing.T) {
	all := []NativePhase{PhasePreflight, PhaseHeuristicsCheck, PhasePortSweep, PhaseSpidering, PhaseProbe,
		PhaseDiscovery, PhaseSeed, PhaseDynamicAssessment, PhaseKnownIssueScan}
	var prev scanplan.Estimate
	for i, n := range []int64{0, 1, 2, 5, 50} {
		est := estimateFor(syntheticPlan(all...), n, n*10)
		if i > 0 {
			if est.Low < prev.Low || est.High < prev.High {
				t.Errorf("targets %d: %d-%d lower than %d-%d", n, est.Low, est.High, prev.Low, prev.High)
			}
			for id, pe := range est.ByPhase {
				if pp := prev.ByPhase[id]; pe.Low < pp.Low || pe.High < pp.High {
					t.Errorf("targets %d: %s %d-%d lower than %d-%d", n, id, pe.Low, pe.High, pp.Low, pp.High)
				}
			}
		}
		prev = est
	}
}

// TestEstimateClampsToMaxRequests: --max-requests caps the total and the plan
// names the phases that run into it.
func TestEstimateClampsToMaxRequests(t *testing.T) {
	p := syntheticPlan(PhasePreflight, PhaseDiscovery, PhaseDynamicAssessment)
	p.Budgets.MaxRequests = 100
	est := estimateFor(p, 2, 100)
	if est.High != 100 || est.Low > 100 || est.ClampedTo == nil || *est.ClampedTo != 100 {
		t.Fatalf("clamp: %+v", est)
	}
	if len(est.HitsMaxRequests) == 0 || est.HitsMaxRequests[len(est.HitsMaxRequests)-1] != string(PhaseDynamicAssessment) {
		t.Errorf("hits_max_requests = %v", est.HitsMaxRequests)
	}
	for _, id := range est.HitsMaxRequests {
		if id == string(PhasePreflight) {
			t.Errorf("preflight (2 requests) cannot hit a 100-request budget")
		}
	}
}

// TestEstimatePaceCeiling: rate × the scan's time budget is the headline; a
// phase without a limiter (spidering) has no ceiling of its own.
func TestEstimatePaceCeiling(t *testing.T) {
	p := syntheticPlan(PhaseSpidering, PhaseDynamicAssessment)
	p.Budgets.ScanMaxDurationMS = 60_000
	p.Phases[0].Budget = &scanplan.PhaseBudget{PerTargetMS: 30_000, PhaseCeilingMS: 30_000, Semantics: scanplan.SemanticsPerTargetCapped}
	p.Phases[1].Budget = &scanplan.PhaseBudget{PhaseCeilingMS: 120_000, Semantics: scanplan.SemanticsPhase}
	est := estimateFor(p, 1, 0)
	if est.CeilingByPace == nil || *est.CeilingByPace != 10*60 {
		t.Errorf("ceiling = %v, want 600", est.CeilingByPace)
	}
	if c := est.ByPhase[string(PhaseSpidering)].CeilingByPace; c != nil {
		t.Errorf("spidering ceiling = %d, want none (no limiter)", *c)
	}
	// The phase's 2m ceiling is cut to the scan's 1m budget: 10 rps × 60s.
	if c := est.ByPhase[string(PhaseDynamicAssessment)].CeilingByPace; c == nil || *c != 600 {
		t.Errorf("dynamic-assessment ceiling = %v, want 600", c)
	}
}

// TestEstimateTargetSilentPhases: external-harvest sends nothing to the target.
func TestEstimateTargetSilentPhases(t *testing.T) {
	est := estimateFor(syntheticPlan(PhaseExternalHarvest), 5, 0)
	if pe := est.ByPhase[string(PhaseExternalHarvest)]; pe.Low != 0 || pe.High != 0 {
		t.Errorf("external-harvest = %+v", pe)
	}
}

// TestEstimateDuration: requests over the rate, each phase bounded by its own
// budget, the total by the scan's; labelled rough.
func TestEstimateDuration(t *testing.T) {
	p := syntheticPlan(PhasePreflight, PhaseDynamicAssessment)
	est := estimateFor(p, 1, 10)
	d := est.DurationMS
	if d == nil {
		t.Fatal("no duration estimate")
	}
	if d.Confidence != scanplan.ConfidenceRough || d.Basis == "" {
		t.Errorf("duration = %+v, want rough with a basis", d)
	}
	// 10 rps: the high is the request high over the rate.
	if want := est.High * 1000 / 10; d.High != want || d.Low > d.High {
		t.Errorf("duration = %+v, want high %d", d, want)
	}

	// A phase budget bounds its share; the scan budget bounds the total.
	p.Phases[1].Budget = &scanplan.PhaseBudget{PhaseCeilingMS: 5_000, Semantics: scanplan.SemanticsPhase}
	d = estimateFor(p, 1, 10).DurationMS
	if d.High > 5_000+1_000 {
		t.Errorf("phase budget ignored: %+v", d)
	}
	p.Budgets.ScanMaxDurationMS = 2_000
	d = estimateFor(p, 1, 10).DurationMS
	if d.High > 2_000 || d.Low > d.High {
		t.Errorf("scan budget ignored: %+v", d)
	}

	// Unpaced: an assumed throughput, said in the basis.
	p = syntheticPlan(PhaseDynamicAssessment)
	p.Budgets.RateLimit = 0
	d = estimateFor(p, 1, 10).DurationMS
	if d.High <= 0 || !strings.Contains(d.Basis, "assumed") {
		t.Errorf("unpaced duration = %+v", d)
	}
}
