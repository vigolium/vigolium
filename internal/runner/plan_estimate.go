package runner

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/portsweep"
	"github.com/vigolium/vigolium/pkg/scanplan"
	"github.com/vigolium/vigolium/pkg/types"
)

// Request-volume estimator for the scan plan. Pure arithmetic over the plan
// and a few counts; every number is ROUGH (confidence "rough", always) and
// every phase says how it was derived in its basis string. The only hard
// number is the pace ceiling (rate limit × the time the scan may run), which
// is why the plan headlines it when it exists.

// planEstimateInput is what the estimator reads besides the plan itself.
type planEstimateInput struct {
	settings *config.Settings
	opts     *types.Options
	// targets is the admitted target count (T).
	targets int64
	// records is the stored records in scope (R).
	records int64
	// sample is the insertion-point sample over those records.
	sample database.InsertionPointSample
}

// Estimator constants. Heuristics, documented in the basis strings.
const (
	// estDefaultInsertionPoints is the insertion points per record assumed
	// without a database sample.
	estDefaultInsertionPoints = 4.0
	// estHeaderInsertionPoints are the header insertion points a module may
	// test on every record on top of its parameters and path segments.
	estHeaderInsertionPoints = 2.0
	// estSpiderLowPerTarget / estSpiderRequestsPerState: a crawl's browser
	// requests per target (low) and per visited state (high).
	estSpiderLowPerTarget     = 20
	estSpiderRequestsPerState = 15
	// estRecursionCap bounds the recursion multiplier on discovery's high.
	estRecursionCap = 3
	// estObservedWordsPerTarget guesses the words discovery harvests from the
	// target's own responses.
	estObservedWordsPerTarget = 200
	// estNewRecordsPerTarget guesses the records discovery and spidering add
	// per target for the assessment's high.
	estNewRecordsPerTarget = 200
	// estKnownIssueLow / estKnownIssueHigh: nuclei requests per target at the
	// default critical+high severity filter.
	estKnownIssueLow  = 100
	estKnownIssueHigh = 3000
)

// tierPayloadFactor is the high-side requests per module × insertion point at
// a tier ceiling.
func tierPayloadFactor(ceiling string) int64 {
	switch ceiling {
	case modules.TagTierLight:
		return 2
	case modules.TagTierModerate:
		return 8
	default:
		return 25
	}
}

// estimatePlan fills the plan's estimate: per enabled phase low/high and its
// pace ceiling, the totals, and the --max-requests clamp.
func estimatePlan(p *scanplan.Plan, in planEstimateInput) scanplan.Estimate {
	est := scanplan.Estimate{ByPhase: map[string]scanplan.PhaseEstimate{}, Confidence: scanplan.ConfidenceRough}
	T := in.targets
	ip := estDefaultInsertionPoints
	ipBasis := fmt.Sprintf("%.0f insertion points/record (default)", ip)
	if in.sample.Records > 0 {
		ip = in.sample.AvgParams + in.sample.AvgPathSegments + estHeaderInsertionPoints
		ipBasis = fmt.Sprintf("%.1f insertion points/record (sample of %d records: %.1f params + %.1f path segments + %.0f headers)",
			ip, in.sample.Records, in.sample.AvgParams, in.sample.AvgPathSegments, estHeaderInsertionPoints)
	}

	var orderedHigh []string // enabled phases, execution order, for the clamp
	var ceilingSum int64
	ceilingKnown := true
	for _, ph := range p.Phases {
		if !ph.Enabled {
			continue
		}
		pe, ok := estimatePhase(p, ph, in, T, ip, ipBasis)
		if !ok {
			continue
		}
		if c := phasePaceCeiling(p, ph, in, T); c != nil {
			pe.CeilingByPace = c
			ceilingSum += *c
		} else if ph.SendsTarget && pe.High > 0 {
			ceilingKnown = false
		}
		est.ByPhase[ph.ID] = pe
		est.Low += pe.Low
		est.High += pe.High
		orderedHigh = append(orderedHigh, ph.ID)
	}

	// The headline: rate × the whole scan's time budget when both are set,
	// else the sum of the phases' own ceilings when every sending phase has
	// one.
	switch {
	case p.Budgets.RateLimit > 0 && p.Budgets.ScanMaxDurationMS > 0:
		c := int64(p.Budgets.RateLimit) * p.Budgets.ScanMaxDurationMS / 1000
		est.CeilingByPace = &c
	case ceilingKnown && ceilingSum > 0:
		c := ceilingSum
		est.CeilingByPace = &c
	}

	basis := []string{fmt.Sprintf("%d admitted target(s)", T)}
	if p.Targets.DBRecordsInScope != nil {
		basis = append(basis, fmt.Sprintf("%d stored record(s) in scope", in.records))
	}
	basis = append(basis, ipBasis)
	if est.CeilingByPace != nil {
		basis = append(basis, fmt.Sprintf("pace ceiling %d requests (rate limit × time budget; the only hard number)", *est.CeilingByPace))
	}

	// --max-requests: the total never exceeds it, and the plan names the
	// phases expected to run into it.
	if limit := p.Budgets.MaxRequests; limit > 0 {
		if est.High > limit {
			clamped := limit
			est.ClampedTo = &clamped
			var cum int64
			for _, id := range orderedHigh {
				cum += est.ByPhase[id].High
				if cum > limit {
					est.HitsMaxRequests = append(est.HitsMaxRequests, id)
				}
			}
			est.High = limit
			basis = append(basis, fmt.Sprintf("clamped to --max-requests %d", limit))
		}
		est.Low = min(est.Low, limit)
	}
	est.Basis = strings.Join(basis, "; ")
	est.DurationMS = estimateDuration(p, in, est)
	return est
}

// estUnpacedRPS is the throughput assumed for a phase no rate limit paces:
// what a loopback or nearby target sustains at default concurrency.
const estUnpacedRPS = 50

// estimateDuration turns the request estimate into a rough wall-clock range:
// each phase's low/high over its rate (estUnpacedRPS when unpaced), the high
// bounded by the phase's own time budget, the total bounded by the scan's.
func estimateDuration(p *scanplan.Plan, in planEstimateInput, est scanplan.Estimate) *scanplan.DurationEstimate {
	T := max(in.targets, 1)
	var low, high int64
	unpaced := false
	for _, ph := range p.Phases {
		pe, ok := est.ByPhase[ph.ID]
		if !ok || !ph.Enabled {
			continue
		}
		rate := int64(p.Budgets.RateLimit)
		if ph.Pace != nil && ph.Pace.RateLimit > 0 {
			rate = int64(ph.Pace.RateLimit)
		}
		if rate <= 0 {
			rate = estUnpacedRPS
			if pe.High > 0 {
				unpaced = true
			}
		}
		pl := pe.Low * 1000 / rate
		ph2 := pe.High * 1000 / rate
		if wall := phaseWallMS(p, ph, T); wall > 0 {
			pl = min(pl, wall)
			ph2 = min(ph2, wall)
		}
		low += pl
		high += ph2
	}
	if est.ClampedTo != nil && p.Budgets.RateLimit > 0 {
		high = min(high, *est.ClampedTo*1000/int64(p.Budgets.RateLimit))
	}
	basis := []string{"estimated requests ÷ rate limit per phase"}
	if unpaced {
		basis = append(basis, fmt.Sprintf("%d req/s assumed where no rate limit applies", estUnpacedRPS))
	}
	basis = append(basis, "bounded by each phase's time budget")
	if scanMax := p.Budgets.ScanMaxDurationMS; scanMax > 0 {
		low, high = min(low, scanMax), min(high, scanMax)
		basis = append(basis, fmt.Sprintf("capped by the scan's %s budget", time.Duration(scanMax)*time.Millisecond))
	}
	low = min(low, high)
	return &scanplan.DurationEstimate{Low: low, High: high, Basis: strings.Join(basis, "; "), Confidence: scanplan.ConfidenceRough}
}

// phaseWallMS is the longest a phase may run: its ceiling, or its per-target
// budget over the rounds its target concurrency needs. 0 when unbounded.
func phaseWallMS(p *scanplan.Plan, ph scanplan.Phase, T int64) int64 {
	if ph.Budget == nil {
		return 0
	}
	if ph.Budget.PhaseCeilingMS > 0 {
		return ph.Budget.PhaseCeilingMS
	}
	if ph.Budget.PerTargetMS > 0 {
		conc := int64(1)
		if p.Discovery != nil && NativePhase(ph.ID) == PhaseDiscovery {
			conc = int64(max(p.Discovery.TargetConcurrency, 1))
		}
		return ph.Budget.PerTargetMS * ((T + conc - 1) / conc)
	}
	return 0
}

// estimatePhase is one phase's low/high. ok is false for a phase with nothing
// to estimate (no target traffic, not modelled).
func estimatePhase(p *scanplan.Plan, ph scanplan.Phase, in planEstimateInput, T int64, ip float64, ipBasis string) (scanplan.PhaseEstimate, bool) {
	settings, opts := in.settings, in.opts
	switch NativePhase(ph.ID) {
	case PhasePreflight:
		return scanplan.PhaseEstimate{Low: T, High: T, Basis: "one GET per admitted target"}, true

	case PhaseHeuristicsCheck:
		high := 3 * T
		if opts.HeuristicsCheck == "advanced" {
			high = 6 * T
		}
		return scanplan.PhaseEstimate{Low: T, High: high, Basis: "root-page probes per target (" + opts.HeuristicsCheck + ")"}, true

	case PhasePortSweep:
		ports := int64(len(portsweep.DefaultPorts))
		if n := len(settings.ScanningStrategy.PortSweep.Ports); n > 0 {
			ports = int64(n)
		}
		if n := len(parsePortList(opts.PortSweepPorts)); n > 0 {
			ports = int64(n)
		}
		return scanplan.PhaseEstimate{Low: T, High: T * ports, Basis: fmt.Sprintf("up to %d alternate ports per target host", ports)}, true

	case PhaseExternalHarvest:
		return scanplan.PhaseEstimate{Basis: "archive and OSINT queries only; no request reaches the target"}, true

	case PhaseHarvestProbe:
		maxURLs := int64(0)
		if p.Harvest != nil {
			maxURLs = int64(p.Harvest.MaxURLs)
		}
		return scanplan.PhaseEstimate{Low: T, High: T + T*maxURLs, Basis: fmt.Sprintf("one liveness request per host, then one GET per harvested URL (≤ %d per domain)", maxURLs)}, true

	case PhaseSpidering:
		states := int64(settings.Spidering.MaxStates)
		if states <= 0 {
			states = 1500
		}
		return scanplan.PhaseEstimate{
			Low:   T * estSpiderLowPerTarget,
			High:  T * states * estSpiderRequestsPerState,
			Basis: fmt.Sprintf("browser: %d requests/target low; %d states × %d requests/state high (heuristic)", estSpiderLowPerTarget, states, estSpiderRequestsPerState),
		}, true

	case PhaseProbe:
		return scanplan.PhaseEstimate{Low: T, High: 2 * T, Basis: "one request per target plus redirects"}, true

	case PhaseFingerprint:
		depth := fingerprintDepthFor(in.opts, int(T))
		low, high := fingerprintRequestsPerOrigin(depth)
		return scanplan.PhaseEstimate{Low: T * low, High: T * high,
			Basis: fmt.Sprintf("%s depth: %d-%d reads per origin", depth, low, high)}, true

	case PhaseDiscovery:
		var short, long, fuzz int64
		if p.Discovery != nil {
			for _, w := range p.Discovery.Wordlists {
				if w.Lines == nil {
					continue
				}
				switch w.Slot {
				case wordlistSlotShortFile, wordlistSlotShortDir:
					short += *w.Lines
				case wordlistSlotLongFile, wordlistSlotLongDir:
					long += *w.Lines
				case wordlistSlotFuzz:
					fuzz += *w.Lines
				}
			}
		}
		perTarget := short + long + fuzz
		low := T * perTarget
		factor := int64(1)
		if p.Discovery != nil && p.Discovery.RecursionEnabled {
			factor = int64(min(max(p.Discovery.RecursionMaxDepth, 1), estRecursionCap))
		}
		high := low*factor + T*estObservedWordsPerTarget
		basis := fmt.Sprintf("%d wordlist words/target (short %d, long %d, fuzz %d); high × recursion %d + %d observed words/target",
			perTarget, short, long, fuzz, factor, estObservedWordsPerTarget)
		return scanplan.PhaseEstimate{Low: low, High: high, Basis: basis}, true

	case PhaseTargetedReSpider:
		rs := &settings.Discovery.ReSpider
		seeds := int64(rs.SeedsTotal())
		return scanplan.PhaseEstimate{High: seeds * int64(rs.PerSeedStates()) * estSpiderRequestsPerState,
			Basis: fmt.Sprintf("only when discovery surfaces SPA routes: ≤ %d seeds × %d states", seeds, rs.PerSeedStates())}, true

	case PhaseSeed:
		return scanplan.PhaseEstimate{Low: T, High: T, Basis: "one request per target to seed the database"}, true

	case PhaseParamMining:
		if p.ParamMining == nil {
			return scanplan.PhaseEstimate{}, false
		}
		hosts := max(T, 1)
		endpoints := hosts * int64(p.ParamMining.EndpointsPerHost)
		if in.records > 0 {
			endpoints = min(endpoints, in.records)
		}
		return scanplan.PhaseEstimate{
			Low:   min(endpoints, hosts*5) * 10,
			High:  endpoints * int64(p.ParamMining.RequestsPerEndpoint),
			Basis: fmt.Sprintf("≤ %d endpoints/host × %d requests/endpoint", p.ParamMining.EndpointsPerHost, p.ParamMining.RequestsPerEndpoint),
		}, true

	case PhaseDynamicAssessment:
		mi := int64(p.Modules.ByScope[scanplan.ScopeInsertionPoint])
		mr := int64(p.Modules.ByScope[scanplan.ScopeRequest])
		mh := int64(p.Modules.ByScope[scanplan.ScopeHost])
		hosts := max(T, 1)
		nLow := max(in.records, T)
		nHigh := in.records + T
		if planRuns(p, PhaseDiscovery) || planRuns(p, PhaseSpidering) {
			nHigh += T * estNewRecordsPerTarget
		}
		perRecord := float64(mr) + float64(mi)*ip
		low := int64(math.Ceil(float64(nLow)*perRecord)) + mh*hosts
		high := int64(math.Ceil(float64(nHigh)*perRecord))*tierPayloadFactor(p.Modules.TierCeiling) + mh*hosts*tierPayloadFactor(p.Modules.TierCeiling)
		basis := fmt.Sprintf("%d-%d records × (%d request + %d insertion-point modules × %s) + %d host modules × %d hosts; high × %d payloads/test (tier %s)",
			nLow, nHigh, mr, mi, ipBasis, mh, hosts, tierPayloadFactor(p.Modules.TierCeiling), p.Modules.TierCeiling)
		return scanplan.PhaseEstimate{Low: low, High: high, Basis: basis}, true

	case PhaseKnownIssueScan:
		return scanplan.PhaseEstimate{Low: T * estKnownIssueLow, High: T * estKnownIssueHigh,
			Basis: fmt.Sprintf("nuclei: %d-%d requests/target (template count not read)", estKnownIssueLow, estKnownIssueHigh)}, true
	}
	return scanplan.PhaseEstimate{}, false
}

// phasePaceCeiling is rate × the phase's wall-clock budget, when both are
// finite: the most requests the phase CAN send, whatever the estimate says.
func phasePaceCeiling(p *scanplan.Plan, ph scanplan.Phase, in planEstimateInput, T int64) *int64 {
	if !ph.SendsTarget || ph.Budget == nil {
		return nil
	}
	rate := int64(p.Budgets.RateLimit)
	if ph.Pace != nil && ph.Pace.RateLimit > 0 {
		rate = int64(ph.Pace.RateLimit)
	}
	switch NativePhase(ph.ID) {
	case PhaseSpidering:
		// The browser has no limiter: no pace ceiling.
		return nil
	case PhaseDiscovery:
		if ph.Pace == nil || ph.Pace.RateLimit <= 0 {
			return nil // unpaced unless discovery's rate is set explicitly
		}
	}
	if rate <= 0 {
		return nil
	}
	wall := time.Duration(ph.Budget.PhaseCeilingMS) * time.Millisecond
	if wall <= 0 && ph.Budget.PerTargetMS > 0 {
		conc := int64(1)
		if p.Discovery != nil && NativePhase(ph.ID) == PhaseDiscovery {
			conc = int64(max(p.Discovery.TargetConcurrency, 1))
		}
		rounds := (max(T, 1) + conc - 1) / conc
		wall = time.Duration(ph.Budget.PerTargetMS) * time.Millisecond * time.Duration(rounds)
	}
	if scanMax := time.Duration(p.Budgets.ScanMaxDurationMS) * time.Millisecond; scanMax > 0 && (wall <= 0 || wall > scanMax) {
		wall = scanMax
	}
	if wall <= 0 {
		return nil
	}
	c := rate * int64(wall/time.Second)
	return &c
}

// planRuns reports whether the plan has phase enabled.
func planRuns(p *scanplan.Plan, phase NativePhase) bool {
	ph := p.Phase(string(phase))
	return ph != nil && ph.Enabled
}
