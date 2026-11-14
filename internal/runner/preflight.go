package runner

import (
	"context"
	"errors"
	"fmt"
	neturl "net/url"
	"os"
	"strings"
	"sync"

	"github.com/sourcegraph/conc/pool"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// Preflight: one GET per admitted CLI target, before any phase runs, so a scan
// whose targets do not answer says so instead of running every phase against
// nothing and reporting success.
//
// The request goes to the target URL itself, not its root: scan-request may
// name a POST endpoint, and a GET to the same URL proves the transport (DNS,
// connect, TLS, an HTTP answer of any status) without replaying the request.
// It is sent through the scan's shared requester on the egress gate's priority
// lane, so it is paced, proxied and counted like every other target request.
//
// # It does not follow redirects, and that is the whole of the question it asks
//
// A 3xx IS an HTTP answer, so a target that sends one has answered. Following
// meant the verdict belonged to wherever the chain ENDED: a target answering a
// 301 that pointed at a dead host was reported as unreachable itself, and a
// scan whose every target did that aborted with no_targets_reachable before a
// phase ran. It also made liveness depend on --redirect-mode, a recording
// policy rather than a reachability one. Not following makes the four modes
// agree and costs one request instead of one per hop.
//
// Repairing it after the fact, the way executor_fetch.go re-points a relocated
// response, is not available here: ExecuteContext returns no chain at all when
// a hop fails (nil, 0, err), so the target's own 3xx is gone by the time the
// class is assigned. (The failing hop's URL does survive, inside the
// *url.Error — executor_fetch.go's own error path still attributes it to the
// seed, which is the same defect one layer down and not fixed here.)
//
// The answer is kept: the heuristics phase probes each target's root page, and
// when the target IS its root it classifies the bytes preflight already holds
// instead of sending the same GET again (see preflightFor). With heuristics on
// (the default) the check therefore costs nothing extra for root targets — and
// those bytes are now the target's own response, including a 3xx. fetchRoot
// does the same, or --skip preflight would change which phases run.

// preflightProbe is one target's preflight answer: the full response when it
// answered, else the transport error class and detail.
type preflightProbe struct {
	target  string
	reached bool
	resp    []byte
	class   string // http.TransportErr* when !reached
	detail  string
}

// ErrNoTargetsReachable is what RunNativeScan's error wraps when none of the
// admitted CLI targets answered the preflight GET: no phase ran. Match it with
// errors.Is; errors.As on *TargetsUnreachableError gives each target and why.
var ErrNoTargetsReachable = errors.New("no targets reachable")

// TargetsUnreachableError is the typed form of ErrNoTargetsReachable.
type TargetsUnreachableError struct {
	// Unreachable names each admitted target and its transport error class.
	Unreachable []database.TargetIssue
	// Hint is an extra remediation clause (e.g. the scheme was assumed), or "".
	Hint string
}

func (e *TargetsUnreachableError) Error() string {
	msg := fmt.Sprintf("%s: none of %d admitted target(s) answered: %s",
		ErrNoTargetsReachable, len(e.Unreachable), describeUnreachable(e.Unreachable, 5))
	if e.Hint != "" {
		msg += "; " + e.Hint
	}
	return msg
}

func (e *TargetsUnreachableError) Unwrap() error { return ErrNoTargetsReachable }

// describeUnreachable renders unreachable targets as "target (connection
// refused)", comma separated, naming at most limit of them (limit <= 0 names all).
func describeUnreachable(issues []database.TargetIssue, limit int) string {
	return describeTargets(issues, limit, func(v database.TargetIssue) (string, string) {
		return v.Target, http.DescribeTransportClass(v.Code)
	})
}

// preflightApplies reports whether this run checks its admitted targets before
// the phases. Callers have already established that the targets are the input
// (targetAdmission non-nil, which excludes scan-on-receive and non-target
// inputs). Skipped for --skip preflight, for a standalone host sweep (the probe
// phase has its own reachability accounting), and for a plan that never
// reaches the target (`run external-harvest` must stay target-silent).
func (r *Runner) preflightApplies(plan NativeScanPlan) bool {
	return !r.options.SkipPreflight && !IsProbeOnlyRun(r.options) && plan.SendsTargetTraffic()
}

// preflightKey is the identity a preflight answer is stored and looked up
// under: the URL with an empty path written as "/" and no fragment, so a target
// typed as http://host and the root heuristics probes (http://host/) match.
func preflightKey(raw string) string {
	u, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.TrimSpace(raw)
	}
	if u.Path == "" && u.RawPath == "" {
		u.Path = "/"
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// preflightFor returns the preflight answer stored for url, or nil when
// preflight did not fetch it. Read-only after runPreflight, so safe from the
// heuristics workers.
func (r *Runner) preflightFor(url string) *preflightProbe {
	if r.preflight == nil {
		return nil
	}
	return r.preflight[preflightKey(url)]
}

// fetchPreflight sends one GET to target and records the outcome.
func fetchPreflight(ctx context.Context, requester *http.Requester, target string) *preflightProbe {
	p := &preflightProbe{target: target}
	rr, err := httpmsg.GetRawRequestFromURL(target)
	if err != nil {
		p.class, p.detail = http.TransportErrOther, "invalid target: "+err.Error()
		return p
	}
	chain, _, err := requester.ExecuteContext(ctx, rr, http.Options{
		DisableCompression: true,
		NoRedirects:        true,
		// A plain GET learning whether the host answers: a timed-out attempt
		// is safe to retry (SAFE-10 keeps timeouts unretried by default).
		RetryTimeouts: true,
	})
	if err != nil {
		p.class, p.detail = http.ClassifyTransportError(err), err.Error()
		return p
	}
	p.reached = true
	p.resp = chain.FullResponseBytes() // a copy; the chain's buffers go back to the pool
	chain.Close()
	return p
}

// probePreflightTargets fetches every distinct target concurrently (bounded
// like the heuristics probe) and returns the answers by preflightKey. A target
// skipped because ctx was cancelled has no entry.
func probePreflightTargets(ctx context.Context, requester *http.Requester, targets []string) map[string]*preflightProbe {
	out := make(map[string]*preflightProbe, len(targets))
	var mu sync.Mutex
	seen := make(map[string]struct{}, len(targets))
	p := pool.New().WithMaxGoroutines(heuristicsProbeConcurrency(len(targets)))
	for _, target := range targets {
		key := preflightKey(target)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		target := target
		p.Go(func() {
			if ctx.Err() != nil {
				return
			}
			probe := fetchPreflight(ctx, requester, target)
			// A request cut off by cancellation says nothing about the target.
			if !probe.reached && ctx.Err() != nil {
				return
			}
			mu.Lock()
			out[key] = probe
			mu.Unlock()
		})
	}
	p.Wait()
	return out
}

// applyPreflightTally fills the preflight outcome's tally from the answers:
// Reached, each unreachable target with its class, and targets_unreachable
// when some (not all) admitted targets did not answer. It reports how many
// targets answered and whether every admitted target was checked; an
// incomplete check (interrupted) leaves the tally's reachability unset.
func applyPreflightTally(o *database.PhaseOutcome, admitted []string, probes map[string]*preflightProbe) (reached int, checked bool) {
	if o.Targets == nil {
		o.Targets = &database.TargetTally{}
	}
	var unreachable []database.TargetIssue
	for _, target := range admitted {
		probe := probes[preflightKey(target)]
		if probe == nil {
			return 0, false
		}
		if probe.reached {
			reached++
			continue
		}
		unreachable = append(unreachable, database.TargetIssue{Target: target, Code: probe.class, Detail: probe.detail})
	}
	o.Targets.Reached = reached
	o.Targets.ReachabilityChecked = true
	for _, issue := range unreachable {
		o.Targets.AddUnreachable(issue)
	}
	reasons := make(map[string]struct{}, len(o.Reasons)+1)
	for _, reason := range o.Reasons {
		reasons[reason] = struct{}{}
	}
	switch {
	case reached == 0 && len(admitted) > 0:
		reasons[database.ReasonNoTargetsReachable] = struct{}{}
	case len(unreachable) > 0:
		reasons[database.ReasonTargetsUnreachable] = struct{}{}
	}
	o.Reasons = database.SortedCodes(reasons)
	o.State = database.ResolvePhaseState(0, o.Reasons, false)
	return reached, true
}

// runPreflight checks the admitted targets and completes the preflight
// outcome. It returns *TargetsUnreachableError when none answered, after
// setting the scan's stop reason; the caller appends the outcome either way.
//
// Unreachable targets are kept in the plan when others answered: dropping them
// would save the later phases' timeouts but turn a transient blip into a silent
// drop. The row says which ones did not answer (targets_unreachable, partial).
func (r *Runner) runPreflight(ctx context.Context, infra *phaseInfra, admitted []string, o *database.PhaseOutcome) error {
	if infra == nil || infra.httpRequester == nil || len(admitted) == 0 {
		return nil
	}
	// Priority lane: the whole scan waits on this answer, so it may use a
	// host's reserved headroom instead of queueing behind module traffic.
	probes := probePreflightTargets(ctx, infra.httpRequester.WithLane(egress.LanePriority), admitted)
	reached, checked := applyPreflightTally(o, admitted, probes)
	if !checked {
		// Interrupted: no verdict. The phase loop records the cancellation.
		return nil
	}
	r.preflight = probes

	var unreachable []database.TargetIssue
	for _, target := range admitted {
		if probe := probes[preflightKey(target)]; probe != nil && !probe.reached {
			unreachable = append(unreachable, database.TargetIssue{Target: target, Code: probe.class, Detail: probe.detail})
		}
	}
	for _, issue := range unreachable {
		line := fmt.Sprintf("target %s did not answer (%s: %s)", issue.Target, issue.Code, issue.Detail)
		r.scanLogger.Warn(string(PhasePreflight), line)
		zap.L().Warn("Preflight: target unreachable",
			zap.String("target", issue.Target), zap.String("class", issue.Code), zap.String("detail", issue.Detail))
	}
	if len(unreachable) > 0 && !r.options.Silent {
		for _, issue := range unreachable {
			fmt.Fprintf(os.Stderr, "  %s %s unreachable %s\n",
				terminal.Red(terminal.SymbolError),
				terminal.Cyan(issue.Target),
				terminal.Gray("("+http.DescribeTransportClass(issue.Code)+")"))
		}
		fmt.Fprintf(os.Stderr, "  %s Preflight: %s targets answered\n",
			terminal.Yellow(terminal.SymbolWarning),
			terminal.Orange(fmt.Sprintf("%d/%d", reached, len(admitted))))
	}

	if reached > 0 {
		return nil
	}
	r.scanOutcome.setStopReason(database.ReasonNoTargetsReachable)
	err := &TargetsUnreachableError{Unreachable: unreachable, Hint: r.assumedSchemeHint(admitted)}
	r.scanLogger.Error(string(PhasePreflight), err.Error())
	return err
}

// assumedSchemeHint names the fix when a target's scheme was guessed (a
// schemeless -t defaults to http) and nothing answered on it.
func (r *Runner) assumedSchemeHint(targets []string) string {
	if len(r.options.TargetsSchemeAssumed) == 0 {
		return ""
	}
	for _, t := range targets {
		if _, assumed := r.options.TargetsSchemeAssumed[t]; assumed {
			return "a schemeless target was assumed http://; pass https:// explicitly if it serves TLS"
		}
	}
	return ""
}
