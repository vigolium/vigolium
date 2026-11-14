package runner

import (
	"context"
	"errors"
	"fmt"
	"github.com/vigolium/vigolium/pkg/authentication"
	nethttp "net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
	"go.uber.org/zap"
)

// spiderDOMXssModuleID labels DOM-XSS findings synthesized by the spider's browser
// probe (not a registered scanner module — the finding's Info is self-describing).
const spiderDOMXssModuleID = "spider-dom-xss"

// emitSpiderDOMXssFindings persists the crawl's browser-confirmed DOM-XSS findings.
// Each was proven by observing an injection canary execute in a real browser, so it
// is a firm finding — attributed to a spider-scoped module id with a self-describing
// Info block (it is not produced by a registered scanner module).
func (r *Runner) emitSpiderDOMXssFindings(ctx context.Context, scanUUID string, findings []spitolas.DOMXssFinding) {
	if r.repository == nil {
		return
	}
	// The crawl typically consumes the whole spidering-phase deadline, so ctx is
	// often already expired here. These findings are browser-confirmed and must be
	// persisted regardless — save under a fresh short-lived context.
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
	}
	for _, f := range findings {
		host := httpmsg.HostnameFromURL(f.URL)
		event := &output.ResultEvent{
			ModuleID:         spiderDOMXssModuleID,
			ModuleType:       database.ModuleTypeActive,
			FindingSource:    database.FindingSourceSpidering,
			RecordKind:       output.RecordKindFinding,
			EvidenceGrade:    output.EvidenceGradeImpact,
			Host:             host,
			URL:              f.URL,
			Matched:          f.URL,
			FuzzingParameter: f.Param,
			ExtractedResults: []string{
				"Parameter: " + f.Param,
				"Payload: " + f.Payload,
				"Sink: " + f.Evidence,
			},
			Info: output.Info{
				Name:        "DOM-based XSS (Browser-Confirmed)",
				Description: "A reflected client-route parameter flows into a DOM HTML sink (e.g. innerHTML / Angular bypassSecurityTrustHtml) without sanitization. A headless browser navigated the route with an injection canary and observed it execute (img onerror), so arbitrary JavaScript runs in a victim's browser via a crafted link. Fix: contextually encode URL-derived data on output, avoid dangerous DOM sinks, and enforce a strict Content-Security-Policy.",
				Severity:    severity.Medium,
				Confidence:  severity.Certain,
				Tags:        []string{"xss", "dom-xss", "browser", "spidering"},
			},
			ModuleShort: "Browser-confirmed DOM-based XSS on a reflected client route",
		}
		if err := r.repository.SaveFinding(ctx, event, nil, scanUUID, r.options.ProjectUUID); err != nil {
			zap.L().Warn("Spidering: failed to persist DOM-XSS finding", zap.String("url", f.URL), zap.Error(err))
		}
	}
}

// spideringPhaseBudgetCap bounds how many per-target max-duration budgets the
// whole spidering phase may consume. Each target still gets its own full
// max-duration; the overall phase deadline is max-duration × min(targets, cap),
// so a small target list is unaffected while a large merged list (CLI targets +
// many in-scope DB hosts) can't blow the phase out to len(targets) × max-duration.
//
// Exported because it is the number the CLI's fan-out hint quotes: the phase
// crawls a bounded number of hosts at a time (VIGOLIUM_SPIDER_HOST_PARALLELISM, default 2), so on a target list larger than this the cap — not
// the pace flags — is what decides how much of the list is reached, and the
// operator has to be told the figure to act on it. One constant, so the hint and
// the ceiling it describes cannot drift apart.
const spideringPhaseBudgetCap = 8

// spideringPhaseCeiling returns the overall wall-clock budget for the spidering
// phase. Each of numTargets gets up to maxDuration, but the total is capped at
// max-duration × min(numTargets, spideringPhaseBudgetCap). A non-positive
// maxDuration (unlimited) or non-positive target count returns 0, meaning "no
// ceiling" — the caller should then run without a phase deadline.
func spideringPhaseCeiling(maxDuration time.Duration, numTargets int) time.Duration {
	if maxDuration <= 0 || numTargets <= 0 {
		return 0
	}
	return maxDuration * time.Duration(min(numTargets, spideringPhaseBudgetCap))
}

// deadlineWithin reports whether ctx is done or its deadline is no more than d
// away — too close to start a crawl that would drain for d before it.
func deadlineWithin(ctx context.Context, d time.Duration) bool {
	if ctx.Err() != nil {
		return true
	}
	if d <= 0 {
		return false
	}
	deadline, ok := ctx.Deadline()
	return ok && time.Until(deadline) <= d
}

// targetBudgetUsed is targetBudgetExhausted for a crawl that drains: the
// crawler stops grace before its deadline, so a target that used its budget
// returns with up to grace left rather than with its deadline fired. Only the
// target's OWN deadline counts — when the phase ceiling (parent) is the earlier
// one, the target was cut short by the phase, not by its budget. Ask it before
// cancelling target.
func targetBudgetUsed(target, parent context.Context, grace time.Duration) bool {
	if targetBudgetExhausted(target, parent) {
		return true
	}
	if grace <= 0 || target.Err() != nil || parent.Err() != nil {
		return false
	}
	own, ok := target.Deadline()
	if !ok {
		return false
	}
	if inherited, ok := parent.Deadline(); ok && !inherited.After(own) {
		return false
	}
	return time.Until(own) <= grace
}

// spideringTeardownGrace is how long past a target's max-duration the watchdog
// waits before declaring RunSpider wedged. Legitimate teardown (browser/page
// close, record-writer drain) is bounded and quick; this only fires on a true
// hang — e.g. an unresponsive/anti-bot browser, or a rod CDP call without a
// bound — guaranteeing the spidering phase can never block the scan forever.
//
// A var, not a const, only so a test can shorten it: a wedged-teardown test at
// the production value would take 90 seconds.
var spideringTeardownGrace = 90 * time.Second

// runWithWatchdog runs work in a goroutine and returns its result, or — if work
// does not finish within timeout — calls onTimeout and returns that instead,
// along with whether the watchdog fired. The work goroutine is abandoned on
// timeout (it leaks until it finishes on its own, if ever), which is the whole
// point: a wedged operation can never block the caller past timeout. The done
// channel is buffered so a late-finishing abandoned worker never blocks on send.
// Generic + side-effect-free so it can be unit-tested without a browser.
//
// The wedged bool is returned rather than encoded into the result because it is
// the one fact only this function knows, and callers need it to decide whether a
// browser session can still be closed: a wedge must be abandoned (closing an
// unresponsive browser hangs the very phase the watchdog protects), while an
// ordinary crawl failure leaves a healthy browser AND a record writer still
// holding that host's captured traffic. Conflating them leaked a Chrome process
// per host group and discarded records earlier seeds had already produced.
// Returning it keeps the distinction impossible to lose in transit.
func runWithWatchdog[T any](timeout time.Duration, work func() T, onTimeout func() T) (result T, wedged bool) {
	done := make(chan T, 1)
	go func() { done <- work() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case v := <-done:
		return v, false
	case <-timer.C:
		return onTimeout(), true
	}
}

// crawlOutcome is what both watchdog wrappers return: the crawl's own result and
// error, plus whether the watchdog fired. wedged is NOT derivable from err —
// both a wedge and an ordinary navigation failure produce a non-nil error, and
// only the first means the browser cannot be safely closed.
type crawlOutcome struct {
	res    *spitolas.SpiderResult
	err    error
	wedged bool
}

// capture is the receipt a phase total should fold in for this crawl.
//
// A wedged crawl has no trustworthy receipt — the watchdog abandoned it with the
// writer still open — so it contributes an explicitly incomplete one. An
// ordinary failure does have a receipt: RunSpider returns a partial result
// carrying it alongside the error, deliberately, so a failed crawl's account is
// not lost. A crawl with neither contributes nothing.
func (oc crawlOutcome) capture() spitolas.CaptureReceipt {
	switch {
	case oc.wedged:
		return spitolas.IncompleteCaptureReceipt()
	case oc.res != nil:
		return oc.res.Capture
	default:
		return spitolas.CaptureReceipt{}
	}
}

// sessionCapture is the receipt a phase total should fold in for a shared
// SpiderSession, and the one place that decides whether to close it.
//
// A session abandoned after a wedged crawl is left to the process to reclaim,
// exactly as the per-target watchdog does — closing a browser that did not
// answer would hang the phase we are trying to protect — so its running
// snapshot (never complete) is the account. A live session is closed, which
// yields its final receipt.
func sessionCapture(sess respiderSession, rw *database.RecordWriter, abandoned bool) spitolas.CaptureReceipt {
	if abandoned {
		return sess.Receipt()
	}
	return closeReSpiderSession(sess, rw)
}

// dumpWedgedGoroutines logs the watchdog's diagnosis: which operation hung, and
// a full goroutine dump so the stuck call site is identifiable after the fact.
func dumpWedgedGoroutines(what, subject string, budget time.Duration) {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	zap.L().Error(what+" watchdog fired — did not return within budget+grace; abandoning the run (browser/goroutines leak until exit)",
		zap.String("subject", subject),
		zap.Duration("budget", budget),
		zap.Duration("grace", spideringTeardownGrace))
	zap.L().Warn(what + " watchdog goroutine dump follows:\n" + string(buf[:n]))
}

// runSpiderWatchdog runs spitolas.RunSpider (and closes rw) under a hard
// watchdog: it always returns within budget + spideringTeardownGrace. If the run
// wedges past that, it logs a full goroutine dump (so the stuck call site is
// diagnosable) and returns wedged=true rather than hanging the scan; the stuck
// run and its browser are abandoned and leak until the process exits. rw is
// closed inside the worker so a stuck close is abandoned with it, not awaited.
func runSpiderWatchdog(ctx context.Context, cfg spitolas.SpiderConfig, rw *database.RecordWriter, budget time.Duration, target string) crawlOutcome {
	oc, wedged := runWithWatchdog(
		budget+spideringTeardownGrace,
		func() crawlOutcome {
			res, err := spitolas.RunSpider(ctx, cfg, rw)
			rw.Close()
			return crawlOutcome{res: res, err: err}
		},
		func() crawlOutcome {
			dumpWedgedGoroutines("Spidering", target, budget)
			return crawlOutcome{err: fmt.Errorf("spidering timed out for %s (exceeded %s)", target, budget+spideringTeardownGrace)}
		},
	)
	oc.wedged = wedged
	return oc
}

// runReSpiderSessionCrawl runs one seed on a shared SpiderSession under the same
// hang-proofing as runSpiderWatchdog: if Crawl does not return within
// budget+grace the run is abandoned (the shared browser/goroutines leak until
// exit) and wedged=true tells the caller not to close the host session.
func runReSpiderSessionCrawl(ctx context.Context, sess *spitolas.SpiderSession, seedURL string, budget time.Duration) crawlOutcome {
	oc, wedged := runWithWatchdog(
		budget+spideringTeardownGrace,
		func() crawlOutcome {
			res, err := sess.Crawl(ctx, seedURL)
			return crawlOutcome{res: res, err: err}
		},
		func() crawlOutcome {
			dumpWedgedGoroutines("Re-spider session-crawl", seedURL, budget)
			return crawlOutcome{err: fmt.Errorf("re-spider seed timed out for %s (exceeded %s)", seedURL, budget+spideringTeardownGrace)}
		},
	)
	oc.wedged = wedged
	return oc
}

// respiderSession is what closeReSpiderSession needs of a SpiderSession: drain
// it, give up on it, and report what its capture got.
//
// An interface purely so the teardown-watchdog path is testable without a
// browser — and specifically so the kill-on-wedge escalation is. That branch only
// runs when a real Chromium has stopped answering, which no unit test can arrange.
// *spitolas.SpiderSession is the only production implementation.
type respiderSession interface {
	Close() error
	Kill()
	Receipt() spitolas.CaptureReceipt
}

// closeReSpiderSession flushes and tears down a shared SpiderSession (and its
// backing RecordWriter) under a teardown watchdog, so a wedged browser close
// can't hang the phase. It returns the session's capture receipt: final when
// the close completed, the running snapshot (never complete) when the watchdog
// abandoned it.
func closeReSpiderSession(sess respiderSession, rw *database.RecordWriter) spitolas.CaptureReceipt {
	rc, _ := runWithWatchdog(
		spideringTeardownGrace,
		func() spitolas.CaptureReceipt {
			if err := sess.Close(); err != nil {
				zap.L().Warn("Spider session closed with lost records", zap.Error(err))
			}
			rw.Close()
			return sess.Receipt()
		},
		func() spitolas.CaptureReceipt {
			zap.L().Error("Re-spider session-close watchdog fired — browser teardown wedged; killing the browser process")
			// The abandoned Close goroutine still holds the browser's and the
			// pool's locks, so Kill deliberately takes neither (see
			// SpiderSession.Kill). In its own goroutine because the launcher's kill
			// has a built-in wait and this path exists to return promptly.
			go sess.Kill()
			return sess.Receipt()
		},
	)
	return rc
}

// captureOutcome maps a browser capture receipt onto the persistence vocabulary
// the scan row and the event stream report.
//
// The two types stay separate deliberately — see spitolas.CaptureReceipt. The
// receipt distinguishes Refused (known turned away) from the writer's Unknown
// (may have landed), and a spec-ingested endpoint can legitimately push
// Persisted past Accepted; collapsing them would lose the first distinction and
// produce negative counts on the second. This is the translation, not a merge.
func captureOutcome(rc spitolas.CaptureReceipt) database.PersistenceOutcome {
	if !rc.Enabled {
		return database.PersistenceOutcome{}
	}
	o := database.PersistenceOutcome{
		Writer:    database.PersistenceWriterRecords,
		Accepted:  int64(rc.Accepted),
		Committed: int64(rc.Persisted),
		// Refused and Failed are both "captured and did not reach the database",
		// which is what Failed means on this side; Unknown is reserved for the
		// entries an abandoned drain never resolved either way.
		Failed: int64(rc.Lost()),
	}
	if !rc.DrainComplete {
		o.TimedOut = true
		// Clamped: Persisted counts spec-ingested rows the capture never
		// accepted, so the difference can be negative without anything being
		// wrong.
		if unknown := o.Accepted - o.Committed - o.Failed; unknown > 0 {
			o.Unknown = unknown
		}
	}
	return o
}

// recordCapture folds a phase's total browser-capture receipt into its outcome,
// so a crawl that lost records says so where every other lost write does — on
// the phase outcome, hence in phase_outcomes and on scan.finished.
//
// Spidering and re-spider were the only phases left whose writer loss reached
// nothing but a yellow suffix on a stderr line: they close their RecordWriter
// fire-and-forget rather than through shutdownWriters, so a crawl that lost its
// entire corpus to a failing database still wrote state: "completed".
//
// Both halves are needed. addPersistence marks the phase partial on Failed or
// Unknown; a receipt abandoned before its writer drained carries NO counts at
// all (IncompleteCaptureReceipt), so it is clean by that rule and lost by the
// receipt's own. The receipt is the authority on whether capture is accounted
// for, so its verdict is applied directly. markPartial is idempotent per code,
// so the overlapping case records one reason.
func recordCapture(t *phaseTracker, rc spitolas.CaptureReceipt) {
	if !rc.Enabled {
		return
	}
	t.addPersistence(captureOutcome(rc))
	if !rc.Clean() {
		t.markPartial(database.ReasonPersistence)
	}
}

// captureIncompleteNote is the completion-line suffix for a phase whose
// capture lost records or never finished draining; "" when nothing was lost.
func captureIncompleteNote(rc spitolas.CaptureReceipt) string {
	if rc.Clean() {
		return ""
	}
	if lost := rc.Lost(); lost > 0 {
		return fmt.Sprintf(" (%d failed — run incomplete)", lost)
	}
	return " (capture did not finish draining — run incomplete)"
}

// groupByHost groups items by the host their key function returns, preserving
// both the order hosts first appear and each host's own item order, so one
// browser context can crawl all of a host's items consecutively. An item with no
// resolvable host gets its own group rather than being dropped.
//
// Shared by the spidering and re-spider phases: both need exactly this ordering
// contract, and the only thing that differs between them is the element type.
func groupByHost[T any](items []T, host func(T) string) [][]T {
	idx := make(map[string]int, len(items))
	var groups [][]T
	for _, item := range items {
		h := host(item)
		if h == "" {
			groups = append(groups, []T{item})
			continue
		}
		if i, ok := idx[h]; ok {
			groups[i] = append(groups[i], item)
			continue
		}
		idx[h] = len(groups)
		groups = append(groups, []T{item})
	}
	return groups
}

// buildSpiderConfig assembles the crawl configuration for one target: browser
// settings from the resolved spidering config, the operator's auth bridge and
// scope boundary, and the intensity-derived login and registration policy.
//
// Both browser phases build from here. They differ only in their budgets and
// their record source, which the caller overrides — everything else (the auth
// bridge, the scope adapter, the intensity policy, the graph output) is one
// decision, and keeping two copies is how a field added to one phase silently
// goes missing from the other.
func (r *Runner) buildSpiderConfig(target string, settingsCfg config.SpideringConfig, maxDuration time.Duration, infra *phaseInfra) spitolas.SpiderConfig {
	rp := resolveBrowserPolicy(settingsCfg, r.options.Intensity)
	rp.applyTrafficPolicy(r.options.TrafficPolicy)
	policy := rp.policy
	compat := resolveBrowserCompat(settingsCfg)
	// Bridge the operator's session/custom headers into the browser so the crawl
	// explores authenticated content, not just the login shell.
	browserCookies, browserHeaders := browserAuthFromHeaders(r.options.Headers)

	cfg := spitolas.SpiderConfig{
		TargetURL:           target,
		MaxDepth:            settingsCfg.MaxDepth,
		MaxStates:           settingsCfg.MaxStates,
		MaxDuration:         maxDuration,
		DrainGrace:          SpideringGrace(maxDuration),
		MaxConsecutiveFails: settingsCfg.MaxConsecutiveFails,
		Headless:            settingsCfg.Headless,
		BrowserCount:        settingsCfg.BrowserCount,
		Tabs:                settingsCfg.Tabs,
		TabIsolation:        settingsCfg.TabIsolation,
		Strategy:            settingsCfg.Strategy,
		IncludeResponseBody: settingsCfg.IncludeResponseBody,
		IncludeHeaders:      true,
		Silent:              r.options.Silent,
		Verbose:             r.options.Verbose,
		BrowserEngine:       settingsCfg.BrowserEngine,
		BrowserPath:         settingsCfg.BrowserPath,
		NoCDP:               settingsCfg.NoCDP,
		Stealth:             settingsCfg.Stealth,
		ProxyURL:            r.options.ProxyURL,
		ProjectUUID:         r.options.ProjectUUID,

		MaxListenerProbeNodes: settingsCfg.MaxListenerProbeNodes,
		// The resolved interaction policy is authoritative; the legacy switches
		// below mirror it so a reader of either sees the same decision.
		// Credential attempts default on at balanced (minimal list) and deep
		// (full list), off at quick/lite; registration is off unless configured
		// at any intensity. See resolveAccountActions.
		Policy:                  &policy,
		DenyClickPattern:        settingsCfg.Interaction.DenyClickPattern,
		ExcludeSelectors:        settingsCfg.ExcludeSelectors,
		MethodAllowed:           r.browserMethodFilter(),
		AuthMonitor:             r.liveSessionMonitor(infra),
		BrowserCompat:           &compat,
		NoForms:                 !policy.EditFields && !policy.SubmitForms,
		LoginCredentialAttempts: policy.LoginAttempts,
		LoginCredentialFullList: rp.fullList,
		SelfRegister:            policy.RegisterAccount,
		IdentityEmailDomain:     settingsCfg.IdentityEmailDomain,
		MaxCaptureBodyBytes:     settingsCfg.MaxCaptureBodyBytes,
		InitialCookies:          browserCookies,
		ExtraHeaders:            browserHeaders,
		RequireAuth:             settingsCfg.RequireAuth,
		// A directory, not a path: the crawl names its own file from the target it
		// actually runs against, so a session reusing this config across a host's
		// seeds still writes each graph under the right name.
		GraphOutputDir:     settingsCfg.GraphOutputDir,
		GraphIncludeValues: settingsCfg.GraphIncludeValues,
		RunID:              infra.scanUUID,

		// Client routes from the target's JavaScript, browsed after the
		// robots/sitemap seeds; none outside the spidering phase.
		ExtraSeeds:    r.spidering.routeSeeds.forTarget(target),
		MaxExtraSeeds: settingsCfg.ExtraSeedsCap(),
	}

	if infra.scopeMatcher != nil && !infra.scopeMatcher.IsPassAll() {
		sm := infra.scopeMatcher
		cfg.ScopeFilter = func(host, path string) bool {
			return sm.InScopeRequest(host, path, "", "")
		}
	}
	return cfg
}

// browserRequestCounters are a browser phase's live request counters: every
// request the crawls' captures see (third-party included, the network cost) and
// the in-scope share. They back requests_sent and requests_in_scope on the
// phase's progress and finished events; the shared requester never sees browser
// traffic, so without them a crawl reported ≈0 requests.
type browserRequestCounters struct {
	sent, inScope atomic.Int64
}

// trackBrowserRequests registers a fresh counter pair with the running phase,
// and the in-scope counter with the request budget: browser traffic bypasses
// the egress gate, so --max-requests holds it softly (see armRequestBudget).
// In-scope only, because the budget caps what the TARGET is sent; the crawl's
// third-party fetches are its own network cost, not load on the target. The
// counter stays tracked for the rest of the scan: once the crawl is done it
// stops moving, and what it reached keeps counting.
func (r *Runner) trackBrowserRequests() *browserRequestCounters {
	bc := &browserRequestCounters{}
	t := r.currentPhase.Load()
	t.addCounter(bc.sent.Load)
	t.addInScopeCounter(bc.inScope.Load)
	r.trackUngatedRequests(bc.inScope.Load)
	return bc
}

// wire points cfg's capture counters at bc.
func (bc *browserRequestCounters) wire(cfg *spitolas.SpiderConfig) {
	if bc == nil {
		return
	}
	cfg.RequestCounter = &bc.sent
	cfg.InScopeRequestCounter = &bc.inScope
}

// openSpiderSession starts one browser context for a host group's targets, or
// returns nil when a session is not wanted: a single-target group (the shared
// context buys nothing), the operator's opt-out, or a launch failure — in which
// case each target falls back to its own fresh browser, which is the path that
// ran before sessions existed.
func (r *Runner) openSpiderSession(ctx context.Context, group []string, settingsCfg config.SpideringConfig, maxDuration time.Duration, infra *phaseInfra, counters *browserRequestCounters) (*spitolas.SpiderSession, *database.RecordWriter) {
	if len(group) < 2 || spiderSessionReuseDisabled() {
		return nil, nil
	}
	base := r.buildSpiderConfig(group[0], settingsCfg, maxDuration, infra)
	counters.wire(&base)
	rw := r.newScanRecordWriter()
	sess, err := spitolas.NewSpiderSession(ctx, base, rw)
	if err != nil {
		zap.L().Warn("Spidering: shared session launch failed, falling back to one browser per target",
			zap.String("host", httpmsg.HostnameFromURL(group[0])), zap.Error(err))
		rw.Close()
		return nil, nil
	}
	zap.L().Info("Spidering: reusing one browser context across a host's targets",
		zap.String("host", httpmsg.HostnameFromURL(group[0])),
		zap.Int("targets", len(group)))
	return sess, rw
}

// reportSpiderCoverage surfaces what the crawl reached beyond ordinary clicking:
// locations its own route declarations named, strings scraped out of the rendered
// document, an account it registered, and the extra sweeps it ran. Each is
// reported only when it did something, so a plain crawl stays quiet.
func (r *Runner) reportSpiderCoverage(result *spitolas.SpiderResult, target string) {
	if result.SeedURLsDiscovered > 0 {
		zap.L().Info("Spidering: seeded frontier from the host's route declarations",
			zap.String("target", target),
			zap.Int("declared", result.SeedURLsDiscovered),
			zap.Int("browsed", result.SeedURLsCrawled))
		r.printPhaseDetail(fmt.Sprintf("%s robots.txt/sitemap declared %s location(s) on %s — all recorded, %s browsed into the crawl.",
			terminal.Purple(terminal.SymbolArrow),
			terminal.Orange(fmt.Sprintf("%d", result.SeedURLsDiscovered)),
			terminal.Gray(target),
			terminal.Orange(fmt.Sprintf("%d", result.SeedURLsCrawled))))
	}
	if result.ExtraSeedsCrawled > 0 {
		zap.L().Info("Spidering: browsed client routes from the JavaScript",
			zap.String("target", target),
			zap.Int("accepted", result.ExtraSeedsAccepted),
			zap.Int("browsed", result.ExtraSeedsCrawled))
	}
	if result.SpeculativeLinksFetched > 0 {
		zap.L().Info("Spidering: fetched URLs scraped from comments and inline script",
			zap.String("target", target), zap.Int("count", result.SpeculativeLinksFetched))
	}
	if result.SelfRegistered {
		zap.L().Info("Spidering: registered an account to reach authenticated content",
			zap.String("target", target), zap.String("identity", result.SelfRegisterIdentity))
		r.printPhaseDetail(fmt.Sprintf("%s Registered %s on %s so the crawl could continue past the signup wall.",
			terminal.Purple(terminal.SymbolArrow),
			terminal.Orange(result.SelfRegisterIdentity),
			terminal.Gray(target)))
	}
	if result.FollowUpPassesRun > 0 || result.ActionsRecovered > 0 {
		zap.L().Info("Spidering: extra sweeps after the first pass drained",
			zap.String("target", target),
			zap.Int("follow_up_passes", result.FollowUpPassesRun),
			zap.Int("actions_retried", result.ActionsRetried),
			zap.Int("actions_recovered", result.ActionsRecovered))
	}
}

// runSpideringPhase runs browser-based crawling using spitolas.
// Captured traffic is stored in vigolium's HTTPRecord table via RepositoryWriter.
// Targets are merged from CLI targets and in-scope hosts discovered by prior phases.
func (r *Runner) runSpideringPhase(ctx context.Context, infra *phaseInfra) error {
	if r.repository == nil {
		return fmt.Errorf("spidering requires a database repository")
	}

	phaseStart := time.Now()
	r.printPhaseStart("Spidering", "browser-based crawling to discover dynamic content and API endpoints")

	settingsCfg := r.settings.Spidering
	// VIGOLIUM_BROWSER_HEADED (set by the agent --headed flag) forces a visible
	// browser window even when settings default to headless. settingsCfg is a
	// value copy, so this never mutates shared settings. This is the same env
	// override ProbeURL honors, extended here so agent pre-scan / --discover
	// spidering is visible too — not just the in-process browser probes.
	if utils.EnvTruthy(spitolas.EnvBrowserHeaded) {
		settingsCfg.Headless = false
	}
	// Each target runs under context.WithTimeout(phaseCtx, maxDuration), so a
	// non-positive budget here is an already-expired deadline, not "unlimited".
	// MaxDurationParsed guarantees a positive value; this catches the nil-settings
	// path, which would otherwise crawl nothing without saying so.
	maxDuration := SpideringBudget(r.settings, r.options)
	if maxDuration <= 0 {
		maxDuration = config.DefaultSpideringConfig().MaxDurationParsed()
	}

	targets := r.options.Targets
	dbHosts := r.getInScopeHostURLs(ctx)
	targets = dedupTargets(targets, dbHosts)

	expandSeedParents := false
	if r.settings != nil {
		expandSeedParents = r.settings.Discovery.ExpandSeedParents
	}
	var parentsAdded int
	if expandSeedParents && len(r.options.Targets) > 0 {
		expanded := discovery.ExpandSeedParents(r.options.Targets)
		before := len(targets)
		targets = dedupTargets(targets, expanded)
		parentsAdded = len(targets) - before
	}

	zap.L().Info("Spidering: merged targets",
		zap.Int("cli", len(r.options.Targets)),
		zap.Int("from_db", len(dbHosts)),
		zap.Int("parents_added", parentsAdded),
		zap.Int("total", len(targets)))

	if r.heuristicsResults != nil {
		before := len(targets)
		targets = filterTargetsByHeuristics(targets, r.heuristicsResults, func(hr *HeuristicsResult) bool {
			return hr.SkipSpidering
		})
		if skipped := before - len(targets); skipped > 0 {
			zap.L().Info("Spidering: targets filtered by heuristics",
				zap.Int("skipped", skipped), zap.Int("remaining", len(targets)))
		}
		if len(targets) == 0 {
			r.printPhaseComplete("Spidering", "skipped — all targets excluded by heuristics check")
			return nil
		}
	}

	configDetail := fmt.Sprintf("Config: strategy=%s, max-depth=%s, max-states=%s, headless=%s",
		terminal.HiTeal(settingsCfg.Strategy),
		terminal.HiTeal(fmt.Sprintf("%d", settingsCfg.MaxDepth)),
		terminal.HiTeal(fmt.Sprintf("%d", settingsCfg.MaxStates)),
		terminal.HiTeal(fmt.Sprintf("%v", settingsCfg.Headless)))
	if budget := PhaseSpeedDetail(r.settings, "spidering", maxDuration); budget != "" {
		configDetail += ", " + budget
	}
	r.printPhaseDetail(configDetail)
	// What the browser may change, resolved once for the phase. Every target's
	// config resolves the same policy from the same settings (buildSpiderConfig),
	// so this line and the conflict warnings describe all of them.
	policy := resolveBrowserPolicy(settingsCfg, r.options.Intensity)
	policy.applyTrafficPolicy(r.options.TrafficPolicy)
	for _, c := range policy.conflicts {
		zap.L().Warn("Spidering: interaction policy key overrides a legacy key", zap.String("override", c))
	}
	r.printPhaseDetail("Policy: " + terminal.HiTeal(policy.detail()))
	r.printPhaseDetail("Browser security: " + terminal.HiTeal(securityDetail(spitolas.EffectiveBrowserSecurity(resolveBrowserCompat(settingsCfg)))))
	if infra.scopeMatcher != nil && !infra.scopeMatcher.IsPassAll() {
		// The in-page primers fetch only what the operator scope admits; the
		// service-worker primer fetches inside its own script and cannot be held
		// to a path boundary, so a custom scope turns it off.
		r.printPhaseDetail("Priming: " + terminal.HiTeal("in-page fetches limited to the operator scope, service_worker=off (custom scope)"))
	}
	r.printTargetDetail(r.formatTargetCounts(ctx, len(targets)))
	// Routes earlier discovery runs of this project found in the JavaScript
	// (`run spidering` after `run discovery`), held only while this phase runs.
	r.spidering.routeSeeds = r.loadSpiderRouteSeeds(ctx)
	defer func() { r.spidering.routeSeeds = nil }()
	if n := r.spidering.routeSeeds.count(); n > 0 {
		r.printPhaseDetail(fmt.Sprintf("Route seeds: %s client route(s) stored by earlier discovery, browsed after each target's landing page",
			terminal.HiTeal(fmt.Sprintf("%d", n))))
	}
	r.printVerboseTargets(targets)

	// Per-target budget with an overall phase ceiling. Each target still gets
	// its own full max-duration, but the whole phase is bounded so a large
	// merged target list (CLI targets + many in-scope DB hosts) can't make
	// spidering run for len(targets) × max-duration. The ceiling is
	// max-duration × min(targets, spideringPhaseBudgetCap); each per-target
	// context derives from it, so the last target before the ceiling gets
	// whatever budget remains and any targets beyond it are skipped (logged).
	// phaseDeadline treats a zero ceiling (unlimited max-duration) as unbounded.
	//
	// A first run on a machine with no browser downloads Chrome for Testing
	// here, BEFORE the ceiling starts: the download is setup, not crawling, and
	// charging ~150 MB to a budget sized for crawling would leave little or
	// nothing for the targets.
	if err := r.provisionSpideringBrowser(ctx, settingsCfg); err != nil {
		r.printPhaseComplete("Spidering", "failed — "+err.Error())
		return err
	}
	phaseCeiling := spideringPhaseCeiling(maxDuration, len(targets))
	phaseCtx, phaseCancel := r.trackedPhaseDeadline(ctx, phaseCeiling)
	defer phaseCancel()

	var totalStates, totalActions, totalRecords, totalPrevented, totalUncertain int
	// phaseCapture sums the final capture receipts: one per RunSpider, one per
	// closed (or abandoned) session. Per-seed session receipts are deltas of a
	// still-open writer and are not summed.
	var phaseCapture spitolas.CaptureReceipt
	var ssoHosts []string
	var skippedTargets int
	// Targets that used their whole per-target budget. Reported as a LIMIT, not a
	// defect: the time box did what it was configured to do.
	var budgetExhaustedTargets int

	// Carry the browser's WAF/bot-cleared session (cookies + optionally its UA)
	// forward into discovery and scanning. On by default; scoped per-host below.
	// The UA is only pinned when the operator opted away from the honest "preset"
	// default (a custom/random UA or VIGOLIUM_DEFAULT_UA) — otherwise the honest
	// self-identifying UA is left untouched. Clearance cookies stay valid because
	// downstream requests keep the same UA the WAF issued them to.
	carrySession := r.options.CarryBrowserSession
	carryUA := !httpmsg.UserAgentIsHonestPreset()
	var harvested map[string]httpmsg.CarriedSession
	if carrySession {
		harvested = make(map[string]httpmsg.CarriedSession)
	}

	// Crawl one host's targets consecutively on a single browser context.
	// Cookies, local storage and capture-level dedup then persist between them,
	// so a session established on one seed is still in force on the next and a
	// shared asset is recorded once rather than once per target — neither of
	// which a fresh browser per target can do.
	groups := groupByHost(targets, httpmsg.HostnameFromURL)
	processed := 0
	// done/total on phase.progress, in targets. processed counts a target when
	// its crawl starts, so the reading is taken once the crawl has returned.
	progress := r.currentPhase.Load().trackTargets(len(targets))
	requests := r.trackBrowserRequests()

	// The drain window before each target's deadline (see SpideringGrace): the
	// crawler stops scheduling new states this long before it, and a ceiling
	// with no more than this left is treated as reached, so no target is
	// launched only to stop at once.
	grace := SpideringGrace(maxDuration)

	// Host groups are independent (each crawls in its own browser context), so
	// up to reSpiderHostParallelism of them run at once (ECON-9: hosts used to
	// be crawled strictly one at a time). Everything a group shares with the
	// phase — the totals, the harvested sessions, the SSO hosts, the capture
	// receipt, progress — is touched only while holding accMu; the lock is
	// released around the browser work itself.
	var accMu sync.Mutex
	var launchErr error
	failedTargets := 0
	runGroup := func(group []string) {
		accMu.Lock()
		defer accMu.Unlock()
		// A browser that cannot launch fails every group the same way.
		if launchErr != nil {
			return
		}
		// Overall ceiling exhausted — skip the remaining targets rather than
		// launching crawls against an already-expired context. They are counted
		// as skipped once every group has returned.
		if deadlineWithin(phaseCtx, grace) {
			return
		}

		// A shared session only pays for itself across several seeds; for a lone
		// target it is machinery around the proven single-crawl path.
		accMu.Unlock()
		sess, sessRW := r.openSpiderSession(phaseCtx, group, settingsCfg, maxDuration, infra, requests)
		accMu.Lock()
		abandoned := false

		for gi, target := range group {
			if deadlineWithin(phaseCtx, grace) {
				break
			}
			processed++
			zap.L().Info("Spidering target", zap.String("target", target))

			// Derive from phaseCtx so the per-target budget is min(max-duration,
			// remaining phase ceiling) — the overall cap is enforced automatically.
			// The watchdog guarantees this returns within budget+grace even if the
			// browser/teardown wedges, so a single target can never hang the scan.
			timeoutCtx, cancel := context.WithTimeout(phaseCtx, maxDuration)
			var oc crawlOutcome
			accMu.Unlock()
			if sess != nil {
				oc = runReSpiderSessionCrawl(timeoutCtx, sess, target, maxDuration)
			} else {
				cfg := r.buildSpiderConfig(target, settingsCfg, maxDuration, infra)
				requests.wire(&cfg)
				rw := r.newScanRecordWriter()
				oc = runSpiderWatchdog(timeoutCtx, cfg, rw, maxDuration, target)
			}
			accMu.Lock()
			if sess == nil {
				phaseCapture.Merge(oc.capture())
			}
			// Asked BEFORE cancel(): cancelling a context whose deadline had not
			// fired overwrites Err with Canceled, and the question "did this target
			// use its whole budget" then has no answer.
			if targetBudgetUsed(timeoutCtx, phaseCtx, grace) {
				budgetExhaustedTargets++
			}
			cancel()
			progress.Set(processed)

			if oc.err != nil && errors.Is(oc.err, spitolas.ErrBrowserLaunch) {
				// No browser: every remaining target would fail the same way.
				// Stop the phase and say why, rather than ending "completed, 0
				// records" and letting discovery read it as a low-yield target.
				zap.L().Error("Spidering: browser could not be launched; stopping the phase",
					zap.String("target", target), zap.Error(oc.err))
				launchErr = oc.err
				failedTargets += len(targets) - processed + 1
				processed = len(targets)
				break
			}
			if oc.err != nil {
				failedTargets++
				zap.L().Error("Spidering failed",
					zap.String("target", target), zap.Error(oc.err))
				if sess != nil {
					// Either way the rest of this host's targets are not attempted:
					// replaying the same failure per target buys nothing. What differs
					// is whether the session can be closed.
					//
					// A wedged browser must be abandoned — closing it would hang the
					// phase. An ordinary failure must NOT be: the browser is fine, and
					// the shared writer is still holding this host's captured records.
					// Abandoning there dropped traffic the earlier seeds had already
					// produced and leaked a Chrome process, for something as routine as
					// one unreachable target.
					abandoned = oc.wedged
					if abandoned {
						zap.L().Warn("Spidering: browser wedged, abandoning shared session for host and killing its browser process",
							zap.String("target", target))
						// Abandoned means nothing will ever close this session, so the
						// Chromium process and its profile would live for the rest of the
						// scan — one per wedged host group. Kill takes no lock the wedged
						// crawl goroutine might hold; its own goroutine because the
						// launcher's kill waits for the process to go.
						go sess.Kill()
					} else {
						zap.L().Warn("Spidering: crawl failed, closing shared browser session for host",
							zap.String("target", target))
					}
					// The rest of this host's targets are never attempted, so count
					// them as processed — they are abandoned, not waiting on budget,
					// and reporting them as "skipped by the ceiling" would misattribute
					// a browser failure to the phase clock.
					processed += len(group) - gi - 1
					break
				}
				continue
			}
			result := oc.res

			totalStates += result.StatesDiscovered
			totalActions += result.ActionsExecuted
			totalRecords += result.RecordsSaved
			totalPrevented += result.FormSubmitsPrevented
			totalUncertain += result.FormSubmitsUncertain

			if carrySession && (len(result.HarvestedCookies) > 0 || result.HarvestedAuthorization != "") {
				// Scope the session to the host the crawl actually settled on: the
				// adopted/landing host when the start URL relocated off-host, else the
				// target host.
				sessionHost := httpmsg.HostnameFromURL(target)
				sessionURL := target
				if result.HostAdopted && result.LandingURL != "" {
					if adopted := httpmsg.HostnameFromURL(result.LandingURL); adopted != "" {
						sessionHost = adopted
						sessionURL = result.LandingURL
					}
				}
				cookieHeader := httpmsg.FlattenCookiesForHost(sessionHost, result.HarvestedCookies)
				// Carry the session when the crawl earned EITHER cookies (cookie-auth
				// apps + WAF clearance) OR a token (token-auth SPAs send Authorization,
				// not a cookie — carrying only cookies would leave the scan unauthenticated).
				if cookieHeader != "" || result.HarvestedAuthorization != "" {
					// Named `carried`, not `sess`: the enclosing scope already holds the
					// shared browser session under that name, and shadowing it here
					// would make a later `sess.Close()` in this block close the wrong
					// thing while still compiling.
					// Both forms: Cookies is authoritative on the HTTP path
					// (evaluated per request, so a /admin or Secure cookie is
					// not sent where a browser wouldn't send it), CookieHeader
					// remains the flat summary and the fallback for consumers
					// that cannot evaluate a jar.
					carried := httpmsg.CarriedSession{
						CookieHeader: cookieHeader,
						Cookies:      httpmsg.CarriedCookiesFromHTTP(sessionHost, result.HarvestedCookies),
					}
					if carryUA {
						carried.UserAgent = result.BrowserUserAgent
					}
					if result.HarvestedAuthorization != "" {
						carried.AuthorizationHeader = "Bearer " + result.HarvestedAuthorization
						// Scope the bearer token to the exact origin (scheme+host+port) the
						// crawl harvested it from, so it isn't attached to a different
						// service sharing the hostname on another port/scheme.
						carried.Origin = httpmsg.OriginFromURL(sessionURL)
					}
					harvested[sessionHost] = carried
				}
			}

			// Persist any browser-confirmed DOM-XSS the crawl found on reflected client routes.
			if len(result.DOMXssFindings) > 0 {
				r.emitSpiderDOMXssFindings(ctx, infra.scanUUID, result.DOMXssFindings)
				r.printPhaseDetail(fmt.Sprintf("%s confirmed %s DOM-based XSS on reflected client route(s) during the crawl.",
					terminal.Orange(terminal.SymbolArrow),
					terminal.Orange(fmt.Sprintf("%d", len(result.DOMXssFindings)))))
			}

			zap.L().Info("Spidering completed for target",
				zap.String("target", target),
				zap.Int("states", result.StatesDiscovered),
				zap.Int("actions", result.ActionsExecuted),
				zap.Int("records_saved", result.RecordsSaved),
				zap.Int("forms_submitted", result.FormsSubmitted),
				zap.Int("form_submits_prevented", result.FormSubmitsPrevented),
				zap.Int("form_submits_uncertain", result.FormSubmitsUncertain),
				zap.Int("records_failed", result.Capture.Failed+result.Capture.Refused),
				zap.Int("wait_conditions_failed", result.WaitConditionsFailed),
				zap.String("auth_state", result.AuthState),
				zap.Int("aux_fetches_denied", result.AuxFetchesDenied),
				zap.Strings("credential_hosts_denied", result.CredentialHostsDenied))

			// Configured authentication that did not reach the browser means this
			// target was (at least partly) crawled anonymously — say so rather
			// than let it read as an authenticated crawl.
			if result.AuthState == spitolas.AuthFailed {
				r.printPhaseDetail(fmt.Sprintf("%s %s: configured authentication could not be applied to the browser — crawled unauthenticated (set spidering.require_auth or --require-auth to fail instead).",
					terminal.Yellow(terminal.SymbolWarning),
					terminal.Gray(target)))
				// The same code the HTTP path records when a configured session
				// could not be established. Without it, whether an operator's
				// scan row says `auth_unavailable` depended on which subsystem
				// failed to log in, not on whether the login failed.
				r.currentPhase.Load().markPartial(database.ReasonAuthUnavailable)
			}
			// The crawl was logged out (a logout control, an expired session)
			// and re-applying credentials did not bring it back: the rest of
			// this target was crawled anonymously (MISS-26).
			if result.AuthState == spitolas.AuthLost {
				r.printPhaseDetail(fmt.Sprintf("%s %s: the browser session was lost mid-crawl and could not be restored — the rest of this target was crawled unauthenticated.",
					terminal.Yellow(terminal.SymbolWarning),
					terminal.Gray(target)))
				r.currentPhase.Load().markPartial(database.ReasonAuthLost)
			}
			if len(result.CredentialHostsDenied) > 0 {
				r.printPhaseDetail(fmt.Sprintf("%s %s: credential headers withheld from %s (outside the operator scope).",
					terminal.Gray(terminal.SymbolArrow),
					terminal.Gray(target),
					strings.Join(result.CredentialHostsDenied, ", ")))
			}

			// A readiness condition that never met explains a thin crawl better
			// than "the site has little content" does.
			if result.WaitConditionsFailed > 0 {
				r.printPhaseDetail(fmt.Sprintf("%s %s: %s readiness condition(s) never met (%s) — the crawl saw the page before it was ready.",
					terminal.Yellow(terminal.SymbolWarning),
					terminal.Gray(target),
					terminal.Orange(fmt.Sprintf("%d", result.WaitConditionsFailed)),
					strings.Join(result.WaitConditionFailures, ", ")))
			}

			// A landing whose "Log on" CTA was driven means the crawler entered the
			// app's OAuth/SAML/SSO flow — surface it so the captured login-flow URLs
			// aren't a surprise.
			if result.LoginCTADriven {
				zap.L().Info("Spidering: drove login CTA into the auth flow",
					zap.String("target", target),
					zap.String("cta", result.LoginCTAText))
				r.printPhaseDetail(fmt.Sprintf("%s clicked the %s call-to-action on %s to enter and capture the OAuth/SAML login flow.",
					terminal.Purple(terminal.SymbolArrow),
					terminal.Orange(fmt.Sprintf("%q", result.LoginCTAText)),
					terminal.Gray(target)))
			}

			// The start URL bounced the browser off-host. Two cases: a login/SSO wall
			// (the crawler can't go past it unauthenticated, so the run yields next
			// to nothing — advise auth), or a relocated app on another host (the
			// crawler adopts that host and crawls it). Either way, say so — a silent
			// near-empty result otherwise reads like the site has no content.
			switch {
			case result.OffHostRedirect && result.LandingIsLogin:
				ssoHosts = append(ssoHosts, ssoHostsFromSpider(result.WallHosts, result.LandingURL)...)
				zap.L().Warn("Spidering: start URL redirected off-host to a login wall",
					zap.String("target", target),
					zap.String("landing", result.LandingURL),
					zap.Strings("wall_hosts", result.WallHosts))
				r.printPhaseDetail(fmt.Sprintf("%s %s redirected off-host to %s — likely an SSO/login wall. The wall's host(s) are now out of scope, so little was discovered. Supply authentication (--auth) or add the redirect host to scope to crawl behind the login.",
					terminal.Yellow(terminal.SymbolArrow),
					terminal.Gray(target),
					terminal.Yellow(result.LandingURL)))
			case result.OffHostRedirect && result.HostAdopted:
				zap.L().Info("Spidering: adopted off-host redirect target into scope",
					zap.String("target", target),
					zap.String("landing", result.LandingURL))
				r.printPhaseDetail(fmt.Sprintf("%s %s redirected off-host to %s — not a login page, so its host was added to scope and crawled.",
					terminal.Purple(terminal.SymbolArrow),
					terminal.Gray(target),
					terminal.Orange(result.LandingURL)))
			case result.OffHostRedirect:
				zap.L().Info("Spidering: start URL redirected off-host",
					zap.String("target", target),
					zap.String("landing", result.LandingURL))
				r.printPhaseDetail(fmt.Sprintf("%s %s redirected off-host to %s.",
					terminal.Purple(terminal.SymbolArrow),
					terminal.Gray(target),
					terminal.Orange(result.LandingURL)))
			}

			r.reportSpiderCoverage(result, target)
		}
		// Picks up the host's remaining targets when a failed session gave up
		// on them (they are counted as processed, not left waiting on budget).
		progress.Set(processed)

		if sess != nil {
			accMu.Unlock()
			receipt := sessionCapture(sess, sessRW, abandoned)
			accMu.Lock()
			phaseCapture.Merge(receipt)
		}
	}

	runHostGroups(groups, reSpiderHostParallelism(len(groups)),
		func() bool {
			accMu.Lock()
			defer accMu.Unlock()
			return launchErr != nil || deadlineWithin(phaseCtx, grace)
		}, runGroup)
	if processed > len(targets) {
		processed = len(targets)
	}
	if processed < len(targets) && deadlineWithin(phaseCtx, grace) {
		skippedTargets = len(targets) - processed
		zap.L().Warn("Spidering: phase budget ceiling reached, skipping remaining targets",
			zap.Int("skipped", skippedTargets),
			zap.Int("total", len(targets)),
			zap.Duration("max_duration", maxDuration),
			zap.Int("budget_cap", spideringPhaseBudgetCap))
	}

	// Carry the harvested per-host sessions forward: store them for the Discovery
	// phase (buildDeparosConfig reads r.browserSessions) and inject them into the
	// shared scan requester used by discovery ingestion and dynamic assessment.
	// The requester is shared across all phases (executeNativePhase threads one
	// infra), so a single injection reaches every downstream request.
	if len(harvested) > 0 {
		r.browserSessions = harvested
		if infra.httpRequester != nil {
			infra.httpRequester.SetCarriedSessions(harvested)
		}
		hosts := make([]string, 0, len(harvested))
		for h := range harvested {
			hosts = append(hosts, h)
		}
		zap.L().Info("Spidering: carried browser session forward",
			zap.Strings("hosts", hosts), zap.Bool("pin_user_agent", carryUA))
		uaNote := ""
		if carryUA {
			uaNote = " and pinned its User-Agent"
		}
		r.printPhaseDetail(fmt.Sprintf("%s Carried the browser's cleared session (cookies%s) forward to discovery and scanning for %s.",
			terminal.Purple(terminal.SymbolArrow),
			uaNote,
			terminal.Orange(strings.Join(hosts, ", "))))
	}

	// Record the outcome for the Discovery phase's low-yield auto-fuzz decision.
	r.spidering = spideringOutcome{
		ran:           true,
		records:       totalRecords,
		lost:          phaseCapture.Lost(),
		complete:      phaseCapture.Clean(),
		sawSSO:        len(ssoHosts) > 0,
		ssoHosts:      ssoHosts,
		browserFailed: launchErr != nil,
	}
	r.noteSpideringFailures(failedTargets, launchErr)

	if r.repository != nil && totalRecords > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, int64(totalRecords)); err != nil {
			zap.L().Warn("Spidering: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	completion := fmt.Sprintf("completed — %s records%s, %s states, %s actions in %s",
		terminal.Orange(fmt.Sprintf("%d", totalRecords)),
		terminal.Yellow(captureIncompleteNote(phaseCapture)),
		terminal.Orange(fmt.Sprintf("%d", totalStates)),
		terminal.Orange(fmt.Sprintf("%d", totalActions)),
		terminal.HiPurple(fmtDuration(elapsed)))
	if totalPrevented > 0 {
		completion += fmt.Sprintf(", %s form submission(s) prevented by policy",
			terminal.Yellow(fmt.Sprintf("%d", totalPrevented)))
	}
	if totalUncertain > 0 {
		completion += fmt.Sprintf(", %s POST form(s) with an uncertain outcome — dependent writes stopped (no fallback, no retry)",
			terminal.Yellow(fmt.Sprintf("%d", totalUncertain)))
	}
	if skippedTargets > 0 {
		completion += fmt.Sprintf(" (%s targets skipped — phase budget ceiling of %s reached)",
			terminal.Yellow(fmt.Sprintf("%d", skippedTargets)),
			terminal.Yellow(fmtDuration(phaseCeiling)))
	}
	r.printPhaseComplete("Spidering", completion)

	// The two coverage facts this phase owns, onto the phase outcome: targets the
	// ceiling never let it reach (a gap), and targets that spent their whole
	// per-target budget (a configured bound, hence a limit).
	tracker := r.currentPhase.Load()
	if skippedTargets > 0 {
		tracker.markPartial(database.ReasonTargetsSkipped)
	}
	if budgetExhaustedTargets > 0 {
		tracker.noteLimit(database.LimitTargetBudget)
	}
	// What the browser capture actually managed to persist — the same fact the
	// HTTP phases get from shutdownWriters.
	recordCapture(tracker, phaseCapture)
	// Name the way out at the moment it bit. The ceiling is not a pace the flags
	// can widen — the phase crawls a bounded number of hosts at a time — so an operator told only
	// that N targets were dropped has no move to make from that line alone. The
	// flags come from SpiderFanOutSuggestion, the same resolver the pre-scan hint
	// uses, so both the advice and its preconditions match this run.
	if flags, ok := SpiderFanOutSuggestion(r.options, len(targets)); ok && skippedTargets > 0 {
		r.printPhaseDetail(fmt.Sprintf("%s Re-run with %s to scan the list as parallel child processes, each with its own browser and its own budget.",
			terminal.Yellow(terminal.SymbolArrow),
			terminal.HiCyan(flags)))
	}
	return nil
}

// noteSpideringFailures records the phase's failed targets on its outcome and,
// when the browser never started, says so on the terminal with the command
// that diagnoses it. A crawl that could not start is a failed phase, not a
// target with nothing to find.
func (r *Runner) noteSpideringFailures(failed int, launchErr error) {
	tracker := r.currentPhase.Load()
	if failed > 0 {
		tracker.setCount("targets_failed", int64(failed))
		tracker.markPartial(database.ReasonTargetsFailed)
	}
	if launchErr == nil {
		return
	}
	tracker.markPartial(database.ReasonBrowserUnavailable)
	r.scanLogger.Error("spidering", "browser could not be launched: "+launchErr.Error())
	if !r.options.Silent {
		r.printPhaseDetail(fmt.Sprintf("%s Spidering failed — the browser could not be launched (%s); run %s",
			terminal.Red(terminal.SymbolWarning), launchErr.Error(), terminal.HiCyan("vigolium doctor --for scan")))
	}
}

// browserMethodFilter is the traffic policy's method check for the browser
// crawl (SAFE-8), nil when every method is allowed.
func (r *Runner) browserMethodFilter() func(string) bool {
	if pol := r.options.TrafficPolicy; pol != nil && len(pol.AllowedMethods) > 0 {
		return pol.AllowsMethod
	}
	return nil
}

// liveSessionAuthMonitor adapts the scan's primary live session to the
// crawler's AuthMonitor (MISS-26): the browser re-applies the session's
// current credentials after a re-login and feeds responses back.
type liveSessionAuthMonitor struct {
	s       *authentication.LiveSession
	changed chan struct{}
}

func (m liveSessionAuthMonitor) Changed() <-chan struct{} { return m.changed }

func (m liveSessionAuthMonitor) Observe(gen uint64, status int, h nethttp.Header, body []byte) {
	m.s.Observe(gen, status, h, body)
}

func (m liveSessionAuthMonitor) Credentials() (uint64, map[string]string, []*nethttp.Cookie) {
	creds := m.s.Credentials()
	if creds == nil {
		return 0, nil, nil
	}
	return creds.Gen, creds.Headers, nil
}

// liveSessionMonitor is the AuthMonitor for infra's primary live session, or
// nil when the scan has none.
func (r *Runner) liveSessionMonitor(infra *phaseInfra) spitolas.AuthMonitor {
	if infra == nil || infra.sessions == nil {
		return nil
	}
	live := infra.sessions.primaryLive()
	if live == nil {
		return nil
	}
	return liveSessionAuthMonitor{s: live, changed: r.relogins.subscribe()}
}

// reloginBroadcast fans a successful live-session re-login out to every
// browser crawl watching it (AuthMonitor.Changed, MISS-26).
type reloginBroadcast struct {
	mu   sync.Mutex
	subs []chan struct{}
}

// subscribe returns a coalescing channel that fires on each re-login.
func (b *reloginBroadcast) subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	b.subs = append(b.subs, ch)
	b.mu.Unlock()
	return ch
}

// notify signals every subscriber without blocking.
func (b *reloginBroadcast) notify() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// runHostGroups runs run once per host group, up to par at a time (ECON-9),
// stopping before a group once stop reports the phase budget is spent. par<=1
// is the sequential crawl.
func runHostGroups[T any](groups [][]T, par int, stop func() bool, run func([]T)) {
	if par <= 1 {
		for _, group := range groups {
			if stop() {
				return
			}
			run(group)
		}
		return
	}
	zap.L().Info("Spidering: crawling independent hosts concurrently",
		zap.Int("hosts", len(groups)), zap.Int("parallelism", par))
	var wg sync.WaitGroup
	sem := make(chan struct{}, par)
	for _, group := range groups {
		if stop() {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(group []T) {
			defer wg.Done()
			defer func() { <-sem }()
			run(group)
		}(group)
	}
	wg.Wait()
}
