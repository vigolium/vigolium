package runner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// harvestStub is one request-only record external-harvest stored in this run:
// the row's UUID and the request it holds.
type harvestStub struct {
	uuid string
	req  *httpmsg.HttpRequestResponse
}

// takeHarvestStubs hands the stubs the harvest stored to the probe, and forgets
// them, so a rescan on the same Runner cannot probe the previous run's list.
func (r *Runner) takeHarvestStubs() []harvestStub {
	stubs := r.harvestStubs
	r.harvestStubs = nil
	return stubs
}

// harvestProbeWriteQueue bounds how many fetched responses wait for the single
// database writer. Each carries a full response body, so this is the memory the
// step can hold beyond the in-flight requests themselves.
const harvestProbeWriteQueue = 64

// Keys of PhaseOutcome.Counts for the harvest-probe step. Stable names: they are
// persisted on the scan row and read by consumers.
const (
	harvestCountStubs       = "stubs"             // harvested URLs handed to the step
	harvestCountHosts       = "hosts"             // distinct origins among them
	harvestCountHostsDead   = "hosts_dead"        // origins whose liveness request got no HTTP answer
	harvestCountProbed      = "probed"            // GETs sent for harvested URLs (liveness excluded)
	harvestCountKept        = "kept"              // stubs completed with their response
	harvestCountDeadHost    = "dropped_dead_host" // stubs on a dead origin, never fetched
	harvestCountNotFound    = "dropped_not_found" // answered 404 or 410
	harvestCountSoft404     = "dropped_soft_404"  // answered like the origin's not-found page
	harvestCountFailed      = "dropped_failed"    // the GET itself failed on a live origin
	harvestCountUnprobed    = "unprobed"          // left as stubs because the step was cut short
	harvestCountDeleted     = "deleted"           // dropped stubs actually removed from the store
	harvestCountWriteFailed = "write_failed"      // survivors whose response could not be stored
)

// harvestVerdict is what one fetched harvested URL turned out to be.
type harvestVerdict int

const (
	harvestKeep harvestVerdict = iota
	harvestNotFound
	harvestSoft404
)

// harvestOrigin groups the stubs that share one scheme://host:port, which is the
// unit of liveness: one request decides whether any of its URLs are fetched.
type harvestOrigin struct {
	base  string // scheme://host[:port], as the stubs spell it
	stubs []harvestStub
	// alive and dead are both false for an origin the step never got to check
	// (the phase was cut short); its stubs are left alone rather than dropped.
	alive bool
	dead  bool
	print *notFoundPrint
}

// runHarvestProbePhase checks the URLs external-harvest stored against the live
// target, before any later phase scans them.
//
// Archive indexes are mostly history: hosts that no longer resolve, pages long
// since removed. Left as stubs, every one of them would be fetched — and then
// fuzzed — by dynamic assessment. The step spends one request per origin and one
// per harvested URL to keep only what still answers:
//
//  1. Liveness: one GET per origin, to a random path. No HTTP answer drops every
//     URL on that origin unfetched — on a stale archive this is the bulk of the
//     saving. The answer doubles as the origin's not-found fingerprint.
//  2. One GET per harvested URL on a live origin, redirects recorded rather than
//     followed. 404/410 is dropped, as is an answer indistinguishable from the
//     origin's not-found fingerprint (a soft-404 on a catch-all host).
//
// Survivors keep source=harvest and get their response filled in; every dropped
// URL's stub is deleted, so no later phase scans it. Everything goes through the
// shared requester, so the scan's session, rate limit and host limiter apply.
//
// The plan schedules the step only when a later phase reaches the target (see
// gateHarvestProbe); external_harvester.probe: false turns it into a no-op that
// leaves every stub for those phases.
func (r *Runner) runHarvestProbePhase(ctx context.Context, infra *phaseInfra) error {
	stubs := r.takeHarvestStubs()
	phaseStart := time.Now()
	tracker := r.currentPhase.Load()

	r.printPhaseStart("HarvestProbe", "check harvested URLs against the live target before they are scanned")

	if r.settings != nil && !r.settings.ExternalHarvester.ProbeEnabled() {
		r.printPhaseDetail(terminal.Orange("disabled by external_harvester.probe: false") +
			terminal.Gray(" — harvested URLs are left for later phases to fetch unchecked"))
		return nil
	}
	if len(stubs) == 0 || r.repository == nil || infra == nil || infra.httpRequester == nil {
		r.printPhaseDetail("nothing to probe — the harvest stored no URLs")
		tracker.setCount(harvestCountStubs, int64(len(stubs)))
		return nil
	}

	origins := groupHarvestOrigins(stubs)
	r.printPhaseDetail(fmt.Sprintf("%s harvested URLs on %s hosts — 1 liveness request per host, then 1 GET per URL on a live host (redirects recorded, not followed)",
		terminal.HiTeal(fmt.Sprintf("%d", len(stubs))), terminal.HiTeal(fmt.Sprintf("%d", len(origins)))))

	p := newHarvestProber(r, infra.httpRequester, r.harvestProbeWorkers())
	tracker.setProgress(progressUnitRecords, func() (int64, int64) {
		return p.done.Load(), int64(len(stubs))
	})

	p.checkLiveness(ctx, origins)
	drops := p.fetchStubs(ctx, origins)

	var deleted int64
	if len(drops) > 0 {
		// Detached from the phase context: a cut-short probe must still remove
		// the URLs it already found dead, or the next phase scans them anyway.
		delCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cursorFlushBudget)
		n, err := r.repository.DeleteRequestOnlyStubs(delCtx, r.options.ProjectUUID, database.RecordSourceHarvest, drops)
		cancel()
		if err != nil {
			tracker.markPartial(database.ReasonPersistence)
			zap.L().Warn("HarvestProbe: failed to delete dropped stubs", zap.Int("count", len(drops)), zap.Error(err))
		}
		deleted = n
	}

	st := p.stats(len(stubs), len(origins), deleted)
	for name, n := range st {
		tracker.setCount(name, n)
	}
	if st[harvestCountWriteFailed] > 0 {
		tracker.markPartial(database.ReasonPersistence)
	}

	r.printPhaseComplete("HarvestProbe", fmt.Sprintf("kept %s of %s harvested URLs in %s",
		terminal.Orange(fmt.Sprintf("%d", st[harvestCountKept])),
		terminal.HiTeal(fmt.Sprintf("%d", len(stubs))),
		terminal.HiPurple(fmtDuration(time.Since(phaseStart)))))
	r.printPhaseFeedback("HarvestProbe", fmt.Sprintf(
		"dropped: dead hosts %d (%d URLs), 404/410 %d, soft-404 %d, failed %d; unprobed %d",
		st[harvestCountHostsDead], st[harvestCountDeadHost], st[harvestCountNotFound],
		st[harvestCountSoft404], st[harvestCountFailed], st[harvestCountUnprobed]))
	zap.L().Info("HarvestProbe: completed", zap.Any("counts", st))
	return nil
}

// harvestProbeWorkers is the step's fetch concurrency: the scan's -c. Per-host
// pressure is bounded separately by the shared host limiter every request
// passes through.
func (r *Runner) harvestProbeWorkers() int {
	if r.options != nil && r.options.Concurrency > 0 {
		return r.options.Concurrency
	}
	return 10
}

// groupHarvestOrigins buckets stubs by origin, keeping first-seen order so the
// step's traffic is deterministic for a given harvest.
func groupHarvestOrigins(stubs []harvestStub) []*harvestOrigin {
	var out []*harvestOrigin
	index := make(map[string]*harvestOrigin)
	for _, s := range stubs {
		base := harvestOriginBase(s.req)
		o := index[base]
		if o == nil {
			o = &harvestOrigin{base: base}
			index[base] = o
			out = append(out, o)
		}
		o.stubs = append(o.stubs, s)
	}
	return out
}

// harvestOriginBase is scheme://host[:port] for a stub, lowercased. An
// unparseable URL gets an origin of its own, whose liveness request then fails
// and drops it.
func harvestOriginBase(rr *httpmsg.HttpRequestResponse) string {
	u, err := url.Parse(rr.Target())
	if err != nil || u.Scheme == "" || u.Host == "" {
		return rr.Target()
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// harvestProber runs the two fetch stages and keeps their tallies.
type harvestProber struct {
	r         *Runner
	requester *vighttp.Requester
	workers   int

	done                                atomic.Int64 // stubs decided, for progress
	probed, kept, notFound, soft404     atomic.Int64
	failed, deadHost, unprobed, wfailed atomic.Int64
	hostsDead                           atomic.Int64
}

func newHarvestProber(r *Runner, requester *vighttp.Requester, workers int) *harvestProber {
	if workers <= 0 {
		workers = 1
	}
	return &harvestProber{r: r, requester: requester, workers: workers}
}

// fetch sends one GET without following redirects, and returns the response
// with the requester's measured duration.
func (p *harvestProber) fetch(ctx context.Context, rr *httpmsg.HttpRequestResponse) (*httpmsg.HttpResponse, error) {
	// NoClustering: every URL here is distinct, and a snapshot from the
	// clusterer would be another request's answer recorded against this one.
	chain, elapsed, err := p.requester.ExecuteContext(ctx, rr, vighttp.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil, err
	}
	defer chain.Close()
	headers, body := chain.HeadersBytes(), chain.BodyBytes()
	raw := make([]byte, 0, len(headers)+len(body))
	raw = append(raw, headers...)
	raw = append(raw, body...)
	return httpmsg.NewHttpResponseWithDuration(raw, elapsed), nil
}

// forEach runs fn over n items on the prober's worker count, stopping new work
// once ctx is done. Returns how many items were never started.
func (p *harvestProber) forEach(ctx context.Context, n int, fn func(i int)) int64 {
	return parallelEach(ctx, n, p.workers, fn)
}

// checkLiveness sends one request per origin, to a path that should not exist.
// Any HTTP answer marks the origin alive and becomes its not-found fingerprint.
// Only an origin that cannot be reached at all — DNS failure or a refused /
// failed dial — is dead and loses its stubs. Any other failure (a timeout, a
// reset, a TLS hiccup) says the host exists but this one request failed, so the
// origin stays unchecked and its stubs are kept, counted unprobed, for the later
// phases. An origin left unchecked because the phase was cut short is treated
// the same way.
func (p *harvestProber) checkLiveness(ctx context.Context, origins []*harvestOrigin) {
	p.forEach(ctx, len(origins), func(i int) {
		o := origins[i]
		target := "/" + randomHarvestPath()
		rr, err := httpmsg.GetRawRequestFromURL(o.base + target)
		if err != nil {
			p.markDead(ctx, o)
			return
		}
		resp, err := p.fetch(ctx, rr)
		if err != nil {
			if isUnreachableError(err) {
				p.markDead(ctx, o)
			}
			zap.L().Debug("HarvestProbe: host did not answer", zap.String("origin", o.base), zap.Error(err))
			return
		}
		o.alive = true
		o.print = newNotFoundPrint(resp, target)
	})
}

// markDead records an origin whose liveness request got no HTTP answer — unless
// the phase context ended, which says nothing about the host.
func (p *harvestProber) markDead(ctx context.Context, o *harvestOrigin) {
	if ctx.Err() != nil {
		return
	}
	o.dead = true
	p.hostsDead.Add(1)
}

// fetchStubs fetches every stub on a live origin, completes the survivors in the
// store, and returns the UUIDs to delete: dead-origin stubs plus every URL whose
// answer was dropped. Survivors are written by one goroutine so the step never
// holds more than harvestProbeWriteQueue response bodies at once and never
// contends with itself for the database.
func (p *harvestProber) fetchStubs(ctx context.Context, origins []*harvestOrigin) []string {
	type job struct {
		stub   harvestStub
		origin *harvestOrigin
	}
	type survivor struct {
		uuid string
		rr   *httpmsg.HttpRequestResponse
	}
	var jobs []job
	var drops []string
	for _, o := range origins {
		n := int64(len(o.stubs))
		switch {
		case o.alive:
			for _, s := range o.stubs {
				jobs = append(jobs, job{stub: s, origin: o})
			}
		case o.dead:
			for _, s := range o.stubs {
				drops = append(drops, s.uuid)
			}
			p.deadHost.Add(n)
			p.done.Add(n)
		default:
			// Never checked: the phase was cut short before this origin's turn.
			p.unprobed.Add(n)
			p.done.Add(n)
		}
	}

	var dropMu sync.Mutex
	drop := func(uuid string) {
		dropMu.Lock()
		drops = append(drops, uuid)
		dropMu.Unlock()
	}
	writes := make(chan survivor, harvestProbeWriteQueue)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		// Detached: a survivor already fetched is stored even if the phase is
		// cut short in the meantime — the request was paid for.
		wctx := context.WithoutCancel(ctx)
		for w := range writes {
			if err := p.r.repository.BackfillRecordResponse(wctx, w.uuid, w.rr); err != nil {
				p.wfailed.Add(1)
				zap.L().Debug("HarvestProbe: failed to store response", zap.String("url", w.rr.Target()), zap.Error(err))
				continue
			}
			p.kept.Add(1)
		}
	}()

	skipped := p.forEach(ctx, len(jobs), func(i int) {
		j := jobs[i]
		defer p.done.Add(1)
		resp, err := p.fetch(ctx, j.stub.req)
		if err != nil {
			if ctx.Err() != nil {
				p.unprobed.Add(1)
				return
			}
			// A failed fetch on a live host says nothing about the URL: keep
			// the stub for the later phases instead of deleting it.
			p.probed.Add(1)
			p.failed.Add(1)
			return
		}
		p.probed.Add(1)
		switch classifyHarvestResponse(j.origin.print, resp, harvestRequestTarget(j.stub.req)) {
		case harvestNotFound:
			p.notFound.Add(1)
		case harvestSoft404:
			p.soft404.Add(1)
		default:
			writes <- survivor{uuid: j.stub.uuid, rr: j.stub.req.WithResponse(resp)}
			return
		}
		drop(j.stub.uuid)
	})
	close(writes)
	<-writerDone
	p.unprobed.Add(skipped)
	p.done.Add(skipped)
	return drops
}

// isUnreachableError reports a failure to reach the origin at all: name
// resolution failed, or the TCP dial itself failed (refused, no route). These
// are the only errors that mark a harvested origin dead.
func isUnreachableError(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return true
	}
	// Some transports flatten the error chain; fall back to the message.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such host") || strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "dial tcp")
}

// stats snapshots the tallies as PhaseOutcome.Counts.
func (p *harvestProber) stats(stubs, hosts int, deleted int64) map[string]int64 {
	return map[string]int64{
		harvestCountStubs:       int64(stubs),
		harvestCountHosts:       int64(hosts),
		harvestCountHostsDead:   p.hostsDead.Load(),
		harvestCountProbed:      p.probed.Load(),
		harvestCountKept:        p.kept.Load(),
		harvestCountDeadHost:    p.deadHost.Load(),
		harvestCountNotFound:    p.notFound.Load(),
		harvestCountSoft404:     p.soft404.Load(),
		harvestCountFailed:      p.failed.Load(),
		harvestCountUnprobed:    p.unprobed.Load(),
		harvestCountDeleted:     deleted,
		harvestCountWriteFailed: p.wfailed.Load(),
	}
}

// harvestRequestTarget is the request-target (path and query) of a stub, the
// part of the URL a not-found page may reflect.
func harvestRequestTarget(rr *httpmsg.HttpRequestResponse) string {
	u, err := url.Parse(rr.Target())
	if err != nil {
		return ""
	}
	return u.RequestURI()
}

// randomHarvestPath is a path segment no real application serves.
func randomHarvestPath() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "vigolium-" + hex.EncodeToString(b[:])
}

// notFoundPrint is an origin's answer to a path that does not exist — the
// cheapest soft-404 fingerprint there is, because the liveness request already
// paid for it.
type notFoundPrint struct {
	status    int
	mediaType string
	bodyLen   int
	location  string // host+path of a redirect's Location
	targetLen int    // length of the probed request-target, for reflection slack
}

func newNotFoundPrint(resp *httpmsg.HttpResponse, target string) *notFoundPrint {
	return &notFoundPrint{
		status:    resp.StatusCode(),
		mediaType: responseMediaType(resp),
		bodyLen:   len(resp.Body()),
		location:  redirectHostPath(resp),
		targetLen: len(target),
	}
}

// catchAll reports whether the origin answers unknown paths with something
// other than an error — a 2xx page or a 3xx redirect — which is the only case
// in which a 2xx/3xx for a harvested URL can mean "not found". An origin whose
// unknown paths get a 404 is judged by status alone; one that answers 401/403/5xx
// for everything is left alone, because those statuses are real endpoints as
// often as not.
func (fp *notFoundPrint) catchAll() bool {
	return fp != nil && fp.status >= 200 && fp.status < 400
}

// matches reports whether resp is indistinguishable from the origin's not-found
// answer: same status and media type, and either the same redirect destination
// or a body whose length differs by no more than a reflected path would explain.
func (fp *notFoundPrint) matches(resp *httpmsg.HttpResponse, target string) bool {
	if !fp.catchAll() || resp.StatusCode() != fp.status || responseMediaType(resp) != fp.mediaType {
		return false
	}
	if fp.status >= 300 {
		return redirectHostPath(resp) == fp.location
	}
	diff := absInt(len(resp.Body()) - fp.bodyLen)
	slack := fp.bodyLen/50 + 16 + 2*absInt(len(target)-fp.targetLen)
	return diff <= slack
}

// classifyHarvestResponse decides one harvested URL's fate from its answer.
func classifyHarvestResponse(fp *notFoundPrint, resp *httpmsg.HttpResponse, target string) harvestVerdict {
	switch resp.StatusCode() {
	case 404, 410:
		return harvestNotFound
	}
	if fp.matches(resp, target) {
		return harvestSoft404
	}
	return harvestKeep
}

// responseMediaType is the Content-Type without parameters, lowercased.
func responseMediaType(resp *httpmsg.HttpResponse) string {
	ct, _, _ := strings.Cut(resp.Header("Content-Type"), ";")
	return strings.ToLower(strings.TrimSpace(ct))
}

// redirectHostPath is the host and path of a 3xx's Location, without the query
// — a catch-all login redirect usually carries the requested path in its query
// (?next=/x), which would otherwise make every redirect look distinct.
func redirectHostPath(resp *httpmsg.HttpResponse) string {
	if resp.StatusCode() < 300 || resp.StatusCode() >= 400 {
		return ""
	}
	loc := strings.TrimSpace(resp.Header("Location"))
	u, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	return strings.ToLower(u.Host) + u.Path
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
