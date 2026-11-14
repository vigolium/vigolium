package runner

import (
	"context"
	"fmt"
	neturl "net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/utils"
	"go.uber.org/zap"
)

// candidateScanLimit bounds how many body-carrying records the re-spider phase
// pulls for evaluation, keeping memory and CPU bounded on large scans.
const candidateScanLimit = 5000

// respiderPageSize bounds how many body-carrying rows are read (and so held in
// memory) per page while collecting re-spider candidates.
const respiderPageSize = 500

// collectReSpiderEvaluated pages through up to candidateScanLimit body-carrying
// records, reducing each page to its body-free evaluated form before reading the
// next page — so peak resident memory is one page of raw_response bodies, not
// all candidateScanLimit of them.
func (r *Runner) collectReSpiderEvaluated(ctx context.Context) ([]respiderEvaluated, error) {
	var evals []respiderEvaluated
	afterUUID := ""
	// Restrict re-spider candidates to this scan's in-scope origins (scheme/host/port),
	// so SPA routes left in the project by a prior scan of a different origin (e.g. a
	// different port on the host) are not re-crawled.
	inScopeHosts := r.getInScopeDBHosts(ctx)
	for len(evals) < candidateScanLimit {
		page := respiderPageSize
		if remaining := candidateScanLimit - len(evals); remaining < page {
			page = remaining
		}
		rows, err := r.repository.GetReSpiderCandidates(ctx, r.options.ProjectUUID, afterUUID, page, inScopeHosts...)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			break
		}
		for i := range rows {
			evals = append(evals, reduceReSpiderRow(&rows[i]))
		}
		afterUUID = rows[len(rows)-1].UUID
		if len(rows) < page {
			break // last (short) page — no more rows
		}
		// rows (with its page of bodies) becomes garbage on the next iteration's
		// reassignment; only the body-free evals accumulate.
	}
	return evals, nil
}

// respiderSeed is a chosen re-crawl target.
type respiderSeed struct {
	url     string
	hostKey string // hostname, for per-host capping and SSO skip
	score   int
	source  string // candidate record's source, or routeSeedSource
}

// runTargetedReSpiderPhase re-crawls the few rich/SPA routes discovery surfaced
// after the one-shot browser spidering. It reads discovery's deduped records
// (bodies already stored — no re-fetch), keeps only client-rendered or
// interactive pages that are not login/SSO walls, dedups them by app-shell so
// one browser covers a whole SPA router, then runs short budgeted crawls whose
// records land in http_records for dynamic assessment.
func (r *Runner) runTargetedReSpiderPhase(ctx context.Context, infra *phaseInfra) error {
	if r.repository == nil || r.settings == nil {
		return nil
	}
	rcfg := &r.settings.Discovery.ReSpider
	if !rcfg.IsEnabled() {
		return nil
	}
	// The browser spidering phase must have run: its records pre-seed the
	// shell-dedup set, and its having run confirms the user allows browsers.
	if !r.spidering.ran {
		return nil
	}

	phaseStart := time.Now()
	r.printPhaseStart("Re-spider", "browser re-crawl of rich/SPA routes discovered after spidering")

	// Page through body-carrying candidates, reducing each page to a body-free
	// form before reading the next, so only respiderPageSize raw_response bodies
	// are resident at once instead of all candidateScanLimit of them.
	evals, err := r.collectReSpiderEvaluated(ctx)
	if err != nil {
		return fmt.Errorf("re-spider: failed to read candidates: %w", err)
	}
	// Client routes this scan's discovery found in the JavaScript: a route
	// only the router knows becomes a browser navigation in the same scan.
	evals = append(evals, r.collectReSpiderRoutes(ctx, infra.scanUUID)...)

	// Select seeds: dedup against already-crawled shells, keep only rich/SPA/
	// interactive non-login pages, rank, and apply per-host + total caps. Pure
	// (no browser) so it is unit-tested directly.
	perHost, total := rcfg.SeedsPerHost(), rcfg.SeedsTotal()
	chosen, skips, kept := selectReSpiderSeedsFromEvaluated(evals, perHost, total)
	if len(chosen) == 0 {
		r.printPhaseComplete("Re-spider", fmt.Sprintf("no rich routes to re-crawl (%s)", formatRespiderSkips(skips)))
		return nil
	}

	r.printPhaseDetail(fmt.Sprintf("Selected %s rich routes to re-crawl (%s kept%s; skips: %s; budget %s/%d-states per seed, cap %d)",
		terminal.Orange(fmt.Sprintf("%d", len(chosen))),
		terminal.HiTeal(fmt.Sprintf("%d", kept)),
		routeSeedNote(chosen),
		formatRespiderSkips(skips),
		rcfg.PerSeedDuration().String(),
		rcfg.PerSeedStates(),
		total,
	))

	// Browser settings mirror the spidering phase (value copy; safe to override).
	spCfg := r.settings.Spidering
	if utils.EnvTruthy(spitolas.EnvBrowserHeaded) {
		spCfg.Headless = false
	}

	stepCtx, stepCancel := context.WithTimeout(ctx, rcfg.StepDuration())
	defer stepCancel()

	// Per-seed config template. Built by the same helper the spidering phase uses
	// so the browser settings, auth bridge, scope adapter, and intensity-derived
	// login/registration policy are one decision rather than two copies that drift
	// — only the re-spider budgets and the record source differ. TargetURL is set
	// per seed (per-seed path) or per session (session path) below.
	baseCfg := r.buildSpiderConfig("", spCfg, rcfg.PerSeedDuration(), infra)
	baseCfg.MaxDepth = rcfg.Depth()
	baseCfg.MaxStates = rcfg.PerSeedStates()
	baseCfg.Source = "respider"
	r.trackBrowserRequests().wire(&baseCfg)

	var totals reSpiderGroupResult
	if spiderSessionReuseDisabled() {
		// Escape hatch: the proven fresh-browser-per-seed path (seeds of one host
		// are interspersed by score, so it needs the shared ssoSkip map).
		ssoSkip := map[string]struct{}{}
		totals = r.crawlReSpiderPerSeed(stepCtx, chosen, baseCfg, rcfg.PerSeedDuration(), ssoSkip)
	} else {
		// Default: reuse one browser context per host across its seeds so cookies,
		// local storage, and capture dedup persist instead of paying a fresh
		// browser launch (and losing any authenticated session) for every seed.
		totals = r.crawlReSpiderBySession(stepCtx, chosen, baseCfg, rcfg.PerSeedDuration())
	}
	totalRecords, crawled, ssoHit := totals.records, totals.crawled, totals.ssoHit

	if totalRecords > 0 {
		if err := r.repository.IncrementProcessedCount(stepCtx, infra.scanUUID, int64(totalRecords)); err != nil {
			zap.L().Warn("Re-spider: failed to increment processed count", zap.Error(err))
		}
	}

	// What the browser capture actually managed to persist, onto the phase
	// outcome — see recordCapture. This phase closes its RecordWriter
	// fire-and-forget too, so without this a re-crawl that lost everything it
	// captured still recorded state: "completed".
	recordCapture(r.currentPhase.Load(), totals.capture)

	detail := fmt.Sprintf("completed — re-crawled %s routes, %s new records%s in %s",
		terminal.Orange(fmt.Sprintf("%d", crawled)),
		terminal.Orange(fmt.Sprintf("%d", totalRecords)),
		terminal.Yellow(captureIncompleteNote(totals.capture)),
		time.Since(phaseStart).Round(time.Millisecond))
	if ssoHit > 0 {
		detail += terminal.Gray(fmt.Sprintf(" (%d skipped: SSO/login wall)", ssoHit))
	}
	r.printPhaseComplete("Re-spider", detail)
	return nil
}

// spiderSessionReuseDisabled reports whether the operator opted out of reusing
// one browser context across a host's seeds (the escape hatch if the session
// path misbehaves), reverting to a fresh browser per seed. Governs both the
// spidering phase and the re-spider phase — it is the same mechanism.
func spiderSessionReuseDisabled() bool {
	return utils.EnvTruthy("VIGOLIUM_SPIDER_NO_SESSION_REUSE")
}

// applyReSpiderSSO records an SSO/login-wall landing: it marks the host so its
// remaining seeds are skipped and feeds the wall host into the scan-wide fuzz
// exclusion the discovery auto-fuzz uses. Returns true when the seed hit a wall.
func (r *Runner) applyReSpiderSSO(result *spitolas.SpiderResult, hostKey string, ssoSkip map[string]struct{}) bool {
	if !result.OffHostRedirect || !result.LandingIsLogin {
		return false
	}
	ssoSkip[hostKey] = struct{}{}
	if hosts := ssoHostsFromSpider(result.WallHosts, result.LandingURL); len(hosts) > 0 {
		r.spidering.ssoHosts = append(r.spidering.ssoHosts, hosts...)
		r.spidering.sawSSO = true
	}
	zap.L().Info("Re-spider: seed redirected to a login wall; skipping remaining seeds on host",
		zap.String("host", hostKey), zap.String("landing", result.LandingURL))
	return true
}

// crawlReSpiderPerSeed crawls each seed with its own fresh browser (the original,
// proven behavior). ssoSkip is consulted/updated so a host's seeds stop after a
// login wall.
func (r *Runner) crawlReSpiderPerSeed(ctx context.Context, chosen []respiderSeed, baseCfg spitolas.SpiderConfig, perSeed time.Duration, ssoSkip map[string]struct{}) (res reSpiderGroupResult) {
	for _, s := range chosen {
		if ctx.Err() != nil {
			zap.L().Info("Re-spider: step budget reached, stopping", zap.Int("crawled", res.crawled))
			break
		}
		if _, blocked := ssoSkip[s.hostKey]; blocked {
			continue
		}
		cfg := baseCfg
		cfg.TargetURL = s.url
		rw := r.newScanRecordWriter()
		seedCtx, cancel := context.WithTimeout(ctx, perSeed)
		// Watchdog bounds RunSpider + rw.Close so a wedged browser can't hang the phase.
		oc := runSpiderWatchdog(seedCtx, cfg, rw, perSeed, s.url)
		cancel()
		res.capture.Merge(oc.capture())
		if oc.err != nil {
			zap.L().Warn("Re-spider: crawl failed", zap.String("seed", s.url), zap.Error(oc.err))
			continue
		}
		res.crawled++
		res.records += oc.res.RecordsSaved
		if r.applyReSpiderSSO(oc.res, s.hostKey, ssoSkip) {
			res.ssoHit++
		}
	}
	return
}

// reSpiderGroupResult aggregates one host group's crawl outcome so groups can run
// concurrently and merge their results under a single lock.
type reSpiderGroupResult struct {
	crawled  int
	records  int
	ssoHit   int
	ssoHosts []string // login-wall hosts to feed into the scan-wide fuzz exclusion
	capture  spitolas.CaptureReceipt
}

// crawlReSpiderHostGroup crawls all of one host's seeds in a single shared browser
// session (cookies/local storage/capture-dedup persist between them) and returns a
// fully self-contained result — it touches no shared runner state, so groups are
// safe to run concurrently. A wedged seed abandons the session (left to leak until
// exit, mirroring the per-seed watchdog).
func (r *Runner) crawlReSpiderHostGroup(ctx context.Context, group []respiderSeed, baseCfg spitolas.SpiderConfig, perSeed time.Duration) reSpiderGroupResult {
	var res reSpiderGroupResult
	hostKey := group[0].hostKey

	base := baseCfg
	base.TargetURL = group[0].url
	rw := r.newScanRecordWriter()
	sess, serr := spitolas.NewSpiderSession(ctx, base, rw)
	if serr != nil {
		// The browser couldn't launch; a fresh-browser-per-seed attempt would fail
		// the same way, so skip this host.
		zap.L().Warn("Re-spider: session launch failed, skipping host",
			zap.String("host", hostKey), zap.Error(serr))
		rw.Close()
		return res
	}

	abandoned := false
	for _, s := range group {
		if ctx.Err() != nil {
			break
		}
		seedCtx, cancel := context.WithTimeout(ctx, perSeed)
		oc := runReSpiderSessionCrawl(seedCtx, sess, s.url, perSeed)
		cancel()
		if oc.err != nil {
			// Only a wedged browser is abandoned; see runWithWatchdog. An ordinary
			// crawl failure leaves a healthy session whose writer still holds this
			// host's records, so it gets closed (and flushed) like any other.
			abandoned = oc.wedged
			if abandoned {
				zap.L().Warn("Re-spider: browser wedged; abandoning host session and killing its browser process",
					zap.String("seed", s.url), zap.Error(oc.err))
				// Nothing will close an abandoned session, so without this the
				// Chromium process and its profile survive the rest of the scan —
				// one per wedged host. Kill takes no lock the wedged crawl goroutine
				// could be holding; its own goroutine because the launcher's kill
				// waits for the process to exit.
				go sess.Kill()
			} else {
				zap.L().Warn("Re-spider: session crawl failed; closing host session",
					zap.String("seed", s.url), zap.Error(oc.err))
			}
			break
		}
		result := oc.res
		res.crawled++
		res.records += result.RecordsSaved
		if result.OffHostRedirect && result.LandingIsLogin {
			res.ssoHit++
			res.ssoHosts = append(res.ssoHosts, ssoHostsFromSpider(result.WallHosts, result.LandingURL)...)
			zap.L().Info("Re-spider: seed redirected to a login wall; skipping remaining seeds on host",
				zap.String("host", hostKey), zap.String("landing", result.LandingURL))
			break // remaining seeds on this host sit behind the same wall
		}
	}
	res.capture = sessionCapture(sess, rw, abandoned)
	return res
}

// crawlReSpiderBySession reuses one browser context per host across its seeds. It
// crawls host groups sequentially by default (one browser at a time — the proven
// behavior) or, when VIGOLIUM_SPIDER_HOST_PARALLELISM>1, up to that many
// independent hosts concurrently. Hosts are independent (each session owns its own
// browser), so the only shared state — the aggregate totals and the scan-wide
// SSO-host feed — is merged under a lock.
func (r *Runner) crawlReSpiderBySession(ctx context.Context, chosen []respiderSeed, baseCfg spitolas.SpiderConfig, perSeed time.Duration) (total reSpiderGroupResult) {
	groups := groupByHost(chosen, func(s respiderSeed) string { return s.hostKey })
	par := reSpiderHostParallelism(len(groups))

	merge := func(res reSpiderGroupResult) {
		total.crawled += res.crawled
		total.records += res.records
		total.ssoHit += res.ssoHit
		total.capture.Merge(res.capture)
		r.feedReSpiderSSOHosts(res.ssoHosts)
	}

	if par <= 1 {
		for _, group := range groups {
			if ctx.Err() != nil {
				zap.L().Info("Re-spider: step budget reached, stopping", zap.Int("crawled", total.crawled))
				break
			}
			merge(r.crawlReSpiderHostGroup(ctx, group, baseCfg, perSeed))
		}
		return
	}

	zap.L().Info("Re-spider: crawling independent hosts concurrently",
		zap.Int("hosts", len(groups)), zap.Int("parallelism", par))
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, par)
	)
	for _, group := range groups {
		if ctx.Err() != nil {
			break
		}
		group := group
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			res := r.crawlReSpiderHostGroup(ctx, group, baseCfg, perSeed)
			mu.Lock()
			merge(res)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return
}

// feedReSpiderSSOHosts records login-wall hosts into the scan-wide fuzz exclusion.
// Callers running host groups concurrently must hold the aggregation lock.
func (r *Runner) feedReSpiderSSOHosts(hosts []string) {
	if len(hosts) == 0 {
		return
	}
	r.spidering.ssoHosts = append(r.spidering.ssoHosts, hosts...)
	r.spidering.sawSSO = true
}

// reSpiderHostParallelism returns how many independent host sessions to crawl
// concurrently. Default 2 (ECON-9: hosts used to be crawled strictly one at a
// time); VIGOLIUM_SPIDER_HOST_PARALLELISM=N overrides (1 = sequential), capped
// so concurrent-browser memory stays bounded and never exceeding the number of
// hosts.
func reSpiderHostParallelism(numGroups int) int {
	n := defaultSpiderHostParallelism
	if v := strings.TrimSpace(os.Getenv("VIGOLIUM_SPIDER_HOST_PARALLELISM")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	if n > reSpiderHostParallelismCap {
		n = reSpiderHostParallelismCap
	}
	if n > numGroups {
		n = numGroups
	}
	if n < 1 {
		n = 1
	}
	return n
}

// reSpiderHostParallelismCap bounds concurrent browser contexts so an opt-in
// parallel re-spider cannot exhaust memory on a many-host scan.
const reSpiderHostParallelismCap = 4

// defaultSpiderHostParallelism is the host-session concurrency without the
// environment override (ECON-9).
const defaultSpiderHostParallelism = 2

// respiderEvaluated is the body-free reduction of a candidate row. Reducing each
// page to this form lets the phase page through candidates without holding every
// raw_response body resident at once.
type respiderEvaluated struct {
	source      string
	hostname    string
	url         string
	isSpidering bool            // source == "spidering" with a 200 status + parseable URL
	spiderShell string          // already-crawled shell fingerprint (isSpidering only)
	decodeOK    bool            // candidate row decoded (non-spidering sources)
	verdict     respiderVerdict // candidate evaluation (set when decodeOK)
}

// reduceReSpiderRow decodes one candidate row into its body-free evaluated form
// so the caller can discard the raw_response afterward. It mirrors the two roles
// a row plays in selectReSpiderSeedsFromEvaluated: a spidering-200 row
// contributes an already-crawled shell fingerprint; any other candidate source
// contributes an evaluation verdict.
func reduceReSpiderRow(row *database.ReSpiderCandidate) respiderEvaluated {
	e := respiderEvaluated{source: row.Source, hostname: row.Hostname, url: row.URL}
	if row.Source == "spidering" {
		if in, ok := decodeReSpiderRow(row); ok && in.StatusCode == 200 {
			if u, perr := neturl.Parse(in.URL); perr == nil {
				e.isSpidering = true
				e.spiderShell = shellFingerprint(u, in.Body)
			}
		}
		return e
	}
	switch row.Source {
	case "respider", "spec-ingest":
		return e // already-crawled or API specs — never a candidate
	}
	if in, ok := decodeReSpiderRow(row); ok {
		e.decodeOK = true
		e.verdict = evaluateReSpiderCandidate(in)
	}
	return e
}

// selectReSpiderSeeds reduces rows then selects seeds. Kept as a thin wrapper
// over selectReSpiderSeedsFromEvaluated so the pure selection stays directly
// unit-testable from in-memory candidate rows.
func selectReSpiderSeeds(rows []database.ReSpiderCandidate, perHost, total int) (chosen []respiderSeed, skips map[string]int, kept int) {
	evals := make([]respiderEvaluated, len(rows))
	for i := range rows {
		evals[i] = reduceReSpiderRow(&rows[i])
	}
	return selectReSpiderSeedsFromEvaluated(evals, perHost, total)
}

// selectReSpiderSeedsFromEvaluated picks re-crawl seeds from body-free evaluated
// candidates: it pre-seeds the shell-dedup set with already-crawled spidering
// shells, then keeps non-duplicate rich/SPA/interactive candidates, ranks them
// by score, and applies the per-host and total caps. Client-route candidates
// (routeSeedSource) carry no shell and skip the shell dedup, but share the
// route dedup and the caps with record-derived ones.
func selectReSpiderSeedsFromEvaluated(evals []respiderEvaluated, perHost, total int) (chosen []respiderSeed, skips map[string]int, kept int) {
	seenShells := make(map[string]struct{})
	seenRoutes := make(map[string]struct{})
	for i := range evals {
		if !evals[i].isSpidering {
			continue
		}
		if evals[i].spiderShell != "" {
			seenShells[evals[i].spiderShell] = struct{}{}
		}
		// Pre-seed route templates already covered by the one-shot spider so the
		// frontier doesn't re-crawl a data page whose template was already visited.
		if u, err := neturl.Parse(evals[i].url); err == nil && u.Host != "" {
			seenRoutes[canonicalRoute(u)] = struct{}{}
		}
	}

	skips = map[string]int{}
	var seeds []respiderSeed
	for i := range evals {
		e := &evals[i]
		switch e.source {
		case "spidering", "respider", "spec-ingest":
			continue // already-crawled or API specs — not candidates
		}
		if !e.decodeOK {
			skips["decode"]++
			continue
		}
		v := e.verdict
		if !v.Keep {
			skips[v.Reason]++
			continue
		}
		// A client-route seed has no stored response, so no shell: routes of
		// one SPA share a shell by design and each still renders its own view.
		if _, dup := seenShells[v.ShellHash]; dup && v.ShellHash != "" {
			skips["dup-shell"]++
			continue
		}
		// Canonical-route dedup: collapse a family of data pages sharing one route
		// template (/item/1, /item/2) to a single browser seed. Complements the
		// shell dedup above, which only catches shared client-side bundle sets.
		route := ""
		if u, err := neturl.Parse(e.url); err == nil && u.Host != "" {
			route = canonicalRoute(u)
			if _, dup := seenRoutes[route]; dup {
				skips["dup-route"]++
				continue
			}
		}
		if v.ShellHash != "" {
			seenShells[v.ShellHash] = struct{}{}
		}
		if route != "" {
			seenRoutes[route] = struct{}{}
		}
		seeds = append(seeds, respiderSeed{url: e.url, hostKey: e.hostname, score: v.Score, source: e.source})
		kept++
	}

	sort.SliceStable(seeds, func(a, b int) bool { return seeds[a].score > seeds[b].score })
	hostCount := map[string]int{}
	chosen = make([]respiderSeed, 0, total)
	for _, s := range seeds {
		if len(chosen) >= total {
			break
		}
		if hostCount[s.hostKey] >= perHost {
			continue
		}
		hostCount[s.hostKey]++
		chosen = append(chosen, s)
	}
	return chosen, skips, kept
}

// decodeReSpiderRow parses a candidate's stored raw response into the fields the
// evaluator needs. Returns false when there is nothing usable to evaluate.
func decodeReSpiderRow(row *database.ReSpiderCandidate) (respiderInput, bool) {
	if len(row.RawResponse) == 0 || row.URL == "" {
		return respiderInput{}, false
	}
	resp := httpmsg.NewHttpResponse(row.RawResponse)
	return respiderInput{
		URL:         row.URL,
		StatusCode:  resp.StatusCode(),
		ContentType: row.ResponseContentType,
		Location:    resp.Header("Location"),
		Body:        resp.Body(),
	}, true
}

// routeSeedNote is the "; N from JS client routes" part of the selection line,
// empty when no client-route seed was chosen.
func routeSeedNote(chosen []respiderSeed) string {
	n := 0
	for _, s := range chosen {
		if s.source == routeSeedSource {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("; %d chosen from JS client routes", n)
}

// formatRespiderSkips renders the skip-reason tally as a compact, stable string.
func formatRespiderSkips(skips map[string]int) string {
	if len(skips) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(skips))
	for k := range skips {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, skips[k]))
	}
	return strings.Join(parts, ", ")
}
