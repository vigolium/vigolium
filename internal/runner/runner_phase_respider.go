package runner

import (
	"context"
	"fmt"
	neturl "net/url"
	"sort"
	"strings"
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

// respiderSeed is a chosen re-crawl target.
type respiderSeed struct {
	url     string
	hostKey string // hostname, for per-host capping and SSO skip
	score   int
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

	rows, err := r.repository.GetReSpiderCandidates(ctx, r.options.ProjectUUID, candidateScanLimit)
	if err != nil {
		return fmt.Errorf("re-spider: failed to read candidates: %w", err)
	}

	// Select seeds: dedup against already-crawled shells, keep only rich/SPA/
	// interactive non-login pages, rank, and apply per-host + total caps. Pure
	// (no browser) so it is unit-tested directly.
	perHost, total := rcfg.SeedsPerHost(), rcfg.SeedsTotal()
	chosen, skips, kept := selectReSpiderSeeds(rows, perHost, total)
	if len(chosen) == 0 {
		r.printPhaseComplete("Re-spider", fmt.Sprintf("no rich routes to re-crawl (%s)", formatRespiderSkips(skips)))
		return nil
	}

	r.printPhaseDetail(fmt.Sprintf("Selected %s rich routes to re-crawl (%s kept; skips: %s; budget %s/%d-states per seed, cap %d)",
		terminal.Orange(fmt.Sprintf("%d", len(chosen))),
		terminal.HiTeal(fmt.Sprintf("%d", kept)),
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

	var scopeFilter func(host, path string) bool
	if infra.scopeMatcher != nil && !infra.scopeMatcher.IsPassAll() {
		sm := infra.scopeMatcher
		scopeFilter = func(host, path string) bool { return sm.InScopeRequest(host, path, "", "") }
	}

	stepCtx, stepCancel := context.WithTimeout(ctx, rcfg.StepDuration())
	defer stepCancel()

	ssoSkip := map[string]struct{}{}
	var totalRecords, crawled, ssoHit int
	for _, s := range chosen {
		if stepCtx.Err() != nil {
			zap.L().Info("Re-spider: step budget reached, stopping", zap.Int("crawled", crawled))
			break
		}
		if _, blocked := ssoSkip[s.hostKey]; blocked {
			continue
		}

		cfg := spitolas.SpiderConfig{
			TargetURL:           s.url,
			MaxDepth:            rcfg.Depth(),
			MaxStates:           rcfg.PerSeedStates(),
			MaxDuration:         rcfg.PerSeedDuration(),
			MaxConsecutiveFails: spCfg.MaxConsecutiveFails,
			Headless:            spCfg.Headless,
			BrowserCount:        spCfg.BrowserCount,
			Strategy:            spCfg.Strategy,
			IncludeResponseBody: spCfg.IncludeResponseBody,
			IncludeHeaders:      true,
			Silent:              r.options.Silent,
			Verbose:             r.options.Verbose,
			BrowserEngine:       spCfg.BrowserEngine,
			BrowserPath:         spCfg.BrowserPath,
			NoCDP:               spCfg.NoCDP,
			NoForms:             spCfg.NoForms,
			ProxyURL:            r.options.ProxyURL,
			ScopeFilter:         scopeFilter,
			ProjectUUID:         r.options.ProjectUUID,
			Source:              "respider",
		}

		rw := database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
		seedCtx, cancel := context.WithTimeout(stepCtx, rcfg.PerSeedDuration())
		result, rerr := spitolas.RunSpider(seedCtx, cfg, rw)
		cancel()
		rw.Close()
		if rerr != nil {
			zap.L().Warn("Re-spider: crawl failed", zap.String("seed", s.url), zap.Error(rerr))
			continue
		}
		crawled++
		totalRecords += result.RecordsSaved

		// Defense-in-depth: even past the cheap screen, a seed can bounce to a
		// login wall. Record the host and skip its remaining seeds, and feed the
		// SSO host into the scan-wide exclusion the discovery auto-fuzz uses.
		if result.OffHostRedirect && result.LandingIsLogin {
			ssoHit++
			ssoSkip[s.hostKey] = struct{}{}
			if lu, perr := neturl.Parse(result.LandingURL); perr == nil && lu.Host != "" {
				r.spidering.ssoHosts = append(r.spidering.ssoHosts, lu.Host)
				r.spidering.sawSSO = true
			}
			zap.L().Info("Re-spider: seed redirected to a login wall; skipping remaining seeds on host",
				zap.String("seed", s.url), zap.String("landing", result.LandingURL))
		}
	}

	if totalRecords > 0 {
		if err := r.repository.IncrementProcessedCount(stepCtx, infra.scanUUID, int64(totalRecords)); err != nil {
			zap.L().Warn("Re-spider: failed to increment processed count", zap.Error(err))
		}
	}

	detail := fmt.Sprintf("completed — re-crawled %s routes, %s new records in %s",
		terminal.Orange(fmt.Sprintf("%d", crawled)),
		terminal.Orange(fmt.Sprintf("%d", totalRecords)),
		time.Since(phaseStart).Round(time.Millisecond))
	if ssoHit > 0 {
		detail += terminal.Gray(fmt.Sprintf(" (%d skipped: SSO/login wall)", ssoHit))
	}
	r.printPhaseComplete("Re-spider", detail)
	return nil
}

// selectReSpiderSeeds runs the two-pass selection over body-carrying records and
// returns the chosen seeds plus a skip tally. Pass 1 pre-seeds the shell-dedup
// set with shells the browser already crawled (spidering-sourced records) so a
// known SPA is never re-crawled. Pass 2 keeps rich/SPA/interactive non-login
// candidates whose shell is new, ranks them by score, then applies the per-host
// and total caps. No I/O — unit-tested directly.
func selectReSpiderSeeds(rows []database.ReSpiderCandidate, perHost, total int) (chosen []respiderSeed, skips map[string]int, kept int) {
	seenShells := make(map[string]struct{})
	for i := range rows {
		row := &rows[i]
		if row.Source != "spidering" {
			continue
		}
		in, ok := decodeReSpiderRow(row)
		if !ok || in.StatusCode != 200 {
			continue
		}
		if u, perr := neturl.Parse(in.URL); perr == nil {
			seenShells[shellFingerprint(u, in.Body)] = struct{}{}
		}
	}

	skips = map[string]int{}
	var seeds []respiderSeed
	for i := range rows {
		row := &rows[i]
		switch row.Source {
		case "spidering", "respider", "spec-ingest":
			continue // already-crawled or API specs — not candidates
		}
		in, ok := decodeReSpiderRow(row)
		if !ok {
			skips["decode"]++
			continue
		}
		v := evaluateReSpiderCandidate(in)
		if !v.Keep {
			skips[v.Reason]++
			continue
		}
		if _, dup := seenShells[v.ShellHash]; dup {
			skips["dup-shell"]++
			continue
		}
		seenShells[v.ShellHash] = struct{}{}
		seeds = append(seeds, respiderSeed{url: in.URL, hostKey: row.Hostname, score: v.Score})
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
