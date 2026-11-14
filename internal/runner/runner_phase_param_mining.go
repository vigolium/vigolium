package runner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/parammine"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// paramMiningCandidateScan bounds how many of this scan's records candidate
// selection reads. Rows carry the raw request but no response body.
const paramMiningCandidateScan = 5000

// Keys of PhaseOutcome.Counts for the param-mining phase. Stable names: they
// are persisted on the scan row and read by consumers.
const (
	paramMiningCountCandidates  = "candidates"       // records read for selection
	paramMiningCountEndpoints   = "endpoints"        // endpoints chosen for mining
	paramMiningCountMined       = "mined"            // endpoints whose whole wordlist was tested
	paramMiningCountUnstable    = "unstable"         // endpoints abandoned: baselines disagreed
	paramMiningCountBlocked     = "blocked"          // endpoints stopped by a 403/429/edge-block burst
	paramMiningCountBudget      = "budget_exhausted" // endpoints that used max_requests_per_endpoint
	paramMiningCountFailed      = "failed"           // endpoints that errored (no baseline, transport)
	paramMiningCountNames       = "names_tested"     // candidate names sent, summed over endpoints
	paramMiningCountFound       = "params_found"     // confirmed hidden parameters
	paramMiningCountRecords     = "records_written"  // new param-mining records stored
	paramMiningCountWriteFailed = "write_failed"     // confirmed parameters whose record could not be stored
)

// paramMineEndpoint is one endpoint chosen for mining: the record it is
// replayed from and the host whose wordlist it uses.
type paramMineEndpoint struct {
	record   database.HTTPRecord
	hostname string
}

// runParamMiningPhase discovers hidden parameters on the dynamic endpoints this
// scan recorded, so the dynamic-assessment phase that follows tests them too.
//
// Each endpoint is mined by pkg/parammine (two-baseline stability profile,
// transport-sized chunks, bisection, confirmation). The wordlist puts the
// names the host's own JavaScript and traffic use first, then the configured
// extra list, then the built-in one. Every confirmed parameter is stored as a
// new record (source param-mining, remark param-mining:name=…;signal=…, the
// parameter flagged hidden), which dynamic assessment reads like any other.
//
// Traffic goes through the shared requester, so the scan's session, rate limit
// and host limiter apply; each endpoint is capped by max_requests_per_endpoint.
func (r *Runner) runParamMiningPhase(ctx context.Context, infra *phaseInfra) error {
	tracker := r.currentPhase.Load()
	phaseStart := time.Now()
	r.printPhaseStart("ParamMining", "hidden-parameter discovery on this scan's dynamic endpoints")

	if r.repository == nil || infra == nil || infra.httpRequester == nil {
		r.printPhaseDetail("nothing to mine — no database or requester")
		return nil
	}
	var cfg config.ParamMiningConfig
	if r.settings != nil {
		cfg = r.settings.DynamicAssessment.ParamMining
	}

	rows, err := r.repository.ParamMiningCandidates(ctx, infra.scanUUID, r.getInScopeDBHosts(ctx), paramMiningCandidateScan)
	if err != nil {
		return fmt.Errorf("param-mining: read candidates: %w", err)
	}
	endpoints := selectParamMiningEndpoints(rows, cfg.EndpointsPerHost())
	tracker.setCount(paramMiningCountCandidates, int64(len(rows)))
	tracker.setCount(paramMiningCountEndpoints, int64(len(endpoints)))
	if len(endpoints) == 0 {
		r.printPhaseComplete("ParamMining", "no dynamic 2xx GET/POST endpoints to mine")
		return nil
	}

	builtin, err := parammine.Builtin()
	if err != nil {
		return fmt.Errorf("param-mining: built-in wordlist: %w", err)
	}
	var extra []string
	if cfg.Wordlist != "" {
		if extra, err = parammine.ReadWordlistFile(cfg.Wordlist); err != nil {
			return fmt.Errorf("param-mining: read wordlist %s: %w", cfg.Wordlist, err)
		}
	}

	workers := cfg.Workers(r.options.Concurrency)
	r.printPhaseDetail(fmt.Sprintf("%s endpoints (top %d per host by risk) — up to %d requests each, %d at a time; wordlist: target-derived names, then %s",
		terminal.HiTeal(fmt.Sprintf("%d", len(endpoints))), cfg.EndpointsPerHost(), cfg.RequestsPerEndpoint(), workers,
		wordlistSourcesDesc(cfg.Wordlist, len(extra), len(builtin))))

	m := &paramMiner{
		r:       r,
		cfg:     cfg,
		scanID:  infra.scanUUID,
		send:    parammine.RequesterSender(infra.httpRequester),
		extra:   extra,
		builtin: builtin,
		words:   make(map[string]*hostWords),
	}
	tracker.setProgress("endpoints", func() (int64, int64) {
		return m.done.Load(), int64(len(endpoints))
	})
	m.run(ctx, endpoints, workers)

	counts := m.counts()
	for name, n := range counts {
		tracker.setCount(name, n)
	}
	if counts[paramMiningCountWriteFailed] > 0 {
		tracker.markPartial(database.ReasonPersistence)
	}
	r.printPhaseComplete("ParamMining", fmt.Sprintf("%s hidden parameters on %s endpoints in %s",
		terminal.Orange(fmt.Sprintf("%d", counts[paramMiningCountFound])),
		terminal.HiTeal(fmt.Sprintf("%d", len(endpoints))),
		terminal.HiPurple(fmtDuration(time.Since(phaseStart)))))
	r.printPhaseFeedback("ParamMining", fmt.Sprintf("mined %d, unstable %d, blocked %d, budget %d, failed %d; %d names tested",
		counts[paramMiningCountMined], counts[paramMiningCountUnstable], counts[paramMiningCountBlocked],
		counts[paramMiningCountBudget], counts[paramMiningCountFailed], counts[paramMiningCountNames]))
	zap.L().Info("ParamMining: completed", zap.Any("counts", counts))
	return nil
}

func wordlistSourcesDesc(path string, extra, builtin int) string {
	if path == "" {
		return fmt.Sprintf("%d built-in", builtin)
	}
	return fmt.Sprintf("%d from %s, %d built-in", extra, path, builtin)
}

// selectParamMiningEndpoints picks what to mine from candidate rows (already
// ranked by risk): one record per method+origin+path, dynamic content only (no
// static assets by path or content type), POST only with a body mining can
// extend, at most perHost per origin.
func selectParamMiningEndpoints(rows []database.HTTPRecord, perHost int) []paramMineEndpoint {
	seen := make(map[string]bool)
	perOrigin := make(map[string]int)
	var out []paramMineEndpoint
	for _, row := range rows {
		path, _, _ := strings.Cut(row.Path, "?")
		if modkit.IsStaticAssetPath(path) || modkit.IsStaticAssetContentType(row.ResponseContentType) {
			continue
		}
		if !paramMiningDynamicContent(row.ResponseContentType) {
			continue
		}
		if row.Method == "POST" && !paramMiningBodyUsable(row.RequestContentType) {
			continue
		}
		origin := fmt.Sprintf("%s://%s:%d", row.Scheme, strings.ToLower(row.Hostname), row.Port)
		key := row.Method + " " + origin + path
		if seen[key] {
			continue
		}
		if perHost > 0 && perOrigin[origin] >= perHost {
			continue
		}
		seen[key] = true
		perOrigin[origin]++
		out = append(out, paramMineEndpoint{record: row, hostname: strings.ToLower(row.Hostname)})
	}
	return out
}

// paramMiningDynamicContent reports a response type an application renders
// per request: HTML, JSON, XML, plain text, or none declared.
func paramMiningDynamicContent(ct string) bool {
	ct = strings.ToLower(ct)
	if ct == "" {
		return true
	}
	for _, frag := range []string{"html", "json", "xml", "text/plain"} {
		if strings.Contains(ct, frag) {
			return true
		}
	}
	return false
}

// paramMiningBodyUsable reports a POST body mining can add names to: form,
// JSON, multipart (names go on the query string) or none.
func paramMiningBodyUsable(ct string) bool {
	if strings.TrimSpace(ct) == "" {
		return true
	}
	switch _, class := httpmsg.ClassifyMediaType(ct, nil); class {
	case httpmsg.ContentTypeURLEncoded, httpmsg.ContentTypeJSON, httpmsg.ContentTypeMultipart:
		return true
	}
	return false
}

// paramMiner runs the endpoints and keeps the phase's tallies.
type paramMiner struct {
	r       *Runner
	cfg     config.ParamMiningConfig
	scanID  string
	send    parammine.Sender
	extra   []string
	builtin []string

	wordsMu sync.Mutex
	words   map[string]*hostWords // hostname -> merged wordlist

	done, mined, unstable, blocked, budget, failed atomic.Int64
	names, found, records, writeFailed             atomic.Int64
}

func (m *paramMiner) counts() map[string]int64 {
	return map[string]int64{
		paramMiningCountMined:       m.mined.Load(),
		paramMiningCountUnstable:    m.unstable.Load(),
		paramMiningCountBlocked:     m.blocked.Load(),
		paramMiningCountBudget:      m.budget.Load(),
		paramMiningCountFailed:      m.failed.Load(),
		paramMiningCountNames:       m.names.Load(),
		paramMiningCountFound:       m.found.Load(),
		paramMiningCountRecords:     m.records.Load(),
		paramMiningCountWriteFailed: m.writeFailed.Load(),
	}
}

// run mines endpoints on workers goroutines, stopping new work once ctx ends.
func (m *paramMiner) run(ctx context.Context, endpoints []paramMineEndpoint, workers int) {
	parallelEach(ctx, len(endpoints), workers, func(i int) {
		m.mineOne(ctx, endpoints[i])
		m.done.Add(1)
	})
}

// hostWords is one host's merged wordlist, loaded once.
type hostWords struct {
	once  sync.Once
	words []string
}

// wordsFor returns the host's merged wordlist, built once per host. The DB
// load runs outside wordsMu, so workers on other hosts are not held behind it.
func (m *paramMiner) wordsFor(ctx context.Context, hostname string) []string {
	m.wordsMu.Lock()
	hw := m.words[hostname]
	if hw == nil {
		hw = &hostWords{}
		m.words[hostname] = hw
	}
	m.wordsMu.Unlock()
	hw.once.Do(func() {
		host, err := m.r.repository.ParamNamesForHost(ctx, m.r.options.ProjectUUID, hostname)
		if err != nil {
			zap.L().Debug("ParamMining: host parameter names unavailable", zap.String("host", hostname), zap.Error(err))
		}
		hw.words = parammine.MergeWordlists(m.cfg.MaxWords, host.JS, host.Observed, m.extra, m.builtin)
	})
	return hw.words
}

func (m *paramMiner) mineOne(ctx context.Context, ep paramMineEndpoint) {
	rr, err := database.RecordToHttpRequestResponse(&ep.record)
	if err != nil {
		m.failed.Add(1)
		return
	}
	res, err := parammine.Mine(ctx, rr, m.wordsFor(ctx, ep.hostname), m.send, parammine.Config{
		MaxRequests: m.cfg.RequestsPerEndpoint(),
	})
	if err != nil {
		zap.L().Debug("ParamMining: endpoint not minable", zap.String("url", ep.record.URL), zap.Error(err))
		m.failed.Add(1)
		return
	}
	m.names.Add(int64(res.Tested))
	switch res.Aborted {
	case "":
		m.mined.Add(1)
	case parammine.AbortUnstable:
		m.unstable.Add(1)
	case parammine.AbortBlocked:
		m.blocked.Add(1)
	case parammine.AbortBudget:
		m.budget.Add(1)
	case parammine.AbortCanceled:
	default:
		m.failed.Add(1)
	}
	for _, hit := range res.Hits {
		m.found.Add(1)
		m.persist(ctx, res, hit)
	}
}

// persist stores one confirmed parameter's exchange as a param-mining record.
// On a detached context: a phase cut short must still keep what it confirmed.
func (m *paramMiner) persist(ctx context.Context, res parammine.Result, hit parammine.Hit) {
	r := m.r
	r.printPhaseFeedback("ParamMining", fmt.Sprintf("hidden parameter %s on %s %s (%s, %s: %s)",
		terminal.BoldOrange(hit.Name), res.Method, res.URL, hit.Location, hit.Signal, hit.Detail))
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cursorFlushBudget)
	defer cancel()
	_, created, err := r.repository.SaveParamMiningRecord(saveCtx, hit.Exchange, r.options.ProjectUUID, m.scanID,
		[]string{hit.Name}, []string{database.ParamMiningRemark(hit.Name, string(hit.Signal))})
	switch {
	case err != nil:
		m.writeFailed.Add(1)
		zap.L().Warn("ParamMining: failed to store record", zap.String("param", hit.Name), zap.String("url", res.URL), zap.Error(err))
	case created:
		m.records.Add(1)
	}
}
