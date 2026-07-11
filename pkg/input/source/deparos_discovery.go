package source

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/internal/resources/wordlists"
	deparosconfig "github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	deparosstorage "github.com/vigolium/vigolium/pkg/deparos/storage"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit/specutil"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// RecordSaver persists HTTP request/response pairs to a database.
// This avoids importing pkg/database directly.
type RecordSaver interface {
	SaveRecord(ctx context.Context, httpRR *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error)
	SaveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, source string, projectUUID string) ([]string, error)
}

type analysisArtifactSaver interface {
	SaveAnalysisArtifact(
		ctx context.Context,
		httpRecordUUID, kind, filename, mediaType, sha256 string,
		content []byte,
		metadata string,
	) error
}

// spideredJSProvider is an optional capability of the record repository: it walks
// JavaScript responses earlier phases (spidering, proxy/Burp ingestion) already
// captured for a host, handing each to a callback as (url, content-type, decoded
// body). Discovery uses it to feed browser-collected bundles through the same
// JSTangle+linkfinder extraction the crawl runs on JS it fetches itself — those
// bundles live in the main DB, not the ephemeral discovery sitemap, so without
// this bridge their endpoints are never analyzed in the native pipeline. The
// signature is intentionally primitive-typed so pkg/database satisfies it
// structurally without either package importing the other.
type spideredJSProvider interface {
	WalkJavaScriptRecords(
		ctx context.Context,
		projectUUID, hostname string,
		limit int,
		fn func(recordURL, contentType string, body []byte) error,
	) error
}

// DeparosDiscoveryConfig configures the deparos content discovery source.
type DeparosDiscoveryConfig struct {
	Targets       []string      // Target URLs
	Concurrency   int           // Worker threads (from -t flag); default: 50
	MaxDuration   time.Duration // default: 1h
	EnableModules []string      // Module selection for WorkItems

	// Full deparos settings (from YAML config)
	Mode             string // "files_and_dirs" | "files_only" | "dirs_only"
	ScopeMode        string // "any" | "subdomain" | "exact"
	RecursionEnabled bool   // default: true
	RecursionDepth   int    // default: 5
	SaveResponseBody bool   // default: true

	// Wordlists
	ShortFilePath        string
	LongFilePath         string
	ShortDirPath         string
	LongDirPath          string
	FuzzWordlistPath     string
	UseObservedNames     bool
	UseObservedPaths     bool
	UseObservedFiles     bool
	EnableNumericFuzzing bool

	// Extensions
	TestCustom           bool
	CustomList           []string
	TestObserved         bool
	TestBackupExtensions bool
	BackupExtensions     []string
	TestNoExtension      bool

	// Confirmation-gated extension fuzzing. When ConfirmRequired is set, a
	// server-side extension (php/asp/aspx/jsp/action/cgi/…) is only wordlist-
	// fuzzed once the app is confirmed to serve it as a valid route via the
	// enabled sources below. Candidates/ProbeFilenames override the built-ins.
	ConfirmRequired       bool
	ConfirmViaObserved    bool
	ConfirmViaFingerprint bool
	ConfirmViaProbe       bool
	Candidates            []string
	ProbeFilenames        []string

	// JSBundleSweep enables the SPA-gated JS-bundle name sweep (main.js,
	// admin.js, config.js, …) on monolith apps; hits are fed to jstangle.
	// JSBundleNames overrides the curated name list (empty = built-in).
	JSBundleSweep bool
	JSBundleNames []string

	// Engine
	CaseSensitivity string // "auto_detect" | "sensitive" | "insensitive"
	EngineTimeout   time.Duration
	CustomHeaders   map[string]string
	// BrowserSessions carries WAF/bot-cleared sessions harvested by the spidering
	// browser, keyed by lowercased hostname. buildDeparosConfig injects the
	// session matching each target host (Cookie + optional pinned User-Agent) into
	// that target's request headers so content discovery crawls with the same
	// cleared session — set-if-absent, so a configured header always wins.
	BrowserSessions         map[string]httpmsg.CarriedSession
	EnableCookieJar         bool
	ProxyURL                string // HTTP proxy URL for discovery requests
	MaxConsecutiveErrors    int
	MaxConsecutiveWAFBlocks int
	ObservedMaxItems        int
	JSTangle                *deparosconfig.JSTangleConfig

	// Per-prefix circuit breaker (zero values = use deparos defaults).
	PrefixBreakerEnabled        *bool   // nil = default (true)
	PrefixBreakerMinSamples     int     // 0 = default
	PrefixBreakerTripRatio      float64 // 0 = default
	PrefixBreakerPrefixSegments int     // 0 = default
	PrefixBreakerLengthBucket   int64   // 0 = default

	// Malformed path probe
	EnableMalformedPathProbe bool

	// DedupClusterCap caps the number of near-identical responses kept per
	// cluster (same host/status/content-type, body size & word count within
	// 0.5%). 0 = use default (defaultDedupClusterCap); negative = disabled;
	// positive = that cap. Resolved via resolveClusterCap.
	DedupClusterCap int

	// DB import: if set, results are saved to vigolium's http_records table
	Repository  RecordSaver
	ProjectUUID string
}

const (
	// defaultDedupClusterCap is the per-cluster cap applied when a run does not
	// configure DedupClusterCap. Catch-all/SPA targets that answer 200 with the
	// same page for every path otherwise flood the report and the downstream
	// scan with hundreds of near-identical records.
	defaultDedupClusterCap = 10

	// dedupClusterTolerance is the relative band (0.5%) within which two
	// responses' body size and word count are treated as the same shape.
	dedupClusterTolerance = 0.005

	// crawlRecordSource labels http_records produced by deparos content
	// discovery (crawled directories/files/fuzzed paths). The post-discovery
	// dedup/status-retention passes are all scoped to this source.
	crawlRecordSource = "deparos"

	// specRecordSource labels http_records synthesized from a discovered API
	// spec (OpenAPI/Swagger/Postman). Kept DISTINCT from crawlRecordSource so the
	// post-discovery deparos dedup/status passes (which drop 4xx and collapse 401s
	// to one-per-host, scoped to source='deparos') leave these alone: spec routes
	// are real, documented endpoints — not fuzzed guesses — and every one must
	// survive (often as a uniform 401) to be scanned by dynamic assessment.
	specRecordSource = "api-spec"

	// jstangleRecordSource labels http_records recovered from the application's
	// own JavaScript by JSTangle (fetch/XHR/axios calls and GraphQL operations the
	// app actually makes). Like specRecordSource it is kept DISTINCT from
	// crawlRecordSource so the fuzz-oriented deparos dedup/status/cluster-cap
	// passes don't drop or collapse them: these are high-precision,
	// application-referenced requests — often non-GET with a real body — not
	// speculative wordlist guesses. An authenticated API commonly answers 401/403
	// without a session and placeholder substitution can make a genuine route 404,
	// exactly the responses the deparos passes prune.
	jstangleRecordSource = "jstangle"

	// formRecordSource labels http_records produced by submitting an HTML form
	// discovered during the crawl. Same rationale as jstangleRecordSource: these
	// are method/body-bearing, application-referenced requests, so they are kept
	// out of the fuzz-noise cleanup.
	formRecordSource = "html-form"
)

// classifyDiscoverySource maps a node's discovery provenance (FoundBy) to the
// http_records source label it should be persisted under. Code-referenced,
// method/body-bearing classes get their own label so the source='deparos'
// dedup/status/cluster-cap passes (which exist to tame catch-all/SPA fuzz
// floods) leave them intact. Everything else — spider links, wordlist/fuzz
// guesses, observed tokens, asset/manifest walks — keeps the crawlRecordSource
// label and remains subject to those passes; spider-referenced links in
// particular are the very catch-all surface the flood control targets, so they
// are deliberately NOT exempted here.
func classifyDiscoverySource(foundBy string) string {
	switch foundBy {
	case "js-extracted":
		return jstangleRecordSource
	case "form":
		return formRecordSource
	default:
		return crawlRecordSource
	}
}

// groupCollectedBySource buckets records by their source label, preserving the
// order in which each label is first seen (so the fuzz class, appended first,
// leads and per-run output is deterministic). It returns that first-seen label
// order, the per-label record slices, and a flat all-source list used for spec
// extraction and source-map artifact mapping.
func groupCollectedBySource(records []collectedRecord) (order []string, bySource map[string][]*httpmsg.HttpRequestResponse, flat []*httpmsg.HttpRequestResponse) {
	bySource = make(map[string][]*httpmsg.HttpRequestResponse, 3)
	order = make([]string, 0, 3)
	flat = make([]*httpmsg.HttpRequestResponse, 0, len(records))
	for _, rec := range records {
		if rec.rr == nil {
			continue
		}
		label := rec.source
		if label == "" {
			label = crawlRecordSource
		}
		if _, seen := bySource[label]; !seen {
			order = append(order, label)
		}
		bySource[label] = append(bySource[label], rec.rr)
		flat = append(flat, rec.rr)
	}
	return order, bySource, flat
}

// resolveClusterCap resolves the effective near-identical response cap.
// 0 => default (defaultDedupClusterCap); negative => disabled (returns 0);
// positive => that value.
func (c DeparosDiscoveryConfig) resolveClusterCap() int {
	switch {
	case c.DedupClusterCap == 0:
		return defaultDedupClusterCap
	case c.DedupClusterCap < 0:
		return 0
	default:
		return c.DedupClusterCap
	}
}

// DiscoveryStats tracks status code statistics for discovered and deduplicated records.
type DiscoveryStats struct {
	TotalDiscovered    int
	HardDedupRemoved   int
	FuzzyCappedRemoved int // records dropped by the near-identical cluster cap
	ClusterCap         int // effective per-cluster cap used (0 = disabled)
	Imported           int
	AllCodes           [5]int // index 0=1xx, 1=2xx, 2=3xx, 3=4xx, 4=5xx
	DedupedCodes       [5]int // status codes of hard-dedup removed records
	CappedCodes        [5]int // status codes of cluster-capped removed records
}

// statusCodeBucket returns the bucket index (0-4) for a status code.
func statusCodeBucket(code int) int {
	idx := code/100 - 1
	if idx < 0 {
		idx = 0
	}
	if idx > 4 {
		idx = 4
	}
	return idx
}

// hardDedupKey identifies records that are hard duplicates.
type hardDedupKey struct {
	hostname string
	method   string
	status   int
	length   int64
	respHash string
}

// collectedRecord is a discovered record plus the metadata used for exact
// deduplication and near-identical clustering. rr is nil for records evicted by
// exact dedup (the zero value acts as a tombstone during compaction). status is
// 0 for records with no response — those bypass clustering.
type collectedRecord struct {
	rr     *httpmsg.HttpRequestResponse
	path   string
	host   string
	method string
	// source is the http_records source label this record is persisted under,
	// derived from the node's discovery provenance (see classifyDiscoverySource).
	// crawlRecordSource ("deparos") records are the fuzz/crawl class subject to
	// the post-discovery flood-control passes; a distinct label (jstangle,
	// html-form) marks a code-referenced record that bypasses hard-dedup, the
	// cluster cap, and the DB-side deparos passes.
	source string
	status int
	ctype  string
	size   int64
	words  int64
}

// respCluster is a running representative for a group of near-identical
// responses during greedy clustering.
type respCluster struct {
	host    string
	method  string
	status  int
	ctype   string
	repSize int64
	repWord int64
	count   int
}

// capNearIdenticalClusters keeps at most capN records per near-identical
// cluster. Two records share a cluster when they have the same host, status,
// and content-type, and their body size and word count are each within
// dedupClusterTolerance (0.5%) of the cluster's representative. Records are
// processed shortest-path-first so the kept representatives are the shallowest
// (most likely real) paths. Records without a response (status 0) bypass
// clustering and are always kept.
//
// Returns the kept records (re-ordered shortest-path-first), the number of
// records capped (dropped), and per-status-bucket counts of the capped records.
func capNearIdenticalClusters(records []collectedRecord, capN int) ([]collectedRecord, int, [5]int) {
	var cappedCodes [5]int
	if capN <= 0 {
		return records, 0, cappedCodes
	}

	sorted := make([]collectedRecord, len(records))
	copy(sorted, records)
	sort.SliceStable(sorted, func(i, j int) bool {
		if len(sorted[i].path) != len(sorted[j].path) {
			return len(sorted[i].path) < len(sorted[j].path)
		}
		return sorted[i].path < sorted[j].path
	})

	var clusters []*respCluster
	kept := make([]collectedRecord, 0, len(sorted))
	capped := 0

	for _, rec := range sorted {
		// No-response records can't be clustered by body shape — always keep.
		if rec.status == 0 {
			kept = append(kept, rec)
			continue
		}

		var match *respCluster
		for _, cl := range clusters {
			if cl.status != rec.status || cl.host != rec.host || cl.method != rec.method || cl.ctype != rec.ctype {
				continue
			}
			if withinDedupTolerance(cl.repSize, rec.size) && withinDedupTolerance(cl.repWord, rec.words) {
				match = cl
				break
			}
		}

		if match == nil {
			clusters = append(clusters, &respCluster{
				host:    rec.host,
				method:  rec.method,
				status:  rec.status,
				ctype:   rec.ctype,
				repSize: rec.size,
				repWord: rec.words,
				count:   1,
			})
			kept = append(kept, rec)
			continue
		}

		if match.count < capN {
			match.count++
			kept = append(kept, rec)
		} else {
			capped++
			cappedCodes[statusCodeBucket(rec.status)]++
		}
	}

	return kept, capped, cappedCodes
}

// withinDedupTolerance reports whether a and b are within dedupClusterTolerance
// (0.5%) of each other, relative to the larger value. Equal values (including
// both zero) always match. The relative band means small bodies require a
// near-exact match (0.5% of a few hundred bytes is <1 byte), so distinct small
// responses are not collapsed — only large near-identical pages cluster.
func withinDedupTolerance(a, b int64) bool {
	if a == b {
		return true
	}
	maxv := max(a, b)
	if maxv <= 0 {
		return true
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return float64(diff)/float64(maxv) <= dedupClusterTolerance
}

// DeparosDiscoverySource uses the deparos library to discover content,
// then converts results to input for scanning.
type DeparosDiscoverySource struct {
	cfg DeparosDiscoveryConfig

	mu      sync.Mutex
	items   chan *work.WorkItem
	done    chan struct{}
	cancel  context.CancelFunc
	started bool
	closed  bool
	runErr  error
	stats   DiscoveryStats
}

// Stats returns the discovery statistics (safe to call after the source is exhausted).
func (d *DeparosDiscoverySource) Stats() DiscoveryStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}

// NewDeparosDiscoverySource creates a new DeparosDiscoverySource.
func NewDeparosDiscoverySource(cfg DeparosDiscoveryConfig) (*DeparosDiscoverySource, error) {
	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 50
	}
	if cfg.MaxDuration <= 0 {
		cfg.MaxDuration = 1 * time.Hour
	}

	return &DeparosDiscoverySource{
		cfg:   cfg,
		items: make(chan *work.WorkItem, 100),
		done:  make(chan struct{}),
	}, nil
}

// Next returns the next discovered item.
// It lazily starts the discovery process on first call.
func (d *DeparosDiscoverySource) Next(ctx context.Context) (*work.WorkItem, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, io.EOF
	}
	if !d.started {
		d.started = true
		go d.runDiscovery()
	}
	d.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case item, ok := <-d.items:
		if !ok {
			d.mu.Lock()
			err := d.runErr
			d.mu.Unlock()
			if err != nil {
				return nil, err
			}
			return nil, io.EOF
		}
		return item, nil
	}
}

// runDiscovery runs deparos for each target and pushes results to the channel.
func (d *DeparosDiscoverySource) runDiscovery() {
	defer close(d.items)

	parentCtx, cancel := context.WithCancel(context.Background())
	d.mu.Lock()
	d.cancel = cancel
	d.mu.Unlock()

	defer cancel()

	for _, target := range d.cfg.Targets {
		select {
		case <-d.done:
			return
		default:
		}

		if err := d.discoverTarget(parentCtx, target); err != nil {
			zap.L().Warn("deparos discovery failed for target",
				zap.String("target", target), zap.Error(err))
		}
	}
}

// buildDeparosConfig builds a deparos Config from the DeparosDiscoveryConfig fields.
// buildDiscoveryHeaders returns the request headers for a discovery target: the
// configured custom headers, plus — when the spidering browser harvested a
// session for this target's host — that session's Cookie and (when carried) its
// User-Agent. Session values are added set-if-absent (case-insensitive) so a
// header the operator already configured always wins. Returns nil when there is
// nothing to send.
func (d *DeparosDiscoverySource) buildDiscoveryHeaders(target string) map[string]string {
	headers := make(map[string]string, len(d.cfg.CustomHeaders)+2)
	for k, v := range d.cfg.CustomHeaders {
		headers[k] = v
	}
	// A whole-Cookie set-if-absent (not a merge): the deparos crawler's existing
	// Cookie is a static operator config header for the whole crawl, so if one is
	// configured we honor it verbatim. This intentionally differs from the
	// scanner requester, which merges carried cookies into a request's own
	// dynamic Cookie header (see http.applyCarriedSession).
	if sess, ok := d.sessionForTarget(target); ok {
		if sess.CookieHeader != "" && !hasHeaderCI(headers, "Cookie") {
			headers["Cookie"] = sess.CookieHeader
		}
		if sess.UserAgent != "" && !hasHeaderCI(headers, "User-Agent") {
			headers["User-Agent"] = sess.UserAgent
		}
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

// sessionForTarget looks up the browser-harvested session whose host matches the
// target URL's host (same-host only), so a session is never sent to a host it
// was not harvested from.
func (d *DeparosDiscoverySource) sessionForTarget(target string) (httpmsg.CarriedSession, bool) {
	if len(d.cfg.BrowserSessions) == 0 {
		return httpmsg.CarriedSession{}, false
	}
	host := httpmsg.HostnameFromURL(target)
	if host == "" {
		return httpmsg.CarriedSession{}, false
	}
	sess, ok := d.cfg.BrowserSessions[host]
	return sess, ok
}

// hasHeaderCI reports whether m already contains name under any case.
func hasHeaderCI(m map[string]string, name string) bool {
	for k := range m {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

func (d *DeparosDiscoverySource) buildDeparosConfig(target string) *deparosconfig.Config {
	cfg := deparosconfig.NewDefaultConfig()
	cfg.Target.StartURL = target
	cfg.Engine.DiscoveryThreads = d.cfg.Concurrency

	// Discovery mode
	switch d.cfg.Mode {
	case "files_only":
		cfg.Target.Mode = deparosconfig.ModeFilesOnly
	case "dirs_only":
		cfg.Target.Mode = deparosconfig.ModeDirsOnly
	case "files_and_dirs", "":
		cfg.Target.Mode = deparosconfig.ModeFilesAndDirs
	}

	// Scope mode
	if d.cfg.ScopeMode != "" {
		cfg.Target.ScopeMode = d.cfg.ScopeMode
	}

	// Recursion
	cfg.Target.Recursion.Enabled = d.cfg.RecursionEnabled
	if d.cfg.RecursionDepth > 0 {
		cfg.Target.Recursion.MaxDepth = int16(d.cfg.RecursionDepth)
	}

	// Wordlists
	if d.cfg.ShortFilePath != "" {
		cfg.Filenames.Wordlists.ShortFilePath = d.cfg.ShortFilePath
	}
	if d.cfg.LongFilePath != "" {
		cfg.Filenames.Wordlists.LongFilePath = d.cfg.LongFilePath
	}
	if d.cfg.ShortDirPath != "" {
		cfg.Filenames.Wordlists.ShortDirPath = d.cfg.ShortDirPath
	}
	if d.cfg.LongDirPath != "" {
		cfg.Filenames.Wordlists.LongDirPath = d.cfg.LongDirPath
	}
	if d.cfg.FuzzWordlistPath != "" {
		cfg.Filenames.Wordlists.FuzzWordlistPath = d.cfg.FuzzWordlistPath
	}
	cfg.Filenames.UseObservedNames = d.cfg.UseObservedNames
	cfg.Filenames.UseObservedPaths = d.cfg.UseObservedPaths
	cfg.Filenames.UseObservedFiles = d.cfg.UseObservedFiles
	cfg.Filenames.EnableNumericFuzzing = d.cfg.EnableNumericFuzzing

	// Extensions
	cfg.Extensions.TestCustom = d.cfg.TestCustom
	if len(d.cfg.CustomList) > 0 {
		cfg.Extensions.CustomList = d.cfg.CustomList
	}
	cfg.Extensions.TestObserved = d.cfg.TestObserved
	cfg.Extensions.TestBackupExtensions = d.cfg.TestBackupExtensions
	if len(d.cfg.BackupExtensions) > 0 {
		cfg.Extensions.BackupExtensions = d.cfg.BackupExtensions
	}
	cfg.Extensions.TestNoExtension = d.cfg.TestNoExtension

	// Confirmation-gated extension fuzzing
	cfg.Extensions.ConfirmRequired = d.cfg.ConfirmRequired
	cfg.Extensions.ConfirmViaObserved = d.cfg.ConfirmViaObserved
	cfg.Extensions.ConfirmViaFingerprint = d.cfg.ConfirmViaFingerprint
	cfg.Extensions.ConfirmViaProbe = d.cfg.ConfirmViaProbe
	if len(d.cfg.Candidates) > 0 {
		cfg.Extensions.Candidates = d.cfg.Candidates
	}
	if len(d.cfg.ProbeFilenames) > 0 {
		cfg.Extensions.ProbeFilenames = d.cfg.ProbeFilenames
	}

	// SPA-gated JS-bundle name sweep
	cfg.Extensions.JSBundleSweep = d.cfg.JSBundleSweep
	if len(d.cfg.JSBundleNames) > 0 {
		cfg.Extensions.JSBundleNames = d.cfg.JSBundleNames
	}

	// Engine settings
	switch d.cfg.CaseSensitivity {
	case "sensitive":
		cfg.Engine.CaseSensitivity = deparosconfig.CaseSensitive
	case "insensitive":
		cfg.Engine.CaseSensitivity = deparosconfig.CaseInsensitive
	case "auto_detect", "":
		cfg.Engine.CaseSensitivity = deparosconfig.CaseAutoDetect
	}
	if d.cfg.EngineTimeout > 0 {
		cfg.Engine.Timeout = d.cfg.EngineTimeout
	}
	cfg.Engine.CustomHeaders = d.buildDiscoveryHeaders(target)
	cfg.Engine.EnableCookieJar = d.cfg.EnableCookieJar
	if d.cfg.ProxyURL != "" {
		cfg.Engine.ProxyURL = d.cfg.ProxyURL
	}
	cfg.Engine.MaxConsecutiveErrors = d.cfg.MaxConsecutiveErrors
	cfg.Engine.MaxConsecutiveWAFBlocks = d.cfg.MaxConsecutiveWAFBlocks
	if d.cfg.ObservedMaxItems > 0 {
		cfg.Engine.ObservedMaxItems = d.cfg.ObservedMaxItems
	}
	// Always disable the crawl's inline secret scan on the integrated path. The
	// records this adapter collects are persisted and then scanned for secrets by
	// the main pipeline — the secret_detect passive module (dynamic-assessment) and
	// the known-issue-scan batch — so an in-crawl scan is pure double work whose
	// matches are, in any case, never promoted out of the ephemeral sitemap into
	// the findings DB (StreamAllResults below does not read node.SecretFindings()).
	// To surface discovery-native secrets instead, re-enable this and promote
	// node.SecretFindings() in the StreamAllResults loop.
	cfg.Engine.DisableSecretScan = true
	if d.cfg.JSTangle != nil {
		cfg.JSTangle = *d.cfg.JSTangle
	}

	// Prefix breaker overrides — zero/nil values keep deparos defaults.
	if d.cfg.PrefixBreakerEnabled != nil {
		cfg.Engine.PrefixBreaker.Enabled = *d.cfg.PrefixBreakerEnabled
	}
	if d.cfg.PrefixBreakerMinSamples > 0 {
		cfg.Engine.PrefixBreaker.MinSamples = d.cfg.PrefixBreakerMinSamples
	}
	if d.cfg.PrefixBreakerTripRatio > 0 {
		cfg.Engine.PrefixBreaker.TripRatio = d.cfg.PrefixBreakerTripRatio
	}
	if d.cfg.PrefixBreakerPrefixSegments > 0 {
		cfg.Engine.PrefixBreaker.PrefixSegments = d.cfg.PrefixBreakerPrefixSegments
	}
	if d.cfg.PrefixBreakerLengthBucket > 0 {
		cfg.Engine.PrefixBreaker.LengthBucket = d.cfg.PrefixBreakerLengthBucket
	}

	// Malformed path probe
	cfg.Filenames.EnableMalformedPathProbe = d.cfg.EnableMalformedPathProbe
	if d.cfg.EnableMalformedPathProbe {
		cfg.Filenames.MalformedPathProbePayloads = loadEmbeddedFuzzWordlist()
	}

	return cfg
}

// loadEmbeddedFuzzWordlist loads fuzz.txt from the embedded presets filesystem.
func loadEmbeddedFuzzWordlist() [][]byte {
	data, err := wordlists.WordlistsFS.ReadFile("fuzz.txt")
	if err != nil {
		zap.L().Warn("Failed to read embedded fuzz.txt", zap.Error(err))
		return nil
	}

	var payloads [][]byte
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		payloads = append(payloads, cp)
	}
	return payloads
}

// discoverTarget runs discovery against a single target URL.
func (d *DeparosDiscoverySource) discoverTarget(parentCtx context.Context, target string) error {
	zap.L().Info("Starting deparos discovery",
		zap.String("target", target),
		zap.Int("threads", d.cfg.Concurrency),
		zap.Duration("max_time", d.cfg.MaxDuration))

	// Build deparos config from all settings
	cfg := d.buildDeparosConfig(target)

	// Create ephemeral SQLite storage
	storageCfg := deparosstorage.DefaultConfig()
	storageCfg.SaveResponseBody = d.cfg.SaveResponseBody
	siteMap, err := deparosstorage.NewSiteMap(storageCfg)
	if err != nil {
		return fmt.Errorf("create sitemap: %w", err)
	}
	defer func() { _ = siteMap.Close() }()

	// Run discovery with timeout
	ctx, cancel := context.WithTimeout(parentCtx, d.cfg.MaxDuration)
	defer cancel()

	// Bridge browser-spidered JS into the discovery sitemap before the engine
	// starts, so its init-time JSTangle pass analyzes bundles the crawl itself
	// never fetches (SPA bundles the browser revealed).
	d.seedSpideredJS(ctx, siteMap, target)

	engine, err := discovery.NewEngineWithContext(ctx, cfg, siteMap)
	if err != nil {
		return fmt.Errorf("create engine: %w", err)
	}

	// Announce confirmed server-side extensions as they're queued for fuzzing.
	engine.SetExtensionConfirmCallback(func(ev discovery.ExtensionConfirmEvent) {
		detail := ""
		if ev.Detail != "" {
			detail = terminal.Gray(" (" + ev.Detail + ")")
		}
		terminal.AgentNotice("ext-fuzz", fmt.Sprintf(
			"%s detected as a valid route via %s%s — fuzzing wordlist for hidden %s files on %s",
			terminal.BoldOrange("."+ev.Extension),
			terminal.HiTeal(ev.Source),
			detail,
			terminal.HiCyan("*."+ev.Extension),
			target))
	})

	if err := engine.Start(); err != nil {
		return fmt.Errorf("start engine: %w", err)
	}

	_ = engine.WaitForQueues(ctx)
	engine.FlushSecretFindings()
	engine.Stop()

	// Collect all results into memory for in-memory hard dedup
	var allRecords []collectedRecord
	dedupMap := make(map[hardDedupKey]int) // key → index in allRecords

	var localStats DiscoveryStats

	err = siteMap.StreamAllResults(func(node *deparosstorage.DiscoveredNode) error {
		select {
		case <-d.done:
			return fmt.Errorf("source closed")
		default:
		}

		nodeURL := node.URL()
		if nodeURL == nil {
			return nil
		}

		// Preserve the discovered method/headers/body. Deparos storage persists
		// these (req_method/req_headers/req_body) for form POSTs and JS-derived
		// API calls; importing them as a bodyless GET would silently drop that
		// API/form coverage from dynamic assessment.
		method := "GET"
		var reqHeaders map[string]string
		var reqBody []byte
		if req := node.Request(); req != nil {
			if req.Method != "" {
				method = strings.ToUpper(req.Method)
			}
			reqHeaders = req.Headers
			reqBody = req.Body
		}

		rr, err := httpmsg.GetRawRequestFromURLWithMethod(nodeURL.String(), method, reqHeaders, reqBody)
		if err != nil {
			return nil // skip URLs we can't parse
		}

		// Classify provenance: code-referenced classes (JSTangle/form) carry a
		// distinct source label and bypass the fuzz-noise cleanup entirely.
		recSource := crawlRecordSource
		if meta := node.Metadata(); meta != nil {
			recSource = classifyDiscoverySource(meta.FoundBy)
		}
		referenced := recSource != crawlRecordSource

		resp := node.Response()
		hasResp := resp != nil && resp.StatusCode > 0

		rec := collectedRecord{rr: rr, path: nodeURL.Path, host: nodeURL.Hostname(), method: method, source: recSource}

		// Attach response data if available
		if hasResp {
			rawResp := httpmsg.BuildRawResponse(resp.StatusCode, resp.Headers, string(resp.Body))
			httpResp := httpmsg.NewHttpResponse(rawResp)
			rr = rr.WithResponse(httpResp)
			rec.rr = rr
			rec.status = resp.StatusCode
			rec.ctype = resp.MIMEType
			rec.size = int64(len(resp.Body))
			rec.words = resp.Words
			if rec.words == 0 && len(resp.Body) > 0 {
				rec.words = int64(len(strings.Fields(string(resp.Body))))
			}
		}

		localStats.TotalDiscovered++
		if hasResp {
			localStats.AllCodes[statusCodeBucket(resp.StatusCode)]++
		}

		// Skip the fuzz-noise hard dedup for records without a response (no body to
		// hash) and for code-referenced records (JSTangle/form): the latter are
		// high-precision application endpoints that must all survive, even when two
		// distinct routes happen to return byte-identical bodies (e.g. two APIs
		// both answering `{}`).
		if !hasResp || referenced {
			allRecords = append(allRecords, rec)
			return nil
		}

		// Exact dedup keyed on the response BODY hash (not the full raw
		// response): volatile headers like Date/Set-Cookie and Go's randomized
		// header-map ordering otherwise make every raw response hash unique,
		// defeating the dedup. Body-only collapses byte-identical bodies served
		// across different paths regardless of header noise.
		h := sha256.Sum256(resp.Body)
		key := hardDedupKey{
			hostname: rec.host,
			method:   rec.method,
			status:   resp.StatusCode,
			length:   rec.size,
			respHash: hex.EncodeToString(h[:]),
		}

		if existingIdx, exists := dedupMap[key]; exists {
			// Keep the shorter path
			existingPath := allRecords[existingIdx].path
			if len(rec.path) < len(existingPath) {
				// Evict existing, keep new
				localStats.DedupedCodes[statusCodeBucket(resp.StatusCode)]++
				allRecords[existingIdx] = collectedRecord{} // mark as tombstone
				dedupMap[key] = len(allRecords)
				allRecords = append(allRecords, rec)
			} else {
				// Keep existing, discard new
				localStats.DedupedCodes[statusCodeBucket(resp.StatusCode)]++
			}
		} else {
			dedupMap[key] = len(allRecords)
			allRecords = append(allRecords, rec)
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Drop exact-dedup tombstones and partition survivors by class in one pass:
	// only the fuzz/crawl class (crawlRecordSource) is subject to the flood-control
	// cap below — code-referenced records (JSTangle/form) must all survive.
	var fuzz, referenced []collectedRecord
	for _, rec := range allRecords {
		switch {
		case rec.rr == nil: // tombstone
			continue
		case rec.source == crawlRecordSource:
			fuzz = append(fuzz, rec)
		default:
			referenced = append(referenced, rec)
		}
	}
	localStats.HardDedupRemoved = localStats.TotalDiscovered - (len(fuzz) + len(referenced))

	// Near-identical cluster cap: backstop for catch-all/SPA targets that the
	// exact hash and the engine's soft-404 detection can't collapse because each
	// response differs by a few bytes/words. Keeps at most clusterCap records per
	// (host, status, content-type, ~size, ~words) cluster.
	clusterCap := d.cfg.resolveClusterCap()
	localStats.ClusterCap = clusterCap
	if clusterCap > 0 {
		var capped int
		var cappedCodes [5]int
		fuzz, capped, cappedCodes = capNearIdenticalClusters(fuzz, clusterCap)
		localStats.FuzzyCappedRemoved = capped
		localStats.CappedCodes = cappedCodes
	}

	// Regroup the survivors by source label. The fuzz class keeps the
	// crawlRecordSource ("deparos") label so the post-discovery dedup/status
	// passes apply to it; code-referenced classes carry their own label and are
	// left alone (see classifyDiscoverySource). `crawled` is the flat, all-source
	// list used for spec extraction and source-map artifact mapping.
	kept := make([]collectedRecord, 0, len(fuzz)+len(referenced))
	kept = append(kept, fuzz...)
	kept = append(kept, referenced...)
	sourceOrder, bySource, crawled := groupCollectedBySource(kept)

	// Parse API specs (OpenAPI/Swagger/Postman) found among the crawled responses
	// and queue their documented endpoints. They are persisted separately under
	// specRecordSource so the deparos dedup/status passes don't drop or collapse
	// them once each carries a real (often uniform 401) baseline response.
	specEndpoints := extractSpecEndpoints(crawled)
	if len(specEndpoints) > 0 {
		terminal.Notice("api-spec", fmt.Sprintf(
			"Ingested %d API spec endpoints from discovery of %s — extra requests "+
				"queued for dynamic assessment (longer scan, more results)",
			len(specEndpoints), target))
	}

	if len(referenced) > 0 {
		terminal.Notice("jstangle", fmt.Sprintf(
			"Preserved %d application-referenced (JS/form) requests from discovery of "+
				"%s under provenance-specific labels — exempt from the fuzz-noise "+
				"dedup/status cleanup so their real methods, bodies and 401/403/404 "+
				"baselines reach dynamic assessment intact",
			len(referenced), target))
	}

	localStats.Imported = len(crawled) + len(specEndpoints)
	if localStats.Imported > 0 {
		zap.L().Info("Deparos discovery results imported to DB",
			zap.String("target", target),
			zap.Int("discovered", localStats.TotalDiscovered),
			zap.Int("hard_dedup_removed", localStats.HardDedupRemoved),
			zap.Int("fuzzy_capped_removed", localStats.FuzzyCappedRemoved),
			zap.Int("cluster_cap", localStats.ClusterCap),
			zap.Int("referenced_preserved", len(referenced)),
			zap.Int("imported", localStats.Imported))
	}

	// Update stats on the source
	d.mu.Lock()
	d.stats.TotalDiscovered += localStats.TotalDiscovered
	d.stats.HardDedupRemoved += localStats.HardDedupRemoved
	d.stats.FuzzyCappedRemoved += localStats.FuzzyCappedRemoved
	d.stats.ClusterCap = localStats.ClusterCap
	d.stats.Imported += localStats.Imported
	for i := range d.stats.AllCodes {
		d.stats.AllCodes[i] += localStats.AllCodes[i]
		d.stats.DedupedCodes[i] += localStats.DedupedCodes[i]
		d.stats.CappedCodes[i] += localStats.CappedCodes[i]
	}
	d.mu.Unlock()

	// Persist + emit each provenance group under its own source label, then the
	// spec endpoints. Spec endpoints go out as request-only stubs (no response);
	// the executor fetches a baseline for each and backfills the stored record so
	// the route isn't left empty. recordUUIDByURL maps every saved record's target
	// URL to its persisted UUID across all groups, so source-map artifacts can be
	// mapped back regardless of which label carried the asset.
	recordUUIDByURL := make(map[string]string)
	for _, label := range sourceOrder {
		records := bySource[label]
		uuids, err := d.saveAndEmitWithUUIDs(ctx, records, label)
		if err != nil {
			return err
		}
		for i, rec := range records {
			if rec != nil && i < len(uuids) && uuids[i] != "" {
				recordUUIDByURL[rec.Target()] = uuids[i]
			}
		}
	}
	d.persistJSTangleSourceArtifacts(ctx, siteMap, recordUUIDByURL)
	if err := d.saveAndEmit(ctx, specEndpoints, specRecordSource); err != nil {
		return err
	}

	return nil
}

// saveAndEmit batch-saves a set of discovery records under the given source
// label, then emits each as a WorkItem tagged with its persisted record UUID
// (so downstream findings link back to the stored record). A DB save failure is
// logged and the records are still emitted (without UUIDs) so scanning proceeds.
func (d *DeparosDiscoverySource) saveAndEmit(ctx context.Context, records []*httpmsg.HttpRequestResponse, recordSource string) error {
	_, err := d.saveAndEmitWithUUIDs(ctx, records, recordSource)
	return err
}

func (d *DeparosDiscoverySource) saveAndEmitWithUUIDs(ctx context.Context, records []*httpmsg.HttpRequestResponse, recordSource string) ([]string, error) {
	if len(records) == 0 {
		return nil, nil
	}

	var uuids []string
	if d.cfg.Repository != nil {
		saved, err := d.cfg.Repository.SaveRecordBatch(ctx, records, recordSource, d.cfg.ProjectUUID)
		if err != nil {
			zap.L().Warn("Failed to batch save discovery results to DB",
				zap.String("source", recordSource), zap.Error(err))
			uuids = make([]string, len(records)) // emit without UUIDs
		} else {
			uuids = saved
		}
	} else {
		uuids = make([]string, len(records))
	}

	for i, rr := range records {
		item := work.NewWithModules(rr, d.cfg.EnableModules)
		if i < len(uuids) {
			item.RecordUUID = uuids[i]
		}

		select {
		case <-d.done:
			return uuids, fmt.Errorf("source closed")
		case d.items <- item:
		}
	}

	return uuids, nil
}

// maxSeededSpideredJS bounds how many browser-spidered JavaScript files are
// seeded into the discovery sitemap per host. Real apps ship well under this; the
// cap keeps the one-shot seed (each body is loaded into memory and, when small
// enough, jstangle-parsed) bounded on pathological targets.
const maxSeededSpideredJS = 300

// seedSpideredJS loads JavaScript already captured for this target's host by
// earlier phases (spidering, proxy/Burp ingestion) from the main DB and stores it
// into the ephemeral discovery sitemap BEFORE the engine starts. The engine's
// initSession then runs extractRoutesFromStoredJS over these bodies — the same
// JSTangle+linkfinder extraction it applies to JS it fetches itself — so SPA
// bundles the browser revealed (but the initial HTML/crawl never links) still
// have their fetch/XHR endpoints recovered and queued for replay. Without this the
// bridge is inert in the native pipeline: the sitemap is created empty and the
// browser's JS lives only in the main DB. Best-effort — any failure is logged and
// discovery proceeds; a no-op when the repository can't provide stored JS or when
// JSTangle is explicitly disabled.
func (d *DeparosDiscoverySource) seedSpideredJS(ctx context.Context, siteMap *deparosstorage.SiteMap, target string) {
	if siteMap == nil {
		return
	}
	if d.cfg.JSTangle != nil && !d.cfg.JSTangle.Enabled {
		return
	}
	provider, ok := d.cfg.Repository.(spideredJSProvider)
	if !ok {
		return
	}
	// Normalized (lowercased, port-stripped) hostname so the scope matches the DB's
	// normalized `hostname` column that WalkJavaScriptRecords filters on.
	host := httpmsg.HostnameFromURL(target)
	if host == "" {
		return
	}

	seeded := 0
	walkErr := provider.WalkJavaScriptRecords(ctx, d.cfg.ProjectUUID, host, maxSeededSpideredJS,
		func(recordURL, contentType string, body []byte) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			ju, perr := url.Parse(recordURL)
			if perr != nil || ju.Scheme == "" || ju.Host == "" {
				return nil // skip unparseable/relative rows
			}
			result := deparosstorage.NewResult(ju)
			result.Request.Method = "GET"
			result.Response.StatusCode = 200
			result.Response.Body = body
			result.Response.MIMEType = contentType
			result.Metadata.FoundBy = "spider"
			result.Metadata.Timestamp = time.Now()
			if serr := siteMap.Store(result); serr != nil {
				zap.L().Debug("Failed to seed spidered JS into discovery sitemap",
					zap.String("url", recordURL), zap.Error(serr))
				return nil
			}
			seeded++
			return nil
		})
	if walkErr != nil {
		zap.L().Debug("Failed to load spidered JS for discovery seeding",
			zap.String("target", target), zap.Error(walkErr))
	}
	if seeded > 0 {
		terminal.Notice("jstangle", fmt.Sprintf(
			"Seeded %d browser-spidered JavaScript file(s) for %s into JSTangle analysis — "+
				"endpoints in bundles the crawl never fetched will be recovered and replayed",
			seeded, target))
	}
}

func (d *DeparosDiscoverySource) persistJSTangleSourceArtifacts(
	ctx context.Context,
	siteMap *deparosstorage.SiteMap,
	recordUUIDByURL map[string]string,
) {
	saver, ok := d.cfg.Repository.(analysisArtifactSaver)
	if !ok || siteMap == nil {
		return
	}
	artifacts, err := siteMap.Extractions().GetJSTangleSourceArtifacts(siteMap.SessionDBID())
	if err != nil {
		zap.L().Debug("Failed to load recovered source-map artifacts", zap.Error(err))
		return
	}
	stored := 0
	for _, artifact := range artifacts {
		recordUUID := recordUUIDByURL[artifact.GeneratedURL]
		if recordUUID == "" || artifact.Content == "" {
			continue
		}
		metadata, marshalErr := json.Marshal(map[string]string{
			"generated_url": artifact.GeneratedURL,
			"virtual_url":   artifact.VirtualURL,
			"source_path":   artifact.SourcePath,
			"language":      artifact.Language,
		})
		if marshalErr != nil {
			continue
		}
		if saveErr := saver.SaveAnalysisArtifact(
			ctx, recordUUID, "source-map-original", artifact.SourcePath,
			"application/javascript", artifact.ContentSHA256, []byte(artifact.Content), string(metadata),
		); saveErr != nil {
			zap.L().Debug("Failed to promote source-map artifact", zap.String("source", artifact.SourcePath), zap.Error(saveErr))
			continue
		}
		stored++
	}
	if stored > 0 {
		zap.L().Info("Stored recovered source-map artifacts", zap.Int("count", stored))
	}
}

// extractSpecEndpoints scans discovered records for API specs (OpenAPI/Swagger/Postman)
// and returns parsed endpoints as additional HttpRequestResponse items.
func extractSpecEndpoints(records []*httpmsg.HttpRequestResponse) []*httpmsg.HttpRequestResponse {
	specSeen := make(map[string]struct{})
	var allEndpoints []*httpmsg.HttpRequestResponse

	for _, rr := range records {
		if rr.Response() == nil {
			continue
		}
		sc := rr.Response().StatusCode()
		if sc < 200 || sc >= 300 {
			continue
		}

		body := rr.Response().Body()
		if len(body) < specutil.MinSpecBodySize || len(body) > specutil.MaxSpecBodySize {
			continue
		}

		// Content-type pre-filter
		ct, _ := httpmsg.FindHttpHeader(rr.Response().Headers(), "Content-Type")
		if ct != "" && !specutil.IsSpecContentType(ct) {
			continue
		}

		// Detect spec type
		st := specutil.DetectSpecType(body)
		if st == specutil.Unknown {
			continue
		}

		// Content dedup
		h := sha256.Sum256(body)
		hash := hex.EncodeToString(h[:])
		if _, seen := specSeen[hash]; seen {
			continue
		}
		specSeen[hash] = struct{}{}

		// Derive base URL from the record's service
		baseURL := ""
		if rr.Service() != nil {
			baseURL = rr.Service().Protocol() + "://" + rr.Service().Host()
		}

		endpoints, err := specutil.ParseSpecTyped(st, body, baseURL, rr.Service())
		if err != nil {
			zap.L().Debug("Failed to parse API spec from discovery result",
				zap.String("url", rr.Target()),
				zap.Error(err))
			continue
		}
		terminal.Notice("api-spec", fmt.Sprintf(
			"Discovered OpenAPI/Swagger spec %s — parsed %d endpoints for ingestion",
			rr.Target(), len(endpoints)))
		allEndpoints = append(allEndpoints, endpoints...)
	}

	return allEndpoints
}

// Close releases resources and stops discovery.
func (d *DeparosDiscoverySource) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}
	d.closed = true

	if d.started {
		close(d.done)
		if d.cancel != nil {
			d.cancel()
		}
		// Drain channel to unblock goroutine
		go func() {
			for range d.items {
			}
		}()
	}

	return nil
}
