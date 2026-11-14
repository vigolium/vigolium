package source

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	nethttp "net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/internal/resources/wordlists"
	deparosconfig "github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/sourcemap"
	deparosstorage "github.com/vigolium/vigolium/pkg/deparos/storage"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit/specutil"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
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
	Targets     []string      // Target URLs
	Concurrency int           // Worker threads (from -t flag), split across concurrent targets; default: 25
	MaxDuration time.Duration // default: 1h

	// BruteForceConcurrency is each target's worker count for wordlist and
	// FUZZ-template requests (deparos EngineConfig.BruteForceThreads). It is
	// per target, not split: concurrent targets are different hosts, each with
	// its own host slots. 0 = the target's Concurrency share.
	BruteForceConcurrency int
	// Protocol is the engines' wire protocol policy (deparos
	// EngineConfig.Protocol): auto, http1, http2, http3; "" = http1.
	Protocol string

	// RateLimit caps each discovery engine's outgoing requests per second.
	// 0 = unpaced (the historical behaviour; Concurrency is then the only
	// throttle). Set it only from an EXPLICIT operator setting — see
	// buildDeparosConfig in the runner — because imposing the global 100 rps
	// default on a crawl changes the speed of every existing scan.
	//
	// On its own the bucket is per engine, i.e. per target, so with several
	// targets in flight the phase as a whole can send up to that many times
	// RateLimit. The runner avoids that by passing Egress, which carries ONE
	// bucket at this rate for every target; RateLimit then only describes it.
	RateLimit int

	// Egress, when set, admits every physical attempt of every per-target engine
	// (deparos EngineConfig.Egress): the scan's host slots and quarantine, plus
	// the discovery token bucket. Because the same wrapper serves all targets,
	// its bucket is phase-wide. When set, the engines' own per-target bucket
	// (RateLimit) is not installed — the gate is expected to carry the rate.
	Egress func(nethttp.RoundTripper) nethttp.RoundTripper

	// TargetConcurrency is how many targets are discovered at once. 0 = default
	// (min(len(Targets), 3)); 1 = one at a time. Targets sharing a host:port are
	// never discovered concurrently, and Concurrency is split across the
	// targets in flight (max(5, Concurrency/active)) so the phase's total
	// request concurrency stays about where it was.
	TargetConcurrency int

	// FlushInterval is how often a running target's records (the referenced
	// class, plus the fuzz class unless FuzzAtEnd) are persisted and emitted.
	// 0 = default (15s); negative = only at the end of the target. A flush
	// also runs once defaultDiscoveryFlushNodes nodes landed since the last one.
	FlushInterval time.Duration

	// FuzzAtEnd keeps the fuzz class (wordlist, spider and observed records)
	// in memory until the target finishes, as before fuzz streaming: exact dedup
	// keeps the shorter of two identical paths and the cluster cap ranks
	// shortest-path-first (discovery.stream_fuzz: false). The default streams it
	// with the referenced class: exact dedup keeps the first record and the
	// cluster cap counts per cluster across flushes, first N wins.
	FuzzAtEnd bool

	EnableModules []string // Module selection for WorkItems

	// DrainTimeout bounds how long Close waits for the producer to finish
	// persisting what it already collected. <=0 uses defaultDiscoveryDrainTimeout.
	DrainTimeout time.Duration

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
	FuzzWordlistPaths    []string // streamed in order, deduplicated across files
	UseObservedNames     bool
	UseObservedPaths     bool
	UseObservedFiles     bool
	EnableNumericFuzzing bool
	// ExtractWords turns on response-body word harvesting into the observed
	// wordlist (deparos Filenames.WordlistExtraction).
	ExtractWords bool

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
	// JSTemplatePersist controls persistence of JS-derived request templates
	// that did not become discovery nodes (see deparos_discovery_jstangle.go).
	JSTemplatePersist JSTemplatePersistConfig
	// Sitemap overrides the deparos sitemap source settings; nil keeps the
	// deparos defaults (on, 2000 sampled URLs, 3 per shape, follow indexes).
	Sitemap *deparosconfig.SitemapConfig

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

	// RequestFilter is the egress policy for every request the discovery engine
	// makes: returning false refuses the request before it is sent, instead of
	// discarding its response afterwards. The engine also derives its spider-queue
	// exclusion from it, so a refused URL is never even queued.
	//
	// It carries the operator's EXPLICIT denials only (scope.host.exclude /
	// scope.path.exclude); how wide the crawl goes is still ScopeMode's job.
	// nil = no denials.
	RequestFilter func(*url.URL) bool

	// MethodFilter refuses requests whose method the traffic policy does not
	// allow (SAFE-8). nil = every method.
	MethodFilter func(method string) bool

	// FormSafety overrides the replay-safety policy for HTML form submission
	// (SAFE-7); empty = the JS replay policy.
	FormSafety string

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
// order and the per-label record slices.
func groupCollectedBySource(records []collectedRecord) (order []string, bySource map[string][]*httpmsg.HttpRequestResponse) {
	bySource = make(map[string][]*httpmsg.HttpRequestResponse, 3)
	order = make([]string, 0, 3)
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
	}
	return order, bySource
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

	// Coverage accounting. Discovery used to log per-target failures and move on,
	// so a run where every target errored was indistinguishable from a run that
	// found nothing. These make the difference reportable.

	// TargetsFailed is the number of targets whose discovery returned an error.
	TargetsFailed int
	// TargetsTimedOut counts targets that exhausted their own MaxDuration. This
	// is designed behavior (per-target time-boxing), not a failure.
	TargetsTimedOut int
	// TargetsSkipped is the number of targets never attempted because the phase
	// was cancelled first.
	TargetsSkipped int
	// ImportFailed counts records that were collected but could not be persisted.
	ImportFailed int
	// TargetErrors holds up to maxReportedTargetErrors "<target>: <err>" strings.
	TargetErrors []string
	// Abandoned is set when Close gave up waiting for the producer to exit.
	Abandoned bool

	// JS-derived request templates (jstangle) that did not become discovery
	// nodes and were persisted as http_records stubs instead.

	// JSFactsPersisted counts template stubs written (emitted + persist-only).
	JSFactsPersisted int
	// JSFactsNotFound counts persisted stubs whose replay was judged not found.
	JSFactsNotFound int
	// JSFactsWithheld counts templates never sent, by withheld_* outcome.
	JSFactsWithheld map[string]int
	// JSTemplatesCapped counts stubs dropped by max_persisted_js_templates; any
	// value above zero is the js_template_persist_cap limit.
	JSTemplatesCapped int
	// JSFactBundles counts jstangle-facts artifacts stored (one per JS asset).
	JSFactBundles int

	// SitemapCapped counts sitemap locs or documents dropped by a sitemap budget
	// (discovery.sitemap.max_urls and the fixed size/index caps); any value
	// above zero is the sitemap_cap limit.
	SitemapCapped int
}

// maxReportedTargetErrors bounds TargetErrors so a sweep of thousands of hosts
// cannot turn a stats struct into a log dump. The count stays exact.
const maxReportedTargetErrors = 10

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
// responses: the first record's body size and word count, and how many records
// the cluster kept so far.
type respCluster struct {
	repSize int64
	repWord int64
	count   int
}

// clusterKey is the exact part of a near-identical cluster's identity; size and
// words are matched within dedupClusterTolerance inside one key.
type clusterKey struct {
	host   string
	method string
	status int
	ctype  string
}

// clusterCapper is the near-identical cluster cap applied one record at a time,
// so a target streamed across flushes keeps its per-cluster counts between them.
// The first capN records of a cluster in arrival order win; nothing it admitted
// is ever revoked, which is what lets an admitted record be persisted at once.
type clusterCapper struct {
	capN        int
	clusters    map[clusterKey][]*respCluster
	capped      int
	cappedCodes [5]int
}

func newClusterCapper(capN int) *clusterCapper {
	return &clusterCapper{capN: capN, clusters: make(map[clusterKey][]*respCluster)}
}

// admit reports whether rec is kept. Two records share a cluster when they have
// the same host, method, status and content-type, and their body size and word
// count are each within dedupClusterTolerance (0.5%) of the cluster's first
// record. Records without a response (status 0) bypass clustering and are
// always kept. A capN <= 0 keeps everything.
func (c *clusterCapper) admit(rec collectedRecord) bool {
	if c.capN <= 0 || rec.status == 0 {
		return true
	}
	key := clusterKey{host: rec.host, method: rec.method, status: rec.status, ctype: rec.ctype}
	for _, cl := range c.clusters[key] {
		if !withinDedupTolerance(cl.repSize, rec.size) || !withinDedupTolerance(cl.repWord, rec.words) {
			continue
		}
		if cl.count < c.capN {
			cl.count++
			return true
		}
		c.capped++
		c.cappedCodes[statusCodeBucket(rec.status)]++
		return false
	}
	c.clusters[key] = append(c.clusters[key], &respCluster{repSize: rec.size, repWord: rec.words, count: 1})
	return true
}

// capNearIdenticalClusters keeps at most capN records per near-identical
// cluster (see clusterCapper.admit). It is order-stable: the first capN records
// of each cluster in input order win, and the kept records keep their input
// order, so capping a target in one batch keeps exactly what capping it one
// streamed record at a time keeps. A caller wanting the shallowest paths as
// representatives sorts first (sortShortestPathFirst).
//
// Returns the kept records, the number of records capped (dropped), and
// per-status-bucket counts of the capped records.
func capNearIdenticalClusters(records []collectedRecord, capN int) ([]collectedRecord, int, [5]int) {
	if capN <= 0 {
		return records, 0, [5]int{}
	}
	capper := newClusterCapper(capN)
	kept := make([]collectedRecord, 0, len(records))
	for _, rec := range records {
		if capper.admit(rec) {
			kept = append(kept, rec)
		}
	}
	return kept, capper.capped, capper.cappedCodes
}

// sortShortestPathFirst orders records shortest path first (then by path), the
// order the end-of-target cluster cap ranks in so the kept representatives are
// the shallowest (most likely real) paths.
func sortShortestPathFirst(records []collectedRecord) {
	sort.SliceStable(records, func(i, j int) bool {
		if len(records[i].path) != len(records[j].path) {
			return len(records[i].path) < len(records[j].path)
		}
		return records[i].path < records[j].path
	})
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

	// baseCtx is the caller's lifetime. runDiscovery derives its working context
	// from it, so cancelling the phase stops the engine immediately instead of
	// letting the running target burn its full MaxDuration.
	baseCtx context.Context

	// finished closes when runDiscovery returns, so Close can join the producer
	// instead of abandoning it to a detached drain goroutine.
	finished chan struct{}

	// abort is the second, harder stop. done means "stop emitting"; abort means
	// "stop everything, including reading the local sitemap we already paid for".
	// Keeping them separate is what lets a cancelled phase still persist the
	// records it collected.
	abort     chan struct{}
	abortOnce sync.Once

	mu             sync.Mutex
	items          chan *work.WorkItem
	done           chan struct{}
	cancel         context.CancelFunc
	started        bool
	closed         bool
	runErr         error
	runErrReported bool
	stats          DiscoveryStats

	// discoverFn overrides discoverTarget in tests. nil means the real thing.
	discoverFn func(ctx context.Context, target string) error

	// abortGrace is how long Close waits after escalating to abort, and again
	// before declaring the producer abandoned. Set in the constructor; a field
	// rather than a constant only so the abandonment path is testable without a
	// ten-second test.
	abortGrace time.Duration

	// requestsSent counts every physical HTTP attempt the discovery engines make.
	// Handed to each per-target engine as its RequestCounter, so it accumulates
	// across the whole target list and is readable while a crawl is running —
	// which is what the phase's progress heartbeat needs. Outside the mutex on
	// purpose: it is written from engine worker goroutines on the request hot path.
	requestsSent atomic.Int64
}

// RequestsSent reports how many HTTP attempts the discovery engines have made so
// far, retries included. Safe to call at any point in the source's life, from any
// goroutine.
//
// It exists because deparos owns its own HTTP client: the runner's phase tracker
// reads a delta on the SHARED requester, which a discovery phase barely touches,
// so phase.started/progress/finished reported ≈0 requests for a crawl that had
// sent tens of thousands.
func (d *DeparosDiscoverySource) RequestsSent() int64 {
	if d == nil {
		return 0
	}
	return d.requestsSent.Load()
}

// Stats returns the discovery statistics (safe to call after the source is exhausted).
func (d *DeparosDiscoverySource) Stats() DiscoveryStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.stats
	out.TargetErrors = slices.Clone(d.stats.TargetErrors)
	if d.stats.JSFactsWithheld != nil {
		out.JSFactsWithheld = make(map[string]int, len(d.stats.JSFactsWithheld))
		for reason, n := range d.stats.JSFactsWithheld {
			out.JSFactsWithheld[reason] = n
		}
	}
	return out
}

// DefaultDiscoveryMaxDuration is the per-target wall-clock budget a discovery
// target gets when nothing configures one. Exported because the runner's banner
// and buildDeparosConfig have to report the same number this source will use;
// when the literal lived only here, the banner printed 0 while targets ran for an
// hour.
const DefaultDiscoveryMaxDuration = 1 * time.Hour

// defaultDiscoveryDrainTimeout bounds how long Close waits for the producer to
// persist what it already collected before the phase gives up on it. Not exposed
// as configuration: there is no measurement yet that would tell an operator what
// to set it to.
const defaultDiscoveryDrainTimeout = 30 * time.Second

// defaultDiscoveryAbortGrace is how long Close waits after escalating from done
// ("stop emitting") to abort ("stop reading the sitemap too"), and again before
// it declares the producer abandoned.
const defaultDiscoveryAbortGrace = 5 * time.Second

// NewDeparosDiscoverySource creates a new DeparosDiscoverySource owned by ctx.
// Cancelling ctx stops the running engine and skips the remaining targets; a nil
// ctx means the source outlives every caller, which is only ever right in a test.
func NewDeparosDiscoverySource(ctx context.Context, cfg DeparosDiscoveryConfig) (*DeparosDiscoverySource, error) {
	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = types.DefaultConcurrency
	}
	if cfg.MaxDuration <= 0 {
		cfg.MaxDuration = DefaultDiscoveryMaxDuration
	}
	if cfg.DrainTimeout <= 0 {
		cfg.DrainTimeout = defaultDiscoveryDrainTimeout
	}

	return &DeparosDiscoverySource{
		cfg:        cfg,
		baseCtx:    ctx,
		items:      make(chan *work.WorkItem, 100),
		done:       make(chan struct{}),
		finished:   make(chan struct{}),
		abort:      make(chan struct{}),
		abortGrace: defaultDiscoveryAbortGrace,
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
		// The working context is derived and published HERE, under the same lock
		// that sets started: if runDiscovery assigned d.cancel itself, a Close
		// arriving first would read nil and leave the engine running on an
		// uncancelled context, which is exactly the hang this is meant to end.
		workCtx, cancel := context.WithCancel(d.baseCtx)
		d.cancel = cancel
		go d.runDiscovery(workCtx, cancel)
	}
	d.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case item, ok := <-d.items:
		if !ok {
			d.mu.Lock()
			err := d.runErr
			if err != nil && !d.runErrReported {
				d.runErrReported = true
			} else {
				err = nil
			}
			d.mu.Unlock()
			// Report the run error exactly once, then EOF forever after. Both
			// consumers (Executor.feedItems and ConcurrentMultiSource.readSource)
			// treat a non-EOF error as "retry", so a sticky error here is an
			// infinite loop rather than a failure report.
			if err != nil {
				return nil, err
			}
			return nil, io.EOF
		}
		return item, nil
	}
}

// noteSkipped records targets the phase never attempted.
func (d *DeparosDiscoverySource) noteSkipped(n int) {
	if n <= 0 {
		return
	}
	d.mu.Lock()
	d.stats.TargetsSkipped += n
	d.mu.Unlock()
}

// noteTargetError counts a per-target failure and keeps the first few messages.
func (d *DeparosDiscoverySource) noteTargetError(target string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stats.TargetsFailed++
	if len(d.stats.TargetErrors) < maxReportedTargetErrors {
		d.stats.TargetErrors = append(d.stats.TargetErrors, fmt.Sprintf("%s: %v", target, err))
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
		// Evaluated for the target's ORIGIN, not blindly flattened: the engine
		// takes one static header for the whole crawl, so there is no request
		// path to match — but the scheme is known, and a Secure cookie must not
		// be handed to an http crawl of the same host. Path is therefore ignored
		// and the broadest copy of a duplicated name wins
		// (CookieHeaderForOrigin). A harvest with no recorded attributes falls
		// back to the flat header, as before.
		scheme, host := targetSchemeHost(target)
		if cookieHeader := sess.CookieHeaderForOrigin(scheme, host, time.Now()); cookieHeader != "" && !hasHeaderCI(headers, "Cookie") {
			headers["Cookie"] = cookieHeader
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

// targetSchemeHost splits a discovery target URL into its scheme and
// port-stripped host for cookie evaluation. An unparseable target yields empty
// strings, which match no cookie — the same outcome as an unknown host.
func targetSchemeHost(target string) (scheme, host string) {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil || u.Host == "" {
		return "", ""
	}
	return u.Scheme, u.Hostname()
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
	cfg.Engine.BruteForceThreads = d.cfg.BruteForceConcurrency
	cfg.Engine.Protocol = d.cfg.Protocol
	// Passed straight through, including 0: the engine reads 0 as "unpaced", and
	// turning it into a default here would throttle every scan that never asked.
	cfg.Engine.RequestsPerSecond = d.cfg.RateLimit
	if d.cfg.Egress != nil {
		// One gate for every target: its bucket is the phase-wide rate, so a
		// per-engine bucket on top would only re-pace each target at the same
		// number (see DeparosDiscoveryConfig.Egress).
		cfg.Engine.Egress = d.cfg.Egress
		cfg.Engine.RequestsPerSecond = 0
	}

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
	if len(d.cfg.FuzzWordlistPaths) > 0 {
		cfg.Filenames.Wordlists.FuzzWordlistPaths = append([]string(nil), d.cfg.FuzzWordlistPaths...)
	}
	cfg.Filenames.UseObservedNames = d.cfg.UseObservedNames
	cfg.Filenames.UseObservedPaths = d.cfg.UseObservedPaths
	cfg.Filenames.UseObservedFiles = d.cfg.UseObservedFiles
	cfg.Filenames.EnableNumericFuzzing = d.cfg.EnableNumericFuzzing
	cfg.Filenames.WordlistExtraction.Enabled = d.cfg.ExtractWords

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
	// Egress policy and the attempt counter. The counter is the SOURCE's, shared by
	// every per-target engine, so RequestsSent reports the phase's whole crawl
	// rather than whichever target happens to be running.
	cfg.Engine.RequestFilter = d.cfg.RequestFilter
	cfg.Engine.MethodFilter = d.cfg.MethodFilter
	cfg.Engine.FormSafety = d.cfg.FormSafety
	cfg.Engine.RequestCounter = &d.requestsSent
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
	if d.cfg.Sitemap != nil {
		cfg.Sitemap = *d.cfg.Sitemap
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
//
// The engine crawls into a per-target ephemeral siteMap. While it runs, a
// flusher streams the records out of the siteMap every flush interval: the
// referenced class (JSTangle/form/API-spec records) and, unless
// discovery.stream_fuzz is off, the deduped and cluster-capped fuzz class. The
// rest, the JS template plan and the artifacts are imported once the engine
// stops (see deparos_discovery_stream.go).
// The engine's thread count is the share runDiscovery gave this target.
func (d *DeparosDiscoverySource) discoverTarget(parentCtx context.Context, target string) error {
	threads := targetThreads(parentCtx, d.cfg.Concurrency)
	zap.L().Info("Starting deparos discovery",
		zap.String("target", target),
		zap.Int("threads", threads),
		zap.Duration("max_time", d.cfg.MaxDuration))

	// Build deparos config from all settings
	cfg := d.buildDeparosConfig(target)
	cfg.Engine.DiscoveryThreads = threads

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

	collector := newTargetCollector(d, target, siteMap)
	stopFlusher := collector.startFlusher(ctx)

	_ = engine.WaitForQueues(ctx)
	engine.FlushSecretFindings()
	engine.Stop()
	stopFlusher()

	return collector.finish(ctx, engine, targetExhaustedBudget(ctx, parentCtx))
}

// collectedGroups is one target's surviving records, partitioned the way they
// will be persisted: grouped by source label in a stable order, plus the API-spec
// endpoints extracted from them.
type collectedGroups struct {
	sourceOrder   []string
	bySource      map[string][]*httpmsg.HttpRequestResponse
	specEndpoints []*httpmsg.HttpRequestResponse
	// jsTemplates is the JS template persistence for the target (nil = none).
	jsTemplates *jsTemplatePlan
	// acc carries what earlier flushes of the same target already imported, so
	// uuidByURL and the emit latch span the whole target. Required.
	acc *importAccum
}

// importCollected is discovery's last stage: write everything one target
// collected, on a budget that survives an expired phase.
//
// The records handed in were paid for with real requests — they were sent, the
// responses came back, and all that is left is a local write. So the write runs
// under importContext rather than under ctx: when the phase was cancelled or the
// target burned its MaxDuration, ctx is already dead and every save on it failed,
// after which the executor re-saved the same requests under the "scanner" label
// and the post-discovery cleanup (scoped to source='deparos') skipped them along
// with the JSTangle artifacts keyed to them. See importContext.
//
// Only a hard abort stops persisting. The consumer going away (d.done) merely
// turns emission off inside importGroup, because the records still belong in the
// database whether or not anything is left to scan them.
//
// Separated from discoverTarget so this decision can be driven with an expired
// context directly, rather than through a race between a real crawl's progress
// and its own deadline.
func (d *DeparosDiscoverySource) importCollected(
	ctx context.Context,
	siteMap *deparosstorage.SiteMap,
	groups collectedGroups,
) error {
	importCtx, releaseImport := importContext(ctx, d.cfg.DrainTimeout)
	defer releaseImport()

	// Persist + emit each provenance group under its own source label, then the
	// spec endpoints. Spec endpoints go out as request-only stubs (no response);
	// the executor fetches a baseline for each and backfills the stored record so
	// the route isn't left empty. acc.uuidByURL maps every saved record's target
	// URL to its persisted UUID across all groups, so source-map artifacts can be
	// mapped back regardless of which label carried the asset.
	acc := groups.acc
	for _, label := range groups.sourceOrder {
		if err := d.importGroup(importCtx, acc, groups.bySource[label], label); err != nil {
			return err
		}
		select {
		case <-d.abort:
			acc.aborted = true
		default:
		}
		if acc.aborted {
			return nil
		}
	}
	// siteMap is optional: a caller with no crawl storage (and nothing to map
	// source-map artifacts against) still persists its groups.
	if siteMap != nil {
		d.persistJSTangleSourceArtifacts(importCtx, siteMap, acc.uuidByURL)
	}
	// After the crawl groups, so the nodes and JS assets the templates annotate
	// and anchor to already have UUIDs.
	if err := d.importJSTemplates(importCtx, acc, groups.jsTemplates); err != nil {
		return err
	}
	return d.importGroup(importCtx, acc, groups.specEndpoints, specRecordSource)
}

// importAccum accumulates the result of persisting one target's record groups.
//
// emit starts true and latches false the moment the consumer stops reading: the
// remaining groups are still persisted (the requests are already paid for), they
// just never become work items. aborted means the source was told to stop
// entirely, which is the only thing that ends the loop early.
type importAccum struct {
	uuidByURL map[string]string
	imported  int
	failed    int
	emit      bool
	aborted   bool
	// factBundles counts jstangle-facts artifacts stored.
	factBundles int
}

func newImportAccum(sizeHint int) *importAccum {
	return &importAccum{uuidByURL: make(map[string]string, sizeHint), emit: true}
}

// importGroup persists one source-labelled group of records, emitting them as
// work items while the consumer is still reading, and counts the outcome.
//
// Imported counts records that actually landed (a non-empty UUID), not records
// handed to the saver: SaveRecordBatch returns "" for a record it could not
// convert or store, so counting the input over-reported every failure as a
// success. With no repository configured there is nothing to persist to, so a
// record that reached the scan counts as imported.
func (d *DeparosDiscoverySource) importGroup(
	ctx context.Context,
	acc *importAccum,
	records []*httpmsg.HttpRequestResponse,
	label string,
) error {
	_, err := d.importRecords(ctx, acc, records, label, true)
	return err
}

// targetExhaustedBudget distinguishes the two ways a target's context can end. A
// deadline on the target's OWN child context means it used up its MaxDuration,
// which is designed behavior (per-target time-boxing) and reported as timed out. A
// cancelled parent means the phase stopped us, which runDiscovery counts as
// skipped instead — conflating the two would report an operator's Ctrl-C as a
// target that ran long.
func targetExhaustedBudget(targetCtx, parentCtx context.Context) bool {
	return errors.Is(targetCtx.Err(), context.DeadlineExceeded) && parentCtx.Err() == nil
}

// errEmitStopped reports that the consumer stopped reading mid-emission. It is
// not a save failure: the records were persisted, they just never became work
// items. The caller downgrades to persist-only rather than abandoning the rest.
var errEmitStopped = errors.New("discovery consumer stopped reading")

// importContext returns the context to persist a target's collected records
// under.
//
// A live parent is used as-is. A cancelled parent — the phase was stopped, or the
// target burned its own MaxDuration — yields a detached context with its own
// drain budget, because the records are already in hand: the requests were sent,
// the responses were received, and the only thing left is a local write. Running
// that write on the expired context made every save fail, after which the
// executor re-saved the items under the "scanner" label; the cleanup passes then
// skipped them (they filter on source='deparos') and the JSTangle artifacts
// keyed to them were lost.
func importContext(parent context.Context, drain time.Duration) (context.Context, context.CancelFunc) {
	if parent.Err() == nil {
		return parent, func() {}
	}
	if drain <= 0 {
		drain = defaultDiscoveryDrainTimeout
	}
	return context.WithTimeout(context.WithoutCancel(parent), drain)
}

// persistOnly batch-saves records under the given source label and returns their
// persisted UUIDs (an empty string where the save failed). It never emits, so it
// is safe to call after the consumer has stopped reading.
func (d *DeparosDiscoverySource) persistOnly(ctx context.Context, records []*httpmsg.HttpRequestResponse, recordSource string) []string {
	if len(records) == 0 {
		return nil
	}
	if d.cfg.Repository == nil {
		return make([]string, len(records))
	}
	saved, err := d.cfg.Repository.SaveRecordBatch(ctx, records, recordSource, d.cfg.ProjectUUID)
	if err != nil {
		zap.L().Warn("Failed to batch save discovery results to DB",
			zap.String("source", recordSource), zap.Error(err))
		return make([]string, len(records)) // emit without UUIDs
	}
	return saved
}

// saveAndEmitWithUUIDs batch-saves a set of discovery records under the given
// source label, then emits each as a WorkItem tagged with its persisted record
// UUID (so downstream findings link back to the stored record), returning the
// UUIDs. A DB save failure is logged and the records are still emitted (without
// UUIDs) so scanning proceeds.
func (d *DeparosDiscoverySource) saveAndEmitWithUUIDs(ctx context.Context, records []*httpmsg.HttpRequestResponse, recordSource string) ([]string, error) {
	if len(records) == 0 {
		return nil, nil
	}

	uuids := d.persistOnly(ctx, records, recordSource)

	for i, rr := range records {
		item := work.NewWithModules(rr, d.cfg.EnableModules)
		if i < len(uuids) {
			item.RecordUUID = uuids[i]
		}

		select {
		case <-d.done:
			// The records are saved; only the hand-off stopped. Say which it was
			// so the caller can keep persisting the remaining groups.
			return uuids, errEmitStopped
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
		terminal.NoticeArrow("jstangle", fmt.Sprintf(
			"Recovering endpoints from %d browser-spidered JS bundle(s) the crawl never fetched — %s",
			seeded, terminal.Gray(target)))
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
	var originAnchors map[string]string
	stored, orphaned := 0, 0
	for _, artifact := range artifacts {
		if artifact.Content == "" {
			continue
		}
		recordUUID := recordUUIDByURL[artifact.GeneratedURL]
		if recordUUID == "" {
			// The generated asset has no record of its own. Stylesheets are the
			// standing case: .css is excluded from body storage, so a recovered
			// .scss/.less source had nowhere to attach and was silently dropped even
			// though the crawl had already parsed it. Anchor it to the origin's own
			// record instead — the artifact metadata still names the exact generated
			// URL, so provenance is unchanged; only the storage anchor is coarser.
			if originAnchors == nil {
				originAnchors = originAnchorRecords(recordUUIDByURL)
			}
			recordUUID = originAnchors[originOf(artifact.GeneratedURL)]
		}
		if recordUUID == "" {
			orphaned++
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
			ctx, recordUUID, sourcemap.ArtifactKindOriginal, artifact.SourcePath,
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
	if orphaned > 0 {
		zap.L().Debug("Recovered source-map artifacts had no record to anchor to",
			zap.Int("count", orphaned))
	}
}

// originOf returns scheme://host for a URL, or "" when it has neither.
func originOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// originAnchorRecords picks one record per origin to anchor artifacts whose own
// asset was not recorded. The shortest URL wins, which is the origin's root or
// closest thing to it — stable regardless of crawl order.
func originAnchorRecords(recordUUIDByURL map[string]string) map[string]string {
	type anchor struct {
		uuid   string
		urlLen int
	}
	best := make(map[string]anchor, 4)
	for recordURL, uuid := range recordUUIDByURL {
		origin := originOf(recordURL)
		if origin == "" || uuid == "" {
			continue
		}
		if current, seen := best[origin]; seen && current.urlLen <= len(recordURL) {
			continue
		}
		best[origin] = anchor{uuid: uuid, urlLen: len(recordURL)}
	}
	anchors := make(map[string]string, len(best))
	for origin, a := range best {
		anchors[origin] = a.uuid
	}
	return anchors
}

// extractSpecEndpointsSeen scans discovered records for API specs
// (OpenAPI/Swagger/Postman/WSDL) and returns parsed endpoints as additional
// HttpRequestResponse items. specSeen is a caller-owned set of spec body hashes
// already parsed, so a target read in batches parses each spec document once.
func extractSpecEndpointsSeen(records []*httpmsg.HttpRequestResponse, specSeen map[string]struct{}) []*httpmsg.HttpRequestResponse {
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
			"Discovered %s %s — parsed %d endpoints for ingestion",
			st.Label(), rr.Target(), len(endpoints)))
		allEndpoints = append(allEndpoints, endpoints...)
	}

	return allEndpoints
}

// Close stops discovery and joins the producer.
//
// The producer is given DrainTimeout to finish persisting what it already
// collected — those records cost real requests, and throwing them away on a
// cancel was the point of this change. If it has not exited by then, abort tells
// it to stop reading the local sitemap too, and after a further grace period the
// source reports the goroutine as abandoned rather than blocking the phase
// forever.
//
// Idempotent, and never waits while holding d.mu: the producer takes that lock to
// record stats, so waiting under it would deadlock the thing we are waiting for.
func (d *DeparosDiscoverySource) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	started := d.started
	if started {
		close(d.done)
		if d.cancel != nil {
			d.cancel()
		}
	}
	d.mu.Unlock()

	if !started {
		return nil
	}

	abortGrace := d.abortGrace
	if abortGrace <= 0 {
		abortGrace = defaultDiscoveryAbortGrace
	}
	if d.waitFinished(d.cfg.DrainTimeout + abortGrace) {
		return nil
	}

	d.abortOnce.Do(func() { close(d.abort) })
	if d.waitFinished(abortGrace) {
		return nil
	}

	d.mu.Lock()
	d.stats.Abandoned = true
	d.mu.Unlock()
	zap.L().Warn("deparos discovery producer did not exit; abandoning it",
		zap.Duration("waited", d.cfg.DrainTimeout+2*abortGrace))
	return nil
}

// waitFinished reports whether the producer exited within d.
func (d *DeparosDiscoverySource) waitFinished(timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-d.finished:
		return true
	case <-timer.C:
		return false
	}
}
