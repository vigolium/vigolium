package core

import (
	nethttp "net/http"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
)

// HookRunner transforms requests before scanning and filters results after scanning.
type HookRunner interface {
	RunPreHooks(req *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error)
	RunPostHooks(result *output.ResultEvent) (*output.ResultEvent, error)
}

// OASTFlusher is implemented by the OAST service to allow the executor to flush
// pending interactions after scanning completes.
type OASTFlusher interface {
	Flush()
	Close()
}

// ExecutorConfig configures the Executor behavior.
type ExecutorConfig struct {
	Workers       int
	OnResult      func(*output.ResultEvent)
	OnCandidate   func(*output.ResultEvent)
	OnObservation func(*output.ResultEvent)
	OnTraffic     func(method, url string, statusCode int, contentType string) // Optional: called for each processed item
	// OnAuthWall is called once per item whose redirect chain the transport
	// refused to follow into a login / SSO wall (http.StoppedAtAuthWall). It
	// carries the target that bounced and the wall it bounced to.
	//
	// The executor only reports; the phase decides what to do. That split is
	// deliberate: the wall host is a scan-wide fact (it feeds the fuzz-target
	// exclusion the spidering phase already maintains) and the executor has no
	// business owning scan-wide state, while re-deriving it later from stored
	// records would mean re-parsing every 3xx in the corpus.
	OnAuthWall func(target, wall string)
	// KeepBlocked stores a response the block detector classified as a WAF or
	// bot-wall page instead of dropping the item, with the remark
	// "blocked:<reason>" on the record. Off for scans, where a block page is not
	// the application's answer; an ingest asks for it with --keep-blocked.
	KeepBlocked bool
	// NoRedirects stops the baseline fetch at the first response: a 3xx is
	// stored as the answer. The fingerprint phase sets it — a 301 from
	// /robots.txt to /login is itself the signal.
	NoRedirects bool
	// FetchStaticFiles keeps the pre-fetch scope check to its host and path
	// rules, without the static-file carve-out: the fingerprint phase asks for
	// a favicon on purpose.
	FetchStaticFiles bool
	// OnResponse is called with each item and the request/response pair its
	// baseline fetch produced, before any module runs. The response buffer is
	// pooled and reclaimed when the item completes, so a callback that keeps
	// anything must copy it.
	OnResponse func(item *work.WorkItem, rr *httpmsg.HttpRequestResponse)
	// OnUnanswered is called once per input item that ends without a baseline
	// response, with the reason it got none: DropFetchError, DropBlocked,
	// DropBudget or DropQuarantined from the fetch, or DropOutOfScope,
	// DropQuarantined or SkipStaticFile for an item refused before the send.
	// err is the cause when there is one. An item a cancelled run never
	// answered gets no call: cancellation says nothing about the item, and the
	// caller can see its own context. Lets a phase that sends a fixed plan say
	// why each missing answer is missing (the fingerprint phase's errors[]).
	OnUnanswered func(item *work.WorkItem, reason string, err error)
	// OnRecordStored is called once per input item whose primary record is in
	// the store when the executor is done with it — newly written, or a dedup
	// hit on an existing row — with that record's UUID. Lets a caller report
	// WHICH records an ingest produced, not only how many.
	OnRecordStored func(uuid string, rr *httpmsg.HttpRequestResponse)
	Services       *services.Services
	HTTPRequester  *http.Requester
	Repository     *database.Repository    // Optional: database storage
	RecordWriter   *database.RecordWriter  // Optional: batched record writer (preferred over Repository.SaveRecord)
	FindingWriter  *database.FindingWriter // Optional: batched finding writer (preferred over Repository.SaveFinding)
	ScanUUID       string
	// ProjectUUID owns every record and finding this executor writes. An empty
	// value is silently coerced to the DEFAULT project by the repository (see
	// database.defaultProjectUUID), so a config carrying a Repository/
	// RecordWriter/FindingWriter MUST set it or its output lands in a project
	// nobody is reading. Enforced by TestExecutorConfigAlwaysSetsProjectUUID.
	ProjectUUID       string
	Hooks             HookRunner           // Optional: pre/post hooks
	ScopeMatcher      *config.ScopeMatcher // Optional: scope filtering
	ScopeOnIngest     bool                 // When true, skip both save and scan for out-of-scope items
	StaticFileMatcher *config.ScopeMatcher // Optional: always-on static file filtering (independent of ScopeMatcher)
	FollowSubdomains  bool                 // When true, subdomain_harvest adds discovered subdomains to scope and feeds them (needs ScopeMatcher + feedback)
	SkipBaseline      bool                 // When true, skip HTTP fetch if response already attached (Phase 3 DB source)
	// RecordRedirectChain persists each followed redirect hop as its own record,
	// chained through parent_uuid, and re-pairs the final response with the
	// request that actually produced it. Off by default: it multiplies row
	// counts on every redirecting URL, and only a host-sweep style phase wants
	// the intermediate hops. See saveRedirectHops.
	RecordRedirectChain bool
	// RecordSource is the http_records.source label this executor stamps. Empty
	// means "scanner", which is what every phase used before the label became
	// configurable — so a phase that says nothing is unchanged.
	RecordSource         string
	OASTProvider         modkit.OASTProvider // Optional: OAST callback URL generator for blind vuln detection
	OASTService          OASTFlusher         // Optional: OAST service to flush after scanning
	PauseCtrl            *PauseController    // Optional: cooperative pause/resume controller
	MaxFindingsPerModule int                 // When > 0, suppress findings after this many per module
	// FindingAdmission optionally shares the per-module cap and the
	// already-admitted identity set with other executors. nil = executor-local,
	// which is right for a phase that runs exactly one Execute. The
	// dynamic-assessment phase passes ONE admission to every feedback round, so
	// the cap spans the phase and a root cause re-found in a later round does not
	// re-fire its callbacks. See FindingAdmission.
	FindingAdmission      *FindingAdmission
	MaxDuration           time.Duration        // When > 0, cancel execution after this duration
	FeedbackDrainTimeout  time.Duration        // Idle timeout for draining feedback after source EOF (default: 100ms)
	FeedbackDrainMaxStall time.Duration        // Hard cap on draining with workers in-flight but making no progress (0 = 2x active module timeout). Guards against a module that ignores cancellation.
	WorkerExitGrace       time.Duration        // Grace for worker goroutines to exit after the item channel is closed (0 = default 60s, capped at FeedbackDrainMaxStall). Kept short and separate from the drain-stall cap so shutdown stays responsive.
	IPCacheSize           int                  // LRU cache size for parsed insertion points (default: 4096)
	IPCache               *InsertionPointCache // Optional: shared IP cache (if nil, a new one is created)
	ParallelPassive       bool                 // When true, run passive per-request modules concurrently
	PassiveModuleTimeout  time.Duration        // Timeout per passive module call (default: 5s). 0 uses default.
	ActiveModuleTimeout   time.Duration        // Timeout per active module call (default: 300s). 0 uses default. Modules may raise via TimeoutHinter.
	ActiveTaskLimit       int                  // Max concurrent active module tasks across host/request/IP scopes
	// HostTaskCap, when non-nil, overrides the per-host active-task cap the
	// scheduler admits under (default: the host limiter's current per-host
	// limit). Tests inject it; a value < 1 is treated as 1.
	HostTaskCap func(hostPort string) int
	// MaxOutstandingItems caps items that are dequeued but not yet finished —
	// a worker dispatches an item's active tasks and moves on, and the item
	// stays outstanding until its last task returns. Each one holds its live
	// baseline response buffer, so this is also the buffer-memory bound.
	// 0 = 4 x Workers. Values below Workers leave some workers idle.
	MaxOutstandingItems int
	OnStatus            func(processed, total, findings, distinctModules, activeCount, passiveCount, timedOut int64, elapsed time.Duration) // Optional: periodic status callback
	StatusInterval      time.Duration                                                                                                       // Interval for OnStatus callback (default: 30s)
	// ModuleTimeouts, when non-nil, is an externally-owned counter the executor
	// increments on each active-module timeout (instead of its own private one).
	// A multi-round phase passes one shared counter so the timed-out total in the
	// status line accumulates across the per-round executors it creates.
	ModuleTimeouts *atomic.Int64
	// OnModuleError, when non-nil, records one failed module call (kind is
	// exception, timeout or panic) on an externally-owned ledger and returns
	// that module's running error total. The runner passes one ledger to every
	// executor of a scan, so the rate-limited module.error events count across
	// phases and feedback rounds, and the totals reach scans.module_errors. nil
	// = executor-local counting only.
	OnModuleError func(moduleID, kind string) int64
	// Phase is the canonical phase id this executor runs under, carried on the
	// module.error events it emits. Empty leaves the field off.
	Phase string
	// FirstStatusInterval, when > 0 and shorter than StatusInterval, fires the
	// very first status tick after this duration instead of waiting a full
	// StatusInterval. Useful for long-cadence status (e.g., 2m) where users
	// shouldn't have to stare at silence before the first line appears.
	FirstStatusInterval time.Duration
	// DisableFeedback drops every URL discovered by passive modules instead of
	// re-injecting it into the scan. With this flag the executor scans exactly
	// the items the input source delivers and nothing more — matching the
	// shallow per-request semantics of `vigolium scan-request`. Used by
	// scan-on-receive's default mode to avoid the cascade of new HTTP records
	// that link extractors and redirect followers would otherwise generate.
	DisableFeedback bool
	// TechFilterDisabled bypasses the tech-stack allowlist gate (see modules.TechAware).
	// Set by --no-tech-filter and automatically by --intensity=deep so deep scans
	// run every module regardless of detected stack.
	TechFilterDisabled bool
	// OnTechDetected fires once per (host, tag) when a passive fingerprint
	// module first publishes a stack detection.
	OnTechDetected func(host, tag string)
	// DeepScan mirrors --intensity=deep into ScanContext so modules can unlock
	// heavier probing (e.g. dashboard_exposure's full mount-path sweep).
	DeepScan bool

	// ExternalFetcher is copied into ScanContext.ExternalFetcher;
	// nil disables third-party lookups.
	ExternalFetcher *nethttp.Client
	// AllowRiskyPayloads mirrors --allow-risky-payloads (or config
	// dynamic-assessment.allow_risky_payloads) into ScanContext, unlocking
	// risk:high payloads below deep.
	AllowRiskyPayloads bool
	// NoParamDedup mirrors --no-param-dedup into ScanContext: modules sharing
	// a vuln class stop skipping parameters another module already reported
	// (dispatch-time, in-task and in-module checks alike).
	NoParamDedup bool
	// InsertionPointFilter, when non-nil, narrows the per-insertion-point stage
	// to the points it accepts (`finding verify` re-runs a module on the one
	// point a finding was found on). Host- and request-scope modules are not
	// affected; their results carry FuzzingParameter for callers to filter on.
	InsertionPointFilter func(httpmsg.InsertionPoint) bool
	// ContentClassByHost seeds the per-host content-class registry from the
	// heuristics root probe (host → modkit.ContentClass string). It is the
	// fallback consulted by the content-class gate when a record's own
	// Content-Type is indeterminate. Honors the same TechFilterDisabled switch.
	ContentClassByHost map[string]string

	// Phase-shared state. A multi-round phase builds one executor per feedback
	// round; with per-executor registries round 2 would forget every tech-stack
	// detection (and the tech gate would let every gated module run
	// everywhere), every confirmed parameter (param dedup restarts) and every
	// per-host claim (per-host modules re-fire each round). When a field is
	// non-nil the executor uses it instead of creating its own; the phase
	// creates them once (see SharePhaseState). nil = executor-local, which is
	// right for a single-Execute phase.
	//
	// A supplied TechRegistry keeps its own OnDetect (OnTechDetected is not
	// applied to it), and a supplied ContentClass is not re-seeded from
	// ContentClassByHost — the phase does both once when it creates them.
	TechRegistry  *modkit.TechRegistry
	WAFStack      *modkit.WAFRegistry
	ParamFindings *modkit.ParameterFindingRegistry
	ContentClass  *modkit.ContentClassRegistry
	HostClaims    *HostClaims
	// HeaderClaims holds the once-per-host header-point claims.
	HeaderClaims *modkit.HeaderClaims

	// Ledger, when set, records per-record coverage in the scan's coverage
	// ledger and skips modules / the passive stage a record already finished
	// (WorkItem.Coverage). See LedgerSpec.
	Ledger *LedgerSpec

	// HeaderPointsAll turns the header insertion-point gate off
	// (dynamic_assessment.header_points: all, --header-fuzz=all): every header
	// point reaches every module that accepts headers, per path.
	HeaderPointsAll bool
}

// HostClaims holds the per-host run-once claims of ScanPerHost modules — one
// (module, origin) entry per claimed pair. Shared across a phase's executors
// via ExecutorConfig.HostClaims.
//
// The caches are bounded LRUs rather than unbounded maps: in a long-lived
// scan-on-receive executor the (module, host) key space grows with every
// distinct host ingested. The LRU caps that growth and, by evicting the
// least-recently-claimed pairs, lets per-host modules re-fire for a host whose
// claim has aged out.
type HostClaims struct {
	active  *lru.Cache[hostClaimKey, struct{}]
	passive *lru.Cache[hostClaimKey, struct{}]

	// attempts counts per-host runs that failed transiently and released their
	// claim (perHostClaimAttempts), so a host that keeps failing is not retried
	// on every item.
	mu       sync.Mutex
	attempts *lru.Cache[hostClaimKey, int]

	// bodies holds (module, response body) pairs a BodyOnlyPassive module has
	// already analysed.
	bodies *lru.Cache[string, struct{}]
}

// bodySeenCacheSize bounds the BodyOnlyPassive dedup set.
const bodySeenCacheSize = 65536

// seenBody reports whether moduleID already ran on this body, recording it if
// not. Nil-safe (always false).
func (h *HostClaims) seenBody(moduleID, bodyKey string) bool {
	if h == nil || h.bodies == nil {
		return false
	}
	seen, _ := h.bodies.ContainsOrAdd(moduleID+"\x00"+bodyKey, struct{}{})
	return seen
}

// maxPerHostClaimAttempts bounds how many times a (module, origin) per-host
// run is attempted when earlier attempts failed transiently.
const maxPerHostClaimAttempts = 2

// claimActive / claimPassive take the (module, origin) claim of a per-host
// active / passive module; true when this caller won it. ContainsOrAdd is
// atomic, so two concurrent workers cannot both win.
func (h *HostClaims) claimActive(key hostClaimKey) bool  { return claim(h.active, key) }
func (h *HostClaims) claimPassive(key hostClaimKey) bool { return claim(h.passive, key) }

func claim(cache *lru.Cache[hostClaimKey, struct{}], key hostClaimKey) bool {
	seen, _ := cache.ContainsOrAdd(key, struct{}{})
	return !seen
}

// releaseActive / releasePassive give a claim back after a transient failure
// (see release).
func (h *HostClaims) releaseActive(key hostClaimKey) bool  { return h.release(h.active, key) }
func (h *HostClaims) releasePassive(key hostClaimKey) bool { return h.release(h.passive, key) }

// release gives back claim key in cache after a transient failure so a later
// item for the same origin retries the run — unless the pair already used
// its attempts. Returns whether the claim was released. Nil-safe.
func (h *HostClaims) release(cache *lru.Cache[hostClaimKey, struct{}], key hostClaimKey) bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	n, _ := h.attempts.Get(key)
	n++
	h.attempts.Add(key, n)
	if n >= maxPerHostClaimAttempts {
		return false
	}
	cache.Remove(key)
	return true
}

// SharePhaseState fills every nil phase-shared field (TechRegistry, WAFStack,
// ParamFindings, ContentClass, HostClaims) with a fresh instance, so every
// executor built from copies of this config shares them. The tech registry
// gets OnTechDetected as its OnDetect and the content-class registry is seeded
// from ContentClassByHost, once, here. Call it on the phase's base config
// before the first round.
func (c *ExecutorConfig) SharePhaseState() {
	if c.TechRegistry == nil {
		c.TechRegistry = modkit.NewTechRegistry()
		c.TechRegistry.OnDetect = c.OnTechDetected
	}
	if c.WAFStack == nil {
		c.WAFStack = modkit.NewWAFRegistry()
	}
	if c.ParamFindings == nil {
		c.ParamFindings = &modkit.ParameterFindingRegistry{}
	}
	if c.ContentClass == nil {
		c.ContentClass = modkit.NewContentClassRegistry()
		for host, class := range c.ContentClassByHost {
			c.ContentClass.Set(host, modkit.ContentClass(class))
		}
	}
	if c.HostClaims == nil {
		c.HostClaims = NewHostClaims()
	}
	if c.HeaderClaims == nil {
		c.HeaderClaims = modkit.NewHeaderClaims()
	}
}

// NewHostClaims returns empty claim caches.
func NewHostClaims() *HostClaims {
	// size <= 0 is the only error lru.New returns; perHostClaimCacheSize is a
	// positive constant.
	a, _ := lru.New[hostClaimKey, struct{}](perHostClaimCacheSize)
	p, _ := lru.New[hostClaimKey, struct{}](perHostClaimCacheSize)
	n, _ := lru.New[hostClaimKey, int](perHostClaimCacheSize)
	b, _ := lru.New[string, struct{}](bodySeenCacheSize)
	return &HostClaims{active: a, passive: p, attempts: n, bodies: b}
}

// defaultOutstandingItemsPerWorker sizes MaxOutstandingItems when unset.
const defaultOutstandingItemsPerWorker = 4
