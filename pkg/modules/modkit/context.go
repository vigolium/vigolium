package modkit

import (
	"context"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/mutation"
	"golang.org/x/sync/singleflight"
)

// ParameterFindingRegistry tracks which (URL, parameter, vulnerability class)
// combinations have already produced findings. Modules can check this to
// avoid redundant scanning of already-confirmed vulnerabilities.
//
// The backing store is a bounded LRU rather than an unbounded sync.Map: the key
// space is (host+path, param, vuln-class), which in a long-lived scan-on-receive
// executor grows with every distinct URL+param ever scanned — the highest-
// cardinality of all the ScanContext registries. Eviction only forgets that a
// location was already found, so at worst an aged-out location is re-scanned
// once (it re-marks itself); it never produces a false finding.
type ParameterFindingRegistry struct {
	once  sync.Once
	found *lru.Cache[string, struct{}]
}

// cache lazily initializes the bounded LRU so a zero-value
// &ParameterFindingRegistry{} (used by the executor and several tests) is safe.
func (r *ParameterFindingRegistry) cache() *lru.Cache[string, struct{}] {
	r.once.Do(func() {
		// lru.New only errors on size <= 0; paramFindingCacheSize is positive.
		r.found, _ = lru.New[string, struct{}](paramFindingCacheSize)
	})
	return r.found
}

// MarkFound records that a vulnerability of the given class was found
// at the specified location and parameter.
func (r *ParameterFindingRegistry) MarkFound(hostPath, paramName, vulnTag string) {
	if r == nil {
		return
	}
	r.cache().Add(hostPath+"|"+paramName+"|"+vulnTag, struct{}{})
}

// HasFinding returns true if a vulnerability of the given class was already
// found at the specified location and parameter.
func (r *ParameterFindingRegistry) HasFinding(hostPath, paramName, vulnTag string) bool {
	if r == nil {
		return false
	}
	return r.cache().Contains(hostPath + "|" + paramName + "|" + vulnTag)
}

// RequestFeeder allows modules to inject discovered requests back into the scanning pipeline.
type RequestFeeder interface {
	// Feed submits a new request for scanning. Returns true if accepted, false if dropped.
	Feed(rr *httpmsg.HttpRequestResponse) bool
}

// ScopeExpander lets modules add an exact host to the scan's runtime scope
// allow-set, so a discovered host becomes scannable without wildcarding its
// apex. Used by subdomain_harvest under --follow-subdomains.
type ScopeExpander interface {
	// AllowHost adds host (exact match) to the in-scope set for this scan.
	AllowHost(host string)
}

// RiskScoreUpdater updates risk scores for HTTP records in the database.
type RiskScoreUpdater interface {
	UpdateRiskScores(ctx context.Context, scores map[string]int) error
}

// RemarksAnnotator appends semantic tags (remarks) to HTTP records in the database.
type RemarksAnnotator interface {
	// AppendRemarks merges the given remarks into existing remarks for each record UUID.
	// Duplicate remarks within a record are deduplicated.
	AppendRemarks(ctx context.Context, annotations map[string][]string) error
}

// DerivedArtifact is immutable analysis output associated with a stored HTTP
// record. The original request/response remains the source of truth; consumers
// can inspect this companion artifact without changing captured traffic.
type DerivedArtifact struct {
	RecordUUID string
	Kind       string
	Filename   string
	MediaType  string
	SHA256     string
	Content    []byte
	Metadata   map[string]any
}

// DerivedArtifactWriter persists immutable companion artifacts produced by
// passive analysis (for example, a beautified JavaScript bundle).
type DerivedArtifactWriter interface {
	StoreDerivedArtifact(ctx context.Context, artifact *DerivedArtifact) error
}

// RequestUUIDResolver resolves a request hash to a database record UUID.
type RequestUUIDResolver interface {
	ResolveRequestUUID(requestHash string) string
}

// ScopeChecker answers whether a host is within the scan's configured scope,
// i.e. whether it is (part of) the scan target rather than a third-party
// resource. Used by the js-beautify module to only treat a known-vendor host as
// third-party when the scan is not actually targeting that vendor.
type ScopeChecker interface {
	IsHostInScope(host string) bool
}

// RecordResponseRewriter overwrites a stored HTTP record's raw response in place
// and recomputes its derived hash/length/word fields. Used by the passive
// js-beautify module to replace a minified JS body with its beautified,
// bundle-unpacked form so downstream traffic/finding/fs views and manual review
// see readable source. No-op when the record can't be resolved (e.g. stateless).
type RecordResponseRewriter interface {
	// RewriteRecordResponse replaces the raw response bytes of the record with
	// the given UUID. rawResponse must be a complete HTTP response (status line
	// + headers + body).
	RewriteRecordResponse(ctx context.Context, uuid string, rawResponse []byte) error
}

// OASTProvider generates out-of-band callback URLs for blind vulnerability detection.
type OASTProvider interface {
	GenerateURL(targetURL, paramName, injectionType, moduleID, requestHash string) string
	// RecordPayload attaches the literal value planted at the injection point to
	// the callback URL's tracked context, so a resulting finding reconstructs the
	// planting request faithfully (the real header/parameter value, not a guessed
	// http://<host> shape). callbackURL is the value returned by GenerateURL.
	RecordPayload(callbackURL, payload string)
	Enabled() bool
}

// MutationGenerator provides value-aware mutation capabilities.
type MutationGenerator interface {
	Classify(value string, hint *mutation.SchemaHint) mutation.ValueType
	Generate(value string, vtype mutation.ValueType, opts *mutation.GenerateOptions) mutation.MutationSet
}

// InsertionPointProvider retrieves cached insertion points for a request,
// avoiding redundant parsing across modules.
type InsertionPointProvider interface {
	GetInsertionPoints(raw []byte, requestID string, includeNested bool) ([]httpmsg.InsertionPoint, error)
}

const baselineCacheSize = 4096

// perHostRegistryCacheSize bounds the per-host TechStack / WAFStack /
// ContentClass registries so a long-lived scan-on-receive executor can't
// accumulate one entry per distinct host for the whole process lifetime.
// Eviction only forgets a host's cached gating hint (re-derived, or fail-open,
// on the next sighting).
const perHostRegistryCacheSize = 8192

// paramFindingCacheSize bounds the cross-module finding-dedup registry — see
// ParameterFindingRegistry.
const paramFindingCacheSize = 65536

// ScanContext provides shared resources to modules during scanning.
type ScanContext struct {
	DedupManager        *dedup.Manager
	RiskScoreUpdater    RiskScoreUpdater
	RemarksAnnotator    RemarksAnnotator
	RecordRewriter      RecordResponseRewriter
	ArtifactWriter      DerivedArtifactWriter
	RequestUUIDResolver RequestUUIDResolver
	Scope               ScopeChecker
	OASTProvider        OASTProvider
	MutationGen         MutationGenerator
	RequestFeeder       RequestFeeder
	ScopeExpander       ScopeExpander // Optional: add discovered hosts to runtime scope (--follow-subdomains)
	InsertionPoints     InsertionPointProvider
	ParamFindings       *ParameterFindingRegistry // Cross-module finding dedup
	TechStack           *TechRegistry             // Per-host tech-stack detections (populated by *_fingerprint passive modules)
	WAFStack            *WAFRegistry              // Per-host WAF/CDN detections (populated by XSS modules on block responses)
	ContentClass        *ContentClassRegistry     // Per-host content-class hint (seeded from the heuristics root probe; fallback for content-class module gating)

	cookiePolicyOnce sync.Once
	cookiePolicy     *CookiePolicyRegistry

	// FollowSubdomains gates the subdomain_harvest feed-back behavior: when true
	// the module adds discovered in-scope subdomains to scope (via ScopeExpander)
	// and feeds them for scanning. Off by default (recon-only).
	FollowSubdomains bool

	// DeepScan mirrors --intensity=deep: modules may use it to unlock heavier,
	// broader probing (e.g. dashboard_exposure's full mount-path sweep). Off by
	// default so normal scans stay bounded.
	DeepScan bool

	baselineOnce   sync.Once
	baselineCache  *lru.Cache[string, *BaselineEntry]
	baselineFlight singleflight.Group

	wildcardOnce   sync.Once
	wildcardCache  *lru.Cache[string, *WildcardEntry]
	wildcardFlight singleflight.Group

	// Catch-all decoy probe cache: a guaranteed-nonexistent sibling/decoy/random-
	// dir probe's response is stable for the host, so it is fetched once per
	// (observed record, probe kind, dir, ext) and reused across a module's whole
	// probe loop and across modules processing the same record. See decoyProbe.
	decoyOnce   sync.Once
	decoyCache  *lru.Cache[string, *decoyResult]
	decoyFlight singleflight.Group
}

func (sc *ScanContext) cookiePolicies() *CookiePolicyRegistry {
	if sc == nil {
		return nil
	}
	sc.cookiePolicyOnce.Do(func() { sc.cookiePolicy = &CookiePolicyRegistry{} })
	return sc.cookiePolicy
}

// DerivedArtifactWriterOrNil returns the configured immutable artifact writer.
func (sc *ScanContext) DerivedArtifactWriterOrNil() DerivedArtifactWriter {
	if sc == nil {
		return nil
	}
	return sc.ArtifactWriter
}

// getBaselineCache returns the LRU baseline cache, lazily initializing on first use.
func (sc *ScanContext) getBaselineCache() *lru.Cache[string, *BaselineEntry] {
	sc.baselineOnce.Do(func() {
		// lru.New only errors if size <= 0
		sc.baselineCache, _ = lru.New[string, *BaselineEntry](baselineCacheSize)
	})
	return sc.baselineCache
}

// DedupMgr returns the DedupManager or nil safely.
func (sc *ScanContext) DedupMgr() *dedup.Manager {
	if sc == nil {
		return nil
	}
	return sc.DedupManager
}

// OASTProv returns the OASTProvider or nil safely.
func (sc *ScanContext) OASTProv() OASTProvider {
	if sc == nil {
		return nil
	}
	return sc.OASTProvider
}

// Feeder returns the RequestFeeder or nil safely.
func (sc *ScanContext) Feeder() RequestFeeder {
	if sc == nil {
		return nil
	}
	return sc.RequestFeeder
}

// RecordResponseRewriterOrNil returns the RecordResponseRewriter or nil safely
// (unset in stateless scans and bare-ScanContext tests).
func (sc *ScanContext) RecordResponseRewriterOrNil() RecordResponseRewriter {
	if sc == nil {
		return nil
	}
	return sc.RecordRewriter
}

// IsScanTarget reports whether host is within the scan's configured scope (i.e.
// the scan is targeting that host). Returns false when no scope checker is wired
// (ingested traffic / no-scope scans / tests) — so a known-vendor host is then
// treated as third-party by default, which is the safe choice for beautification.
func (sc *ScanContext) IsScanTarget(host string) bool {
	return sc != nil && sc.Scope != nil && sc.Scope.IsHostInScope(host)
}

// ShouldFollowSubdomains reports whether the subdomain_harvest module should
// pull discovered subdomains into the scan. Requires both the toggle and a
// usable feeder + scope expander, so the module never half-applies the feature.
func (sc *ScanContext) ShouldFollowSubdomains() bool {
	return sc != nil && sc.FollowSubdomains && sc.RequestFeeder != nil && sc.ScopeExpander != nil
}

// AllowHost adds host to the scan's runtime scope allow-set if a ScopeExpander
// is wired. No-op otherwise (e.g. tests with a bare ScanContext).
func (sc *ScanContext) AllowHost(host string) {
	if sc == nil || sc.ScopeExpander == nil {
		return
	}
	sc.ScopeExpander.AllowHost(host)
}

// IPProvider returns the InsertionPointProvider or nil safely.
func (sc *ScanContext) IPProvider() InsertionPointProvider {
	if sc == nil {
		return nil
	}
	return sc.InsertionPoints
}

// GetInsertionPoints returns insertion points for a request, using the cached
// provider if available and falling back to direct parsing otherwise.
func (sc *ScanContext) GetInsertionPoints(raw []byte, requestID string, includeNested bool) ([]httpmsg.InsertionPoint, error) {
	if p := sc.IPProvider(); p != nil {
		return p.GetInsertionPoints(raw, requestID, includeNested)
	}
	return httpmsg.CreateAllInsertionPoints(raw, includeNested)
}

// ParamFindingsRegistry returns the ParameterFindingRegistry or nil safely.
func (sc *ScanContext) ParamFindingsRegistry() *ParameterFindingRegistry {
	if sc == nil {
		return nil
	}
	return sc.ParamFindings
}

// MarkTech records a detected tech tag for the given host. No-op when the
// registry is unset (e.g. tests with a bare ScanContext).
func (sc *ScanContext) MarkTech(host, tag string) {
	if sc == nil || sc.TechStack == nil {
		return
	}
	sc.TechStack.Mark(host, tag)
}

// HasTech reports whether tag was detected for host during the scan. It is the
// read-side mirror of MarkTech and is fail-closed: a nil ScanContext or unset
// registry returns false, so a tech-gated active module never probes a host
// whose stack was not fingerprinted (or in tests with a bare ScanContext).
func (sc *ScanContext) HasTech(host, tag string) bool {
	if sc == nil || sc.TechStack == nil {
		return false
	}
	return sc.TechStack.Has(host, tag)
}

// MarkWAF records the WAF/CDN type observed fronting host. No-op when the
// registry is unset (e.g. tests with a bare ScanContext).
func (sc *ScanContext) MarkWAF(host, wafType string) {
	if sc == nil || sc.WAFStack == nil {
		return
	}
	sc.WAFStack.Mark(host, wafType)
}

// DetectedWAF returns the WAF/CDN type observed fronting host during the scan,
// or "" if none was seen or the registry is unset.
func (sc *ScanContext) DetectedWAF(host string) string {
	if sc == nil || sc.WAFStack == nil {
		return ""
	}
	return sc.WAFStack.Get(host)
}

// MutGen returns the MutationGenerator or a default implementation if nil.
func (sc *ScanContext) MutGen() MutationGenerator {
	if sc == nil || sc.MutationGen == nil {
		return &defaultMutationGen{}
	}
	return sc.MutationGen
}

// defaultMutationGen is the fallback implementation using the mutation package directly.
type defaultMutationGen struct{}

func (d *defaultMutationGen) Classify(value string, hint *mutation.SchemaHint) mutation.ValueType {
	return mutation.Classify(value, hint)
}

func (d *defaultMutationGen) Generate(value string, vtype mutation.ValueType, opts *mutation.GenerateOptions) mutation.MutationSet {
	return mutation.Generate(value, vtype, opts)
}
