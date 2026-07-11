package jstangle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"
)

const (
	defaultServiceMemoryBudget = int64(768 * 1024 * 1024)
	defaultServiceCacheBytes   = int64(128 * 1024 * 1024)
	serviceWeightBytes         = int64(128 * 1024 * 1024)
	defaultNormalInputBytes    = int64(1 * 1024 * 1024)
	defaultMaxASTInputBytes    = int64(4 * 1024 * 1024)
	defaultHardInputBytes      = int64(DefaultMaxInputBytes)
)

var ErrServiceClosed = errors.New("jstangle service is closed")

// ServiceConfig controls process-wide admission and result reuse. Admission is
// memory-derived rather than CPU-derived because Babel AST jobs are RSS-heavy.
type ServiceConfig struct {
	MemoryBudgetBytes int64
	MaxWeight         int64
	CacheBytes        int64
	WorkerCount       int
	WorkerMaxJobs     int
	WorkerMaxRSSBytes int64
	NormalInputBytes  int64
	MaxASTInputBytes  int64
	HardInputBytes    int64
	ScannerConfig     *Config
}

func DefaultServiceConfig() *ServiceConfig {
	return &ServiceConfig{
		MemoryBudgetBytes: defaultServiceMemoryBudget,
		CacheBytes:        defaultServiceCacheBytes,
		NormalInputBytes:  defaultNormalInputBytes,
		MaxASTInputBytes:  defaultMaxASTInputBytes,
		HardInputBytes:    defaultHardInputBytes,
		ScannerConfig:     DefaultConfig(),
	}
}

// AnalysisRequest is the single public work item accepted by the shared
// service. Content ownership remains with the caller and is never mutated.
type AnalysisRequest struct {
	Content []byte
	Options ScanOptions
}

type serviceBackend interface {
	ScanWithOptions(context.Context, []byte, ScanOptions) (*ScanResult, error)
	Capabilities() (*Capabilities, error)
}

type closeableBackend interface {
	Close() error
}

type cachedMetadata struct {
	Result     *ScanResult
	HasPayload bool
}

type cachedPayload struct {
	Code             *CodeRecord
	Beautified       *BeautifiedCode
	ArtifactContents [][]byte
}

type analysisFlight struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	result  *ScanResult
	err     error
}

// Service owns weighted admission, byte-bounded caches, and cancellation-aware
// in-flight coalescing for every JSTANGLE consumer in the process.
type Service struct {
	backend          serviceBackend
	weight           *semaphore.Weighted
	maxWeight        int64
	normalInputBytes int64
	maxASTInputBytes int64
	hardInputBytes   int64

	metadataCache *byteLRU[*cachedMetadata]
	payloadCache  *byteLRU[*cachedPayload]

	flightMu sync.Mutex
	flights  map[string]*analysisFlight

	rootCtx context.Context
	cancel  context.CancelFunc
	closed  atomic.Bool
	wg      sync.WaitGroup

	cacheHits        atomic.Int64
	cacheMisses      atomic.Int64
	coalesced        atomic.Int64
	jobsStarted      atomic.Int64
	jobsCompleted    atomic.Int64
	activeWeight     atomic.Int64
	degradedJobs     atomic.Int64
	fallbackJobs     atomic.Int64
	rejectedJobs     atomic.Int64
	queueWaitNS      atomic.Int64
	metricsMu        sync.Mutex
	profileStats     map[string]ServiceProfileStats
	stageMS          map[string]float64
	recordCounts     map[string]int64
	limitHits        map[string]int64
	confidenceCounts map[string]int64
}

// ServiceProfileStats is an aggregate over actual worker/fallback jobs. Cache
// hits are reported separately and never double-count input or stage time.
type ServiceProfileStats struct {
	Jobs        int64
	Complete    int64
	Partial     int64
	Failed      int64
	InputBytes  int64
	OutputBytes int64
	DurationMS  float64
}

// ServiceStats is a race-free snapshot suitable for diagnostics/metrics.
type ServiceStats struct {
	CacheHits        int64
	CacheMisses      int64
	Coalesced        int64
	JobsStarted      int64
	JobsCompleted    int64
	ActiveWeight     int64
	MetadataEntries  int
	MetadataBytes    int64
	PayloadEntries   int
	PayloadBytes     int64
	Workers          int
	WorkerJobs       int
	WorkerRestarts   int64
	WorkerRetries    int64
	WorkerActive     int64
	WorkerStarted    int64
	DegradedJobs     int64
	FallbackJobs     int64
	RejectedJobs     int64
	QueueWait        time.Duration
	WorkerRSSBytes   int64
	Profiles         map[string]ServiceProfileStats
	StageDurationMS  map[string]float64
	RecordCounts     map[string]int64
	LimitHits        map[string]int64
	ConfidenceCounts map[string]int64
}

func NewService(config *ServiceConfig) (*Service, error) {
	if config == nil {
		config = DefaultServiceConfig()
	}
	copyConfig := *config
	if copyConfig.MemoryBudgetBytes <= 0 {
		copyConfig.MemoryBudgetBytes = defaultServiceMemoryBudget
	}
	if copyConfig.MaxWeight <= 0 {
		copyConfig.MaxWeight = max(1, copyConfig.MemoryBudgetBytes/serviceWeightBytes)
	}
	if copyConfig.CacheBytes < 0 {
		copyConfig.CacheBytes = 0
	} else if copyConfig.CacheBytes == 0 {
		copyConfig.CacheBytes = defaultServiceCacheBytes
	}
	if copyConfig.ScannerConfig == nil {
		copyConfig.ScannerConfig = DefaultConfig()
	}
	scanner, err := NewScanner(copyConfig.ScannerConfig)
	if err != nil {
		return nil, err
	}
	workerCount := copyConfig.WorkerCount
	if workerCount <= 0 {
		// Start conservatively: one process per ~512 MiB of service budget,
		// capped at two until field RSS data justifies a wider default.
		workerCount = int(min(int64(2), max(int64(1), copyConfig.MemoryBudgetBytes/(512*1024*1024))))
	}
	pool := newWorkerPool(scanner, workerPoolConfig{
		Count: workerCount, MaxJobs: copyConfig.WorkerMaxJobs,
		MaxRSSBytes: copyConfig.WorkerMaxRSSBytes,
	})
	return newServiceWithBackend(&copyConfig, pool), nil
}

func newServiceWithBackend(config *ServiceConfig, backend serviceBackend) *Service {
	maxWeight := config.MaxWeight
	if maxWeight <= 0 {
		maxWeight = 1
	}
	cacheBytes := max(int64(0), config.CacheBytes)
	normalInputBytes := config.NormalInputBytes
	if normalInputBytes <= 0 {
		normalInputBytes = defaultNormalInputBytes
	}
	maxASTInputBytes := config.MaxASTInputBytes
	if maxASTInputBytes <= 0 {
		maxASTInputBytes = defaultMaxASTInputBytes
	}
	hardInputBytes := config.HardInputBytes
	if hardInputBytes <= 0 {
		hardInputBytes = defaultHardInputBytes
	}
	maxASTInputBytes = min(maxASTInputBytes, hardInputBytes)
	normalInputBytes = min(normalInputBytes, maxASTInputBytes)
	// Endpoint/flow metadata is comparatively small and more reusable; large
	// transformed/beautified documents live in an independently evictable cache.
	metadataBytes := cacheBytes / 3
	payloadBytes := cacheBytes - metadataBytes
	rootCtx, cancel := context.WithCancel(context.Background())
	return &Service{
		backend:          backend,
		weight:           semaphore.NewWeighted(maxWeight),
		maxWeight:        maxWeight,
		normalInputBytes: normalInputBytes,
		maxASTInputBytes: maxASTInputBytes,
		hardInputBytes:   hardInputBytes,
		metadataCache:    newByteLRU[*cachedMetadata](metadataBytes),
		payloadCache:     newByteLRU[*cachedPayload](payloadBytes),
		flights:          make(map[string]*analysisFlight),
		profileStats:     make(map[string]ServiceProfileStats),
		stageMS:          make(map[string]float64),
		recordCounts:     make(map[string]int64),
		limitHits:        make(map[string]int64),
		confidenceCounts: make(map[string]int64),
		rootCtx:          rootCtx,
		cancel:           cancel,
	}
}

var (
	defaultServiceMu     sync.Mutex
	defaultService       *Service
	defaultServiceErr    error
	defaultServiceConfig = DefaultServiceConfig()
)

// ConfigureDefaultService sets process-wide budgets before the first caller
// resolves DefaultService. Once initialized, changing worker/cache semantics
// would split callers across incompatible brokers and is rejected.
func ConfigureDefaultService(config *ServiceConfig) error {
	if config == nil {
		return nil
	}
	defaultServiceMu.Lock()
	defer defaultServiceMu.Unlock()
	if defaultService != nil || defaultServiceErr != nil {
		return fmt.Errorf("jstangle default service already initialized")
	}
	copyConfig := *config
	if config.ScannerConfig != nil {
		scannerConfig := *config.ScannerConfig
		copyConfig.ScannerConfig = &scannerConfig
	}
	defaultServiceConfig = &copyConfig
	return nil
}

// DefaultService returns the one process-wide broker used by discovery and
// passive modules. It runs all analysis through the length-prefixed worker
// pool; Scanner is only the binary/capability helper the pool builds on.
func DefaultService() (*Service, error) {
	defaultServiceMu.Lock()
	defer defaultServiceMu.Unlock()
	if defaultService == nil && defaultServiceErr == nil {
		defaultService, defaultServiceErr = NewService(defaultServiceConfig)
	}
	return defaultService, defaultServiceErr
}

func (s *Service) Scan(ctx context.Context, content []byte) (*ScanResult, error) {
	return s.Analyze(ctx, AnalysisRequest{Content: content, Options: ScanOptions{Profile: ProfileLegacy}})
}

func (s *Service) ScanWithOptions(ctx context.Context, content []byte, options ScanOptions) (*ScanResult, error) {
	return s.Analyze(ctx, AnalysisRequest{Content: content, Options: options})
}

func (s *Service) Analyze(ctx context.Context, request AnalysisRequest) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.closed.Load() {
		return nil, ErrServiceClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	options := normalizeScanOptions(request.Options)
	hardLimit := min(s.hardInputBytes, int64(options.MaxInputBytes))
	if int64(len(request.Content)) > hardLimit {
		s.rejectedJobs.Add(1)
		return nil, fmt.Errorf("%w: input=%d limit=%d", ErrInputTooLarge, len(request.Content), hardLimit)
	}
	originalProfile := options.Profile
	policy := s.inputPolicy(options.Profile, len(request.Content))
	if policy == inputPolicyLarge {
		switch options.Profile {
		case ProfileDiscovery:
			options.Profile = ProfileDiscoveryLite
		case ProfileLegacy:
			options.Profile = ProfileEndpoints
		default:
			policy = inputPolicyNormal
		}
	}
	caps, err := s.backend.Capabilities()
	if err != nil {
		return nil, err
	}
	// Capability handshake: if the embedded helper explicitly advertises its
	// profiles and the requested one is absent, fail fast with a typed error so
	// callers (js_beautify, the CSPT dom-security consumer) can skip cleanly with
	// a diagnostic instead of dispatching a job that dies with an opaque error.
	if !caps.SupportsProfile(options.Profile) {
		s.rejectedJobs.Add(1)
		return nil, fmt.Errorf("%w: %q (helper advertises %v)", ErrUnsupportedProfile, options.Profile, caps.Profiles)
	}
	key := serviceCacheKey(request.Content, options, caps.SourceHash)
	if result, ok := s.loadCache(key, options.SourceURL); ok {
		s.cacheHits.Add(1)
		return result, nil
	}
	s.cacheMisses.Add(1)

	result, err := s.doFlight(ctx, key, options.Deadline, func(jobCtx context.Context) (*ScanResult, error) {
		// Another flight may have populated the cache between the first lookup and
		// registration of this job.
		if result, ok := s.loadCache(key, options.SourceURL); ok {
			s.cacheHits.Add(1)
			return result, nil
		}

		if policy == inputPolicyFallback {
			s.jobsStarted.Add(1)
			s.fallbackJobs.Add(1)
			result := cheapFallbackAnalysis(request.Content, options, caps.SourceHash)
			s.jobsCompleted.Add(1)
			s.observeResult(options.Profile, len(request.Content), result)
			s.storeCache(key, result)
			return cloneScanResult(result)
		}

		weight := s.estimateWeight(options.Profile, len(request.Content))
		queueStarted := time.Now()
		if err := s.weight.Acquire(jobCtx, weight); err != nil {
			s.queueWaitNS.Add(time.Since(queueStarted).Nanoseconds())
			return nil, err
		}
		s.queueWaitNS.Add(time.Since(queueStarted).Nanoseconds())
		s.activeWeight.Add(weight)
		defer func() {
			s.activeWeight.Add(-weight)
			s.weight.Release(weight)
		}()

		s.jobsStarted.Add(1)
		result, err := s.backend.ScanWithOptions(jobCtx, request.Content, options)
		if err != nil {
			if jobCtx.Err() != nil || !supportsLexicalFallback(options.Profile) {
				return nil, err
			}
			result = cheapFallbackAnalysisWithReason(
				request.Content, options, caps.SourceHash, "worker_failure_fallback",
				"JavaScript worker analysis failed after its bounded retry; used string and manifest extraction",
			)
			s.fallbackJobs.Add(1)
			s.degradedJobs.Add(1)
		}
		if result == nil {
			return nil, fmt.Errorf("%w: backend returned nil result", ErrIncompleteOutput)
		}
		if analysisFailed(result) && supportsLexicalFallback(options.Profile) {
			reason := "ast_analysis_failed_fallback"
			if result.Completion != nil && result.Completion.ReasonCode != "" {
				reason = result.Completion.ReasonCode + "_fallback"
			}
			originalDiagnostics := append([]Diagnostic(nil), result.Diagnostics...)
			result = cheapFallbackAnalysisWithReason(
				request.Content, options, caps.SourceHash, reason,
				"AST analysis did not complete; used bounded string and manifest extraction",
			)
			result.Diagnostics = append(originalDiagnostics, result.Diagnostics...)
			if result.Analysis != nil {
				result.Analysis.Diagnostics = append(originalDiagnostics, result.Analysis.Diagnostics...)
			}
			if result.Completion != nil {
				result.Completion.Counts.Diagnostics = len(result.Diagnostics)
			}
			s.fallbackJobs.Add(1)
			s.degradedJobs.Add(1)
		}
		if originalProfile != options.Profile {
			s.degradedJobs.Add(1)
			markProfileDegraded(result, originalProfile, options.Profile, len(request.Content))
		}
		s.jobsCompleted.Add(1)
		s.observeResult(options.Profile, len(request.Content), result)
		s.storeCache(key, result)
		clone, err := cloneScanResult(result)
		if err != nil {
			return nil, err
		}
		return clone, nil
	})
	if result != nil {
		// Source URL is intentionally excluded from the content-analysis cache
		// key, so every waiter receives provenance rebound to its own asset URL.
		rebindSourceURL(result, options.SourceURL)
	}
	return result, err
}

func (s *Service) observeResult(profile AnalysisProfile, inputBytes int, result *ScanResult) {
	if result == nil {
		return
	}
	status := "complete"
	var durationMS float64
	var outputBytes int64
	var stages []StageMetric
	records := map[string]int{}
	if result.Analysis != nil {
		if result.Analysis.Stats.Status != "" {
			status = result.Analysis.Stats.Status
		}
		durationMS = result.Analysis.Stats.DurationMS
		stages = result.Analysis.Stats.StageMetrics
		for kind, count := range result.Analysis.Stats.RecordCounts {
			records[kind] = count
		}
	}
	if result.Completion != nil {
		if result.Completion.Status != "" {
			status = result.Completion.Status
		}
		outputBytes = result.Completion.OutputBytes
		if len(stages) == 0 {
			stages = result.Completion.StageMetrics
		}
	}
	if durationMS == 0 && result.ScanDuration > 0 {
		durationMS = float64(result.ScanDuration) / float64(time.Millisecond)
	}
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	key := string(profile)
	profileStats := s.profileStats[key]
	profileStats.Jobs++
	profileStats.InputBytes += int64(inputBytes)
	profileStats.OutputBytes += outputBytes
	profileStats.DurationMS += durationMS
	switch status {
	case "partial":
		profileStats.Partial++
	case "failed", "cancelled":
		profileStats.Failed++
	default:
		profileStats.Complete++
	}
	s.profileStats[key] = profileStats
	for _, stage := range stages {
		s.stageMS[stage.Stage] += stage.DurationMS
	}
	for kind, count := range records {
		s.recordCounts[kind] += int64(count)
	}
	addConfidence := func(kind, confidence string) {
		if confidence == "" {
			confidence = "unknown"
		}
		s.confidenceCounts[kind+"|"+confidence]++
	}
	for i := range result.RequestFacts {
		addConfidence("httpRequest", result.RequestFacts[i].Provenance.Confidence)
	}
	for i := range result.DomFlowFacts {
		addConfidence("domFlow", result.DomFlowFacts[i].Provenance.Confidence)
	}
	for i := range result.AssetFacts {
		addConfidence("assetReference", result.AssetFacts[i].Provenance.Confidence)
	}
	for i := range result.GraphQLOperations {
		addConfidence("graphqlOperation", result.GraphQLOperations[i].Provenance.Confidence)
	}
	for i := range result.WebSockets {
		addConfidence("websocket", result.WebSockets[i].Provenance.Confidence)
	}
	for i := range result.EventSources {
		addConfidence("eventSource", result.EventSources[i].Provenance.Confidence)
	}
	for i := range result.ClientRoutes {
		addConfidence("clientRoute", result.ClientRoutes[i].Provenance.Confidence)
	}
	for i := range result.BrowserFlows {
		addConfidence("browserSecurityFlow", result.BrowserFlows[i].Provenance.Confidence)
	}
	for _, diagnostic := range result.Diagnostics {
		if strings.Contains(diagnostic.Code, "limit") || strings.Contains(diagnostic.Code, "budget") ||
			strings.Contains(diagnostic.Code, "too_large") {
			s.limitHits[diagnostic.Code]++
		}
	}
}

func analysisFailed(result *ScanResult) bool {
	return result != nil && ((result.Completion != nil && result.Completion.Status == "failed") ||
		(result.Analysis != nil && result.Analysis.Stats.Status == "failed"))
}

func supportsLexicalFallback(profile AnalysisProfile) bool {
	return profile != ProfileDOMSecurity && profile != ProfileBeautify
}

type serviceInputPolicy uint8

const (
	inputPolicyNormal serviceInputPolicy = iota
	inputPolicyLarge
	inputPolicyFallback
)

func (s *Service) inputPolicy(profile AnalysisProfile, contentBytes int) serviceInputPolicy {
	bytes := int64(contentBytes)
	if bytes > s.maxASTInputBytes {
		return inputPolicyFallback
	}
	if bytes > s.normalInputBytes && (profile == ProfileDiscovery || profile == ProfileLegacy) {
		return inputPolicyLarge
	}
	return inputPolicyNormal
}

func markProfileDegraded(result *ScanResult, requested, effective AnalysisProfile, contentBytes int) {
	if result == nil {
		return
	}
	diagnostic := Diagnostic{
		Type: "diagnostic", Severity: "warning", Stage: "admission",
		Code:        "large_input_profile_degraded",
		Message:     fmt.Sprintf("input %d bytes requested profile %s; ran %s without transformed source", contentBytes, requested, effective),
		Recoverable: true,
	}
	result.Diagnostics = append(result.Diagnostics, diagnostic)
	// Enforce the downgraded contract even for alternate/test backends.
	result.Code = nil
	result.Artifacts = dropArtifactType(result.Artifacts, "transformedSource")
	if result.Analysis != nil {
		result.Analysis.Diagnostics = append(result.Analysis.Diagnostics, diagnostic)
		result.Analysis.Stats.Status = "partial"
		result.Analysis.Artifacts = dropArtifactType(result.Analysis.Artifacts, "transformedSource")
	}
	if result.Completion != nil {
		result.Completion.Status = "partial"
		result.Completion.ReasonCode = diagnostic.Code
	}
}

func dropArtifactType(artifacts []ArtifactDescriptor, artifactType string) []ArtifactDescriptor {
	filtered := make([]ArtifactDescriptor, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.ArtifactType != artifactType {
			filtered = append(filtered, artifact)
		}
	}
	return filtered
}

func (s *Service) doFlight(ctx context.Context, key string, deadline time.Duration, run func(context.Context) (*ScanResult, error)) (*ScanResult, error) {
	s.flightMu.Lock()
	if existing := s.flights[key]; existing != nil {
		existing.waiters++
		s.coalesced.Add(1)
		s.flightMu.Unlock()
		return s.waitFlight(ctx, key, existing)
	}

	jobDeadline := deadline + 10*time.Second
	if jobDeadline <= 0 || jobDeadline > MaxScanTimeout {
		jobDeadline = MaxScanTimeout
	}
	jobCtx, cancel := context.WithTimeout(s.rootCtx, jobDeadline)
	flight := &analysisFlight{done: make(chan struct{}), cancel: cancel, waiters: 1}
	s.flights[key] = flight
	s.wg.Add(1)
	s.flightMu.Unlock()

	go func() {
		defer s.wg.Done()
		flight.result, flight.err = run(jobCtx)
		cancel()
		s.flightMu.Lock()
		if s.flights[key] == flight {
			delete(s.flights, key)
		}
		close(flight.done)
		s.flightMu.Unlock()
	}()

	return s.waitFlight(ctx, key, flight)
}

func (s *Service) waitFlight(ctx context.Context, key string, flight *analysisFlight) (*ScanResult, error) {
	select {
	case <-flight.done:
		if flight.err != nil {
			return nil, flight.err
		}
		return cloneScanResult(flight.result)
	case <-ctx.Done():
		s.flightMu.Lock()
		if s.flights[key] == flight {
			flight.waiters--
			if flight.waiters == 0 {
				delete(s.flights, key)
				flight.cancel()
			}
		}
		s.flightMu.Unlock()
		return nil, ctx.Err()
	}
}

func (s *Service) estimateWeight(profile AnalysisProfile, contentBytes int) int64 {
	bytes := int64(contentBytes)
	ceilUnits := func(unit int64) int64 {
		if bytes == 0 {
			return 0
		}
		return (bytes + unit - 1) / unit
	}
	var weight int64
	switch profile {
	case ProfileDOMSecurity:
		weight = 1 + ceilUnits(512*1024)
	case ProfileBeautify:
		weight = 4 + ceilUnits(256*1024)
	case ProfileFull, ProfileLegacy, ProfileInspect:
		weight = 5 + ceilUnits(192*1024)
	default:
		weight = 2 + ceilUnits(256*1024)
	}
	return min(max(int64(1), weight), s.maxWeight)
}

func serviceCacheKey(content []byte, options ScanOptions, sourceHash string) string {
	digest := sha256.Sum256(content)
	keyMaterial := struct {
		ContentSHA       string
		ToolSourceHash   string
		Profile          AnalysisProfile
		Beautify         bool
		MaxOutputBytes   int64
		MaxArtifactBytes int64
		MaxRequests      int
		MaxASTNodes      int
		DeadlineMS       int64
		Filename         string
		MediaType        string
	}{
		ContentSHA: hex.EncodeToString(digest[:]), ToolSourceHash: sourceHash,
		Profile: options.Profile, Beautify: options.Beautify,
		MaxOutputBytes: options.MaxOutputBytes, MaxArtifactBytes: options.MaxArtifactBytes,
		MaxRequests: options.MaxRequests, MaxASTNodes: options.MaxASTNodes, DeadlineMS: options.Deadline.Milliseconds(),
		Filename: options.Filename, MediaType: options.MediaType,
	}
	encoded, _ := json.Marshal(keyMaterial)
	keyDigest := sha256.Sum256(encoded)
	return hex.EncodeToString(keyDigest[:])
}

func (s *Service) loadCache(key, sourceURL string) (*ScanResult, bool) {
	metadata, ok := s.metadataCache.get(key)
	if !ok || metadata == nil || metadata.Result == nil {
		return nil, false
	}
	result, err := cloneScanResult(metadata.Result)
	if err != nil {
		s.metadataCache.remove(key)
		return nil, false
	}
	if metadata.HasPayload {
		payload, payloadOK := s.payloadCache.get(key)
		if !payloadOK || payload == nil {
			return nil, false
		}
		applyCachedPayload(result, payload)
	}
	rebindSourceURL(result, sourceURL)
	return result, true
}

func (s *Service) storeCache(key string, result *ScanResult) {
	metadataResult, payload, err := splitCachedResult(result)
	if err != nil {
		return
	}
	metadata := &cachedMetadata{Result: metadataResult, HasPayload: payload != nil}
	encoded, err := json.Marshal(metadata)
	if err != nil || !s.metadataCache.add(key, metadata, int64(len(encoded))) {
		return
	}
	if payload != nil {
		if !s.payloadCache.add(key, payload, payload.size()) {
			// A metadata hit without its required payload must never be presented
			// as a complete result.
			s.metadataCache.remove(key)
		}
	}
}

func splitCachedResult(result *ScanResult) (*ScanResult, *cachedPayload, error) {
	clone, err := cloneScanResult(result)
	if err != nil {
		return nil, nil, err
	}
	payload := &cachedPayload{Code: clone.Code, Beautified: clone.Beautified}
	clone.Code = nil
	clone.Beautified = nil
	for i := range clone.Artifacts {
		if len(clone.Artifacts[i].Content) > 0 {
			payload.ArtifactContents = append(payload.ArtifactContents, append([]byte(nil), clone.Artifacts[i].Content...))
			clone.Artifacts[i].Content = nil
		} else {
			payload.ArtifactContents = append(payload.ArtifactContents, nil)
		}
	}
	if payload.Code == nil && payload.Beautified == nil {
		hasContent := false
		for _, content := range payload.ArtifactContents {
			hasContent = hasContent || len(content) > 0
		}
		if !hasContent {
			payload = nil
		}
	}
	return clone, payload, nil
}

func (p *cachedPayload) size() int64 {
	if p == nil {
		return 0
	}
	var size int64
	if p.Code != nil {
		size += int64(len(p.Code.Content) + len(p.Code.Filename))
	}
	if p.Beautified != nil {
		size += int64(len(p.Beautified.Content) + len(p.Beautified.Filename))
		for _, path := range p.Beautified.ModulePaths {
			size += int64(len(path))
		}
	}
	for _, content := range p.ArtifactContents {
		size += int64(len(content))
	}
	return max(int64(1), size)
}

func applyCachedPayload(result *ScanResult, payload *cachedPayload) {
	if payload == nil {
		return
	}
	result.Code = cloneCodeRecord(payload.Code)
	result.Beautified = cloneBeautified(payload.Beautified)
	for i := range result.Artifacts {
		if i < len(payload.ArtifactContents) {
			result.Artifacts[i].Content = append([]byte(nil), payload.ArtifactContents[i]...)
		}
	}
}

func cloneScanResult(result *ScanResult) (*ScanResult, error) {
	if result == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("clone jstangle result: %w", err)
	}
	var clone ScanResult
	if err := json.Unmarshal(encoded, &clone); err != nil {
		return nil, fmt.Errorf("clone jstangle result: %w", err)
	}
	for i := range result.Artifacts {
		if i < len(clone.Artifacts) {
			clone.Artifacts[i].Content = append([]byte(nil), result.Artifacts[i].Content...)
		}
	}
	return &clone, nil
}

func cloneCodeRecord(record *CodeRecord) *CodeRecord {
	if record == nil {
		return nil
	}
	clone := *record
	return &clone
}

func cloneBeautified(value *BeautifiedCode) *BeautifiedCode {
	if value == nil {
		return nil
	}
	clone := *value
	clone.ModulePaths = append([]string(nil), value.ModulePaths...)
	return &clone
}

func rebindSourceURL(result *ScanResult, sourceURL string) {
	if result == nil {
		return
	}
	for i := range result.AssetFacts {
		result.AssetFacts[i].ParentSourceURL = sourceURL
	}
	if result.Analysis != nil {
		result.Analysis.Source.URL = sourceURL
		// Source URL is intentionally excluded from the content/profile cache key.
		// Asset records are the only typed records that embed their parent source,
		// so rebind their raw envelope representation as well as the decoded slice.
		for i, record := range result.Analysis.Records {
			var header struct {
				Kind string `json:"kind"`
			}
			if json.Unmarshal(record, &header) != nil || header.Kind != "assetReference" {
				continue
			}
			var fact AssetReferenceFact
			if json.Unmarshal(record, &fact) != nil {
				continue
			}
			fact.ParentSourceURL = sourceURL
			if rebound, err := json.Marshal(fact); err == nil {
				result.Analysis.Records[i] = rebound
			}
		}
	}
}

func (s *Service) Capabilities() (*Capabilities, error) {
	return s.backend.Capabilities()
}

func (s *Service) EnsureReady() error {
	_, err := s.backend.Capabilities()
	return err
}

func (s *Service) Checksum() string {
	if backend, ok := s.backend.(interface{ Checksum() string }); ok {
		return backend.Checksum()
	}
	return ""
}

func (s *Service) Stats() ServiceStats {
	metadataEntries, metadataBytes := s.metadataCache.lenAndBytes()
	payloadEntries, payloadBytes := s.payloadCache.lenAndBytes()
	stats := ServiceStats{
		CacheHits: s.cacheHits.Load(), CacheMisses: s.cacheMisses.Load(),
		Coalesced: s.coalesced.Load(), JobsStarted: s.jobsStarted.Load(),
		JobsCompleted: s.jobsCompleted.Load(), ActiveWeight: s.activeWeight.Load(),
		MetadataEntries: metadataEntries, MetadataBytes: metadataBytes,
		PayloadEntries: payloadEntries, PayloadBytes: payloadBytes,
	}
	if backend, ok := s.backend.(interface{ Stats() WorkerPoolStats }); ok {
		pool := backend.Stats()
		stats.Workers = pool.Workers
		stats.WorkerJobs = pool.Jobs
		stats.WorkerRestarts = pool.Restarts
		stats.WorkerRetries = pool.Retries
		stats.WorkerActive = pool.ActiveJobs
		stats.WorkerStarted = pool.JobsStarted
		stats.WorkerRSSBytes = pool.RSSBytes
	}
	stats.DegradedJobs = s.degradedJobs.Load()
	stats.FallbackJobs = s.fallbackJobs.Load()
	stats.RejectedJobs = s.rejectedJobs.Load()
	stats.QueueWait = time.Duration(s.queueWaitNS.Load())
	s.metricsMu.Lock()
	stats.Profiles = cloneMap(s.profileStats)
	stats.StageDurationMS = cloneMap(s.stageMS)
	stats.RecordCounts = cloneMap(s.recordCounts)
	stats.LimitHits = cloneMap(s.limitHits)
	stats.ConfidenceCounts = cloneMap(s.confidenceCounts)
	s.metricsMu.Unlock()
	return stats
}

func cloneMap[K comparable, V any](source map[K]V) map[K]V {
	result := make(map[K]V, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func (s *Service) ClearCache() {
	s.metadataCache.clear()
	s.payloadCache.clear()
}

func (s *Service) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.cancel()
	s.flightMu.Lock()
	for key, flight := range s.flights {
		delete(s.flights, key)
		flight.cancel()
	}
	s.flightMu.Unlock()
	s.wg.Wait()
	s.ClearCache()
	if backend, ok := s.backend.(closeableBackend); ok {
		return backend.Close()
	}
	return nil
}
