package source

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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

	// Engine
	CaseSensitivity         string // "auto_detect" | "sensitive" | "insensitive"
	EngineTimeout           time.Duration
	CustomHeaders           map[string]string
	EnableCookieJar         bool
	ProxyURL                string // HTTP proxy URL for discovery requests
	MaxConsecutiveErrors    int
	MaxConsecutiveWAFBlocks int
	ObservedMaxItems        int
	DisableKingfisher       bool

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
)

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
	status int
	ctype  string
	size   int64
	words  int64
}

// respCluster is a running representative for a group of near-identical
// responses during greedy clustering.
type respCluster struct {
	host    string
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
			if cl.status != rec.status || cl.host != rec.host || cl.ctype != rec.ctype {
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
	if len(d.cfg.CustomHeaders) > 0 {
		cfg.Engine.CustomHeaders = d.cfg.CustomHeaders
	}
	cfg.Engine.EnableCookieJar = d.cfg.EnableCookieJar
	if d.cfg.ProxyURL != "" {
		cfg.Engine.ProxyURL = d.cfg.ProxyURL
	}
	cfg.Engine.MaxConsecutiveErrors = d.cfg.MaxConsecutiveErrors
	cfg.Engine.MaxConsecutiveWAFBlocks = d.cfg.MaxConsecutiveWAFBlocks
	if d.cfg.ObservedMaxItems > 0 {
		cfg.Engine.ObservedMaxItems = d.cfg.ObservedMaxItems
	}
	cfg.Engine.DisableKingfisher = d.cfg.DisableKingfisher

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

	engine, err := discovery.NewEngineWithContext(ctx, cfg, siteMap)
	if err != nil {
		return fmt.Errorf("create engine: %w", err)
	}

	if err := engine.Start(); err != nil {
		return fmt.Errorf("start engine: %w", err)
	}

	_ = engine.WaitForQueues(ctx)
	engine.FlushKingfisher()
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

		rr, err := httpmsg.GetRawRequestFromURL(nodeURL.String())
		if err != nil {
			return nil // skip URLs we can't parse
		}

		resp := node.Response()
		hasResp := resp != nil && resp.StatusCode > 0

		rec := collectedRecord{rr: rr, path: nodeURL.Path, host: nodeURL.Hostname()}

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

		// Skip dedup for records without response (no body to hash)
		if !hasResp {
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
			method:   "GET",
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

	// Compact: drop exact-dedup tombstones.
	compacted := make([]collectedRecord, 0, len(allRecords))
	for _, rec := range allRecords {
		if rec.rr != nil {
			compacted = append(compacted, rec)
		}
	}
	localStats.HardDedupRemoved = localStats.TotalDiscovered - len(compacted)

	// Near-identical cluster cap: backstop for catch-all/SPA targets that the
	// exact hash and the engine's soft-404 detection can't collapse because each
	// response differs by a few bytes/words. Keeps at most clusterCap records per
	// (host, status, content-type, ~size, ~words) cluster.
	clusterCap := d.cfg.resolveClusterCap()
	localStats.ClusterCap = clusterCap
	if clusterCap > 0 {
		var capped int
		var cappedCodes [5]int
		compacted, capped, cappedCodes = capNearIdenticalClusters(compacted, clusterCap)
		localStats.FuzzyCappedRemoved = capped
		localStats.CappedCodes = cappedCodes
	}

	// Collect survivors (records + spec endpoints below).
	survivors := make([]*httpmsg.HttpRequestResponse, 0, len(compacted))
	for _, rec := range compacted {
		survivors = append(survivors, rec.rr)
	}

	// Parse API specs (OpenAPI/Swagger/Postman) found among survivors and add parsed endpoints
	specEndpoints := extractSpecEndpoints(survivors)
	if len(specEndpoints) > 0 {
		survivors = append(survivors, specEndpoints...)
		terminal.Notice("api-spec", fmt.Sprintf(
			"Ingested %d API spec endpoints from discovery of %s — extra requests "+
				"queued for dynamic assessment (longer scan, more results)",
			len(specEndpoints), target))
	}

	localStats.Imported = len(survivors)

	// Batch save to DB
	var uuids []string
	if d.cfg.Repository != nil && len(survivors) > 0 {
		var saveErr error
		uuids, saveErr = d.cfg.Repository.SaveRecordBatch(ctx, survivors, "deparos", d.cfg.ProjectUUID)
		if saveErr != nil {
			zap.L().Warn("Failed to batch save deparos results to DB", zap.Error(saveErr))
			// Fall back to emitting without UUIDs
			uuids = make([]string, len(survivors))
		}
	} else {
		uuids = make([]string, len(survivors))
	}

	if localStats.Imported > 0 {
		zap.L().Info("Deparos discovery results imported to DB",
			zap.String("target", target),
			zap.Int("discovered", localStats.TotalDiscovered),
			zap.Int("hard_dedup_removed", localStats.HardDedupRemoved),
			zap.Int("fuzzy_capped_removed", localStats.FuzzyCappedRemoved),
			zap.Int("cluster_cap", localStats.ClusterCap),
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

	// Emit WorkItems
	for i, rr := range survivors {
		item := work.NewWithModules(rr, d.cfg.EnableModules)
		if i < len(uuids) {
			item.RecordUUID = uuids[i]
		}

		select {
		case <-d.done:
			return fmt.Errorf("source closed")
		case d.items <- item:
		}
	}

	return nil
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
