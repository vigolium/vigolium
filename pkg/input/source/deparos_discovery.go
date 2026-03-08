package source

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/vigolium/vigolium/internal/resources/wordlists"
	deparosconfig "github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	deparosstorage "github.com/vigolium/vigolium/pkg/deparos/storage"
	"github.com/vigolium/vigolium/pkg/httpmsg"
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
	Mode             string            // "files_and_dirs" | "files_only" | "dirs_only"
	ScopeMode        string            // "any" | "subdomain" | "exact"
	RecursionEnabled bool              // default: true
	RecursionDepth   int               // default: 5
	SaveResponseBody bool              // default: true

	// Wordlists
	ShortFilePath    string
	LongFilePath     string
	ShortDirPath     string
	LongDirPath      string
	FuzzWordlistPath string
	UseObservedNames bool
	UseObservedFiles bool

	// Extensions
	TestCustom      bool
	CustomList      []string
	TestObserved    bool
	TestVariants    bool
	TestNoExtension bool

	// Engine
	CaseSensitivity   string // "auto_detect" | "sensitive" | "insensitive"
	EngineTimeout     time.Duration
	CustomHeaders     map[string]string
	EnableCookieJar bool
	ProxyURL        string // HTTP proxy URL for discovery requests

	// Malformed path probe
	EnableMalformedPathProbe bool

	// DB import: if set, results are saved to vigolium's http_records table
	Repository  RecordSaver
	ProjectUUID string
}

// DiscoveryStats tracks status code statistics for discovered and deduplicated records.
type DiscoveryStats struct {
	TotalDiscovered  int
	HardDedupRemoved int
	Imported         int
	AllCodes         [5]int // index 0=1xx, 1=2xx, 2=3xx, 3=4xx, 4=5xx
	DedupedCodes     [5]int // status codes of hard-dedup removed records
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
	cfg.Filenames.UseObservedFiles = d.cfg.UseObservedFiles

	// Extensions
	cfg.Extensions.TestCustom = d.cfg.TestCustom
	if len(d.cfg.CustomList) > 0 {
		cfg.Extensions.CustomList = d.cfg.CustomList
	}
	cfg.Extensions.TestObserved = d.cfg.TestObserved
	cfg.Extensions.TestVariants = d.cfg.TestVariants
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
	type collectedRecord struct {
		rr   *httpmsg.HttpRequestResponse
		path string
	}
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

		// Attach response data if available
		if hasResp {
			rawResp := httpmsg.BuildRawResponse(resp.StatusCode, resp.Headers, string(resp.Body))
			httpResp := httpmsg.NewHttpResponse(rawResp)
			rr = rr.WithResponse(httpResp)
		}

		localStats.TotalDiscovered++
		if hasResp {
			localStats.AllCodes[statusCodeBucket(resp.StatusCode)]++
		}

		// Skip dedup for records without response (no hash to compare)
		if !hasResp {
			allRecords = append(allRecords, collectedRecord{rr: rr, path: nodeURL.Path})
			return nil
		}

		// Compute dedup key
		respRaw := rr.Response().Raw()
		h := sha256.Sum256(respRaw)
		key := hardDedupKey{
			hostname: nodeURL.Hostname(),
			method:   "GET",
			status:   resp.StatusCode,
			length:   int64(len(resp.Body)),
			respHash: hex.EncodeToString(h[:]),
		}

		if existingIdx, exists := dedupMap[key]; exists {
			// Keep the shorter path
			existingPath := allRecords[existingIdx].path
			newPath := nodeURL.Path
			if len(newPath) < len(existingPath) {
				// Evict existing, keep new
				localStats.DedupedCodes[statusCodeBucket(resp.StatusCode)]++
				allRecords[existingIdx] = collectedRecord{} // mark as nil
				dedupMap[key] = len(allRecords)
				allRecords = append(allRecords, collectedRecord{rr: rr, path: newPath})
			} else {
				// Keep existing, discard new
				localStats.DedupedCodes[statusCodeBucket(resp.StatusCode)]++
			}
		} else {
			dedupMap[key] = len(allRecords)
			allRecords = append(allRecords, collectedRecord{rr: rr, path: nodeURL.Path})
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Compact: collect survivors
	survivors := make([]*httpmsg.HttpRequestResponse, 0, len(allRecords))
	for _, rec := range allRecords {
		if rec.rr != nil {
			survivors = append(survivors, rec.rr)
		}
	}

	localStats.HardDedupRemoved = localStats.TotalDiscovered - len(survivors)
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
			zap.Int("imported", localStats.Imported))
	}

	// Update stats on the source
	d.mu.Lock()
	d.stats.TotalDiscovered += localStats.TotalDiscovered
	d.stats.HardDedupRemoved += localStats.HardDedupRemoved
	d.stats.Imported += localStats.Imported
	for i := range d.stats.AllCodes {
		d.stats.AllCodes[i] += localStats.AllCodes[i]
		d.stats.DedupedCodes[i] += localStats.DedupedCodes[i]
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
