package discovery

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
	pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
	"go.uber.org/zap"
)

// initSession prepares engine for discovery.
func (e *Engine) initSession() error {
	if e.config.Target.StartURL == "" {
		return fmt.Errorf("start URL required")
	}

	targetURL, err := url.Parse(e.config.Target.StartURL)
	if err != nil {
		return fmt.Errorf("invalid start URL: %w", err)
	}

	// Extract host components as observed names for wordlist
	// e.g., "brand.example.com" → adds "brand", "example"
	// Use trusted frequency since host components are reliable sources.
	hostComponents := ExtractHostComponents(targetURL.Host)
	for _, component := range hostComponents {
		e.AddObservedNameTrusted(component)
	}
	if len(hostComponents) > 0 {
		logger.Debug("Added host components to observed names",
			zap.Strings("components", hostComponents))
	}

	// Burp _x.java:1039-1042 - Always read from sitemap at startup
	logger.Info("Copying existing URLs from sitemap")
	if err := e.copyFromSiteMap(); err != nil {
		logger.Warn("Failed to copy from sitemap", zap.Error(err))
	}

	// Load extractions from database (jsscan requests for task generation)
	if err := e.loadExtractionsFromDB(); err != nil {
		logger.Warn("Failed to load extractions from database", zap.Error(err))
	}

	// Re-extract words from stored response bodies if -extract-words is enabled
	if e.wordlistExtractor != nil && e.config.Filenames.WordlistExtraction.Enabled {
		if err := e.extractWordsFromStoredResponses(); err != nil {
			logger.Warn("Failed to extract words from stored responses", zap.Error(err))
		}
	}

	// Burp _x.java:1034-1038 - Probe start URL before scanning
	logger.Info("Probing start URL", zap.String("url", targetURL.String()))
	if err := e.probeStartURL(targetURL); err != nil {
		return fmt.Errorf("start URL probe failed: %w", err)
	}

	// Learn baseline fingerprints for common extensions
	if !e.config.Engine.SkipFingerprintLearning {
		logger.Info("Learning baseline fingerprints for soft 404 detection")
		if err := e.learnBaselineFingerprints(targetURL); err != nil {
			logger.Warn("Fingerprint learning failed, continuing without baseline", zap.Error(err))
		}
		// Pre-warm cache for common paths/extensions beyond root to reduce
		// inline learning pauses during the main discovery phase.
		if e.fpCache != nil {
			e.fpCache.PreWarm(e.ctx, targetURL)
		}
	} else {
		logger.Debug("Skipping fingerprint learning (SkipFingerprintLearning=true)")
	}

	logger.Info("Session initialization complete")
	return nil
}

// learnBaselineFingerprints learns 404 signatures for common file extensions at root.
func (e *Engine) learnBaselineFingerprints(baseURL *url.URL) error {
	return e.learnBaselineFingerprintsForDirectory(baseURL)
}

// learnBaselineFingerprintsForDirectory learns 404 signatures for a specific directory.
// Called at startup for root, and when discovering new directories before bruteforce.
func (e *Engine) learnBaselineFingerprintsForDirectory(dirURL *url.URL) error {
	// Normalize directory path
	dirPath := dirURL.Path
	if dirPath == "" {
		dirPath = "/"
	}
	if dirPath[len(dirPath)-1] != '/' {
		dirPath += "/"
	}

	// CRITICAL: "" (no extension) MUST be learned FIRST
	var extensions []string
	extensions = append(extensions, "")

	// Add custom extensions if configured
	if e.config.Extensions.TestCustom && len(e.config.Extensions.CustomList) > 0 {
		for _, ext := range e.config.Extensions.CustomList {
			if ext != "" && ext[0] != '.' {
				ext = "." + ext
			}
			extensions = append(extensions, ext)
		}
	}

	logger.Debug("Starting fingerprint learning for directory",
		zap.String("path", dirPath),
		zap.Int("extension_count", len(extensions)))

	var learnedCount atomic.Int32

	// Learn "" (no extension) synchronously first — it MUST complete before others
	if len(extensions) > 0 {
		ext := extensions[0] // always ""
		key := fingerprint.CacheKey{
			Host:      dirURL.Host,
			Path:      dirPath,
			Extension: ext,
		}
		if _, ok := e.fpCache.Get(key); !ok {
			learnURL := *dirURL
			learnURL.Path = dirPath
			_, err := e.fpCache.LearnAndCache(e.ctx, key, &learnURL)
			if err != nil {
				logger.Debug("Failed to learn fingerprint for extension",
					zap.String("path", dirPath),
					zap.String("extension", ext),
					zap.Error(err))
			} else {
				learnedCount.Add(1)
			}
		}
	}

	// Learn remaining extensions in parallel with bounded concurrency
	if len(extensions) > 1 {
		sem := make(chan struct{}, 3)
		var wg sync.WaitGroup

		for _, ext := range extensions[1:] {
			ext := ext // capture loop variable

			key := fingerprint.CacheKey{
				Host:      dirURL.Host,
				Path:      dirPath,
				Extension: ext,
			}

			// Skip if already learned
			if _, ok := e.fpCache.Get(key); ok {
				continue
			}

			wg.Add(1)
			sem <- struct{}{} // acquire semaphore slot
			go func() {
				defer wg.Done()
				defer func() { <-sem }() // release semaphore slot

				learnURL := *dirURL
				learnURL.Path = dirPath

				_, err := e.fpCache.LearnAndCache(e.ctx, key, &learnURL)
				if err != nil {
					logger.Debug("Failed to learn fingerprint for extension",
						zap.String("path", dirPath),
						zap.String("extension", ext),
						zap.Error(err))
					return
				}
				learnedCount.Add(1)

				// Brief delay between requests to avoid overwhelming the server
				time.Sleep(200 * time.Millisecond)
			}()
		}

		wg.Wait()
	}

	logger.Info("Fingerprint learning complete for directory",
		zap.String("path", dirPath),
		zap.Int32("learned", learnedCount.Load()),
		zap.Int("total", len(extensions)))

	return nil
}

// learnBaselineForDirectory learns baseline fingerprint for a discovered directory.
// Only learns "" extension (no extension) to minimize HTTP requests.
// Called before creating recursive bruteforce tasks.
func (e *Engine) learnBaselineForDirectory(dirURL *url.URL) error {
	// Normalize directory path
	dirPath := dirURL.Path
	if dirPath == "" {
		dirPath = "/"
	}
	if dirPath[len(dirPath)-1] != '/' {
		dirPath += "/"
	}

	key := fingerprint.CacheKey{
		Host:      dirURL.Host,
		Path:      dirPath,
		Extension: "", // Only learn no-extension baseline
	}

	// Skip if already learned
	if _, ok := e.fpCache.Get(key); ok {
		logger.Debug("Baseline already learned for directory",
			zap.String("path", dirPath))
		return nil
	}

	logger.Info("Learning baseline fingerprint for directory",
		zap.String("path", dirPath))

	// Create URL for learning
	learnURL := *dirURL
	learnURL.Path = dirPath

	_, err := e.fpCache.LearnAndCache(e.ctx, key, &learnURL)
	if err != nil {
		return fmt.Errorf("learn baseline for %s: %w", dirPath, err)
	}

	return nil
}

// probeStartURL validates the start URL with an HTTP GET request.
func (e *Engine) probeStartURL(targetURL *url.URL) error {
	req, err := pkghttp.NewRequest(targetURL.String()).Headers(e.config.Engine.CustomHeaders).Build()
	if err != nil {
		return fmt.Errorf("failed to create probe request: %w", err)
	}

	logger.Debug("Sending probe request", zap.String("url", targetURL.String()))
	rc, err := e.httpClient.Send(e.ctx, req)
	if err != nil {
		return fmt.Errorf("probe request failed: %w", err)
	}
	defer rc.Close()

	resp := rc.Response()
	body := rc.BodyBytes()

	found, err := e.analyzer.Analyze(e.ctx, req, rc)
	if err != nil {
		return fmt.Errorf("response analysis failed: %w", err)
	}

	logger.Info("Probe request completed",
		zap.String("url", targetURL.String()),
		zap.Int("status_code", resp.StatusCode),
		zap.Bool("found", found),
		zap.Int("body_size", len(body)))

	// Extract links and names from probe response
	logger.Debug("Extracting links from probe response")
	e.extractLinks(targetURL, rc, 0)

	return nil
}

// generateInitialTasks creates first wave of discovery tasks.
func (e *Engine) generateInitialTasks() {
	logger.Info("Generating initial discovery tasks")

	// Parse StartURL and strip query params for wordlist/observed tasks.
	// Query params should NOT be included in bruteforce base URLs.
	parsedStart, err := url.Parse(e.config.Target.StartURL)
	if err != nil {
		logger.Error("Failed to parse start URL", zap.Error(err))
		return
	}
	baseURLNoQuery := &url.URL{
		Scheme: parsedStart.Scheme,
		Host:   parsedStart.Host,
		Path:   parsedStart.Path,
	}
	baseURL := []byte(baseURLNoQuery.String())
	depth := uint16(0)

	tasks, err := e.factory.CreateInitialTasks(baseURL, depth)
	if err != nil {
		logger.Error("Failed to create initial tasks", zap.Error(err))
		return
	}

	logger.Debug("Enqueuing initial tasks", zap.Int("count", len(tasks)))
	e.addTasks(tasks)

	// Create observed name tasks (Burp: _x.java:917-952)
	// Note: CreateObservedNameTasks internally extracts scheme://host and path from baseURL
	observedTasks := e.factory.CreateObservedNameTasks(baseURL, depth, e.observedNames, e.observedExtensions)
	logger.Debug("Enqueuing observed name tasks", zap.Int("count", len(observedTasks)))
	e.addTasks(observedTasks)

	// Create observed directory tasks (Burp: _x.java:928-932)
	// Extract scheme://host and path for the new API
	schemeHost := extractSchemeHost(string(baseURL))
	dirPath := extractPathFromURL(string(baseURL))
	observedDirTasks := e.factory.CreateObservedDirectoryTasks([]byte(schemeHost), dirPath, depth, e.observedNames)
	logger.Debug("Enqueuing observed directory tasks", zap.Int("count", len(observedDirTasks)))
	e.addTasks(observedDirTasks)

	// Create observed path tasks (segments already in observedNames, handled by existing tasks)
	var observedPathTasks []Task
	if e.config.Filenames.UseObservedPaths {
		observedPathTasks = e.factory.CreateObservedPathTasks(baseURL, depth, e.observedPaths)
		logger.Debug("Enqueuing observed path tasks", zap.Int("count", len(observedPathTasks)))
		e.addTasks(observedPathTasks)
	}

	// Create JS extracted request task for root URL
	if e.jsscanScanner != nil {
		targetURL, err := url.Parse(e.config.Target.StartURL)
		if err == nil {
			jsExtTask := e.factory.CreateJSExtractedRequestTask(
				targetURL,
				e.GetExtractedRequests,
				depth,
			)
			if jsExtTask != nil {
				e.AddTask(jsExtTask)
				logger.Debug("Added JS extracted request task for root URL")
			}
		}
	}

	// Create fuzz wordlist task (Priority 12: runs after all other wordlists)
	if e.config.Filenames.Wordlists.HasFuzzWordlist() {
		// Build URL template: use StartURL as-is if it contains FUZZ,
		// otherwise auto-append /FUZZ to the URL.
		fuzzTemplate := e.config.Target.StartURL
		if !strings.Contains(fuzzTemplate, "FUZZ") {
			fuzzTemplate = strings.TrimRight(fuzzTemplate, "/") + "/FUZZ"
		}

		fuzzTask, err := e.factory.CreateFuzzTask(
			fuzzTemplate,
			e.config.Filenames.Wordlists.FuzzWordlistPath,
			depth,
		)
		if err != nil {
			logger.Error("Failed to create fuzz task", zap.Error(err))
		} else {
			e.AddTask(fuzzTask)
			logger.Debug("Added fuzz wordlist task",
				zap.String("template", fuzzTemplate))
		}
	}

	// Malformed path probe (Priority 10: runs against start URL)
	if e.config.Filenames.EnableMalformedPathProbe {
		probeTask := e.factory.CreateMalformedPathProbeTask([]byte(schemeHost), []byte(dirPath), depth)
		if probeTask != nil {
			e.AddTask(probeTask)
			logger.Debug("Added malformed path probe task",
				zap.String("path", dirPath))
		}
	}

	logger.Info("Initial task generation complete",
		zap.Int("total_tasks", len(tasks)+len(observedTasks)+len(observedDirTasks)+len(observedPathTasks)))
}

// copyFromSiteMap populates observed collections from existing sitemap.
func (e *Engine) copyFromSiteMap() error {
	if e.storage == nil {
		return nil
	}

	// Load from observed table (with frequencies preserved from previous runs)
	if err := e.loadObservedFromDB(); err != nil {
		logger.Warn("Failed to load observed data from DB", zap.Error(err))
		// Continue - not fatal, we can still extract from sitemap
	}

	// Walk existing nodes for additional extraction
	return extractFilenamesFromSitemap(e)
}

// loadObservedFromDB loads previously stored observed data with frequencies.
func (e *Engine) loadObservedFromDB() error {
	repo := e.storage.Observed()
	if repo == nil {
		return nil
	}

	hostname := e.storage.Hostname()
	if hostname == "" {
		return nil
	}

	items, err := repo.GetByHostname(hostname)
	if err != nil {
		return err
	}

	if len(items) == 0 {
		return nil
	}

	var namesCount, extsCount, pathsCount, filesCount int

	for _, item := range items {
		switch storage.ObservedType(item.Type) {
		case storage.ObservedTypeName:
			// Sanitize name to clean legacy data that may contain query params
			name := sanitizeObservedName(item.Value)
			if name != "" {
				e.observedNames.AddWithFrequency([]byte(name), item.Frequency)
				namesCount++
			}
		case storage.ObservedTypeExtension:
			e.observedExtensions.AddWithFrequency([]byte(item.Value), item.Frequency)
			// Also mark as seen in seenExtensions to prevent duplicate task generation
			if e.seenExtensions != nil {
				e.seenExtensions.IsSeen(item.Value)
			}
			extsCount++
		case storage.ObservedTypePath:
			e.observedPaths.AddWithFrequency([]byte(item.Value), item.Frequency)
			pathsCount++
		case storage.ObservedTypeFile:
			e.observedFiles.AddWithFrequency([]byte(item.Value), item.Frequency)
			filesCount++
		}
	}

	logger.Info("Loaded observed data from database",
		zap.Int("names", namesCount),
		zap.Int("extensions", extsCount),
		zap.Int("paths", pathsCount),
		zap.Int("files", filesCount))

	return nil
}

// extractWordsFromStoredResponses re-extracts words from all stored response bodies.
func (e *Engine) extractWordsFromStoredResponses() error {
	if e.storage == nil || e.wordlistExtractor == nil {
		return nil
	}

	logger.Info("Re-extracting words from stored response bodies")

	count := extractWordsFromResponses(e)

	logger.Info("Word extraction from stored responses complete",
		zap.Int("words_extracted", count))

	return nil
}

// fetchRobotsTxt fetches and parses robots.txt to discover initial URLs.
// Non-fatal: logs warning on failure, does not stop discovery.
func (e *Engine) fetchRobotsTxt(baseURL *url.URL) {
	robotsURL := *baseURL
	robotsURL.Path = "/robots.txt"
	robotsURL.RawQuery = ""
	robotsURL.Fragment = ""

	req, err := pkghttp.NewRequest(robotsURL.String()).
		Headers(e.config.Engine.CustomHeaders).
		Build()
	if err != nil {
		logger.Debug("Failed to build robots.txt request", zap.Error(err))
		return
	}

	logger.Debug("Fetching robots.txt", zap.String("url", robotsURL.String()))
	rc, err := e.httpClient.Send(e.ctx, req)
	if err != nil {
		logger.Debug("robots.txt fetch failed", zap.Error(err))
		return
	}
	defer rc.Close()

	resp := rc.Response()

	// Skip non-success responses
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Debug("robots.txt returned non-success status",
			zap.Int("status", resp.StatusCode))
		return
	}

	// Extract links using spider coordinator (runs RobotsTxtParser)
	e.extractLinks(&robotsURL, rc, 0)
	logger.Info("robots.txt parsed", zap.String("url", robotsURL.String()))
}
