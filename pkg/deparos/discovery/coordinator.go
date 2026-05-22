package discovery

import (
	"context"
	"errors"
	stdhttp "net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sourcegraph/conc"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
	pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"github.com/vigolium/vigolium/pkg/deparos/spider"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
	"github.com/vigolium/vigolium/pkg/deparos/waf"
	"go.uber.org/zap"
)

// PayloadCoordinator manages task execution with N workers using a channel-based pipeline.
//
// Architecture:
//   - Expander goroutine pulls tasks from queue, expands payloads × extensions into WorkItems
//   - WorkItems are sent to workChan (buffered channel)
//   - N workers pull from workChan and execute HTTP requests concurrently
//
// Benefits over previous design:
//   - No task boundary blocking - workers always busy if work available
//   - No mutex contention - channel has built-in synchronization
//   - Early dedup - check request cache before sending to channel
type PayloadCoordinator struct {
	queue       *queue.TaskQueue
	workerCount int
	callbacks   *Callbacks

	// Work channel - all workers pull from this
	workChan chan *WorkItem

	// Metrics
	metrics CoordinatorMetrics

	// Lifecycle
	wg conc.WaitGroup
}

// CoordinatorMetrics tracks execution statistics.
type CoordinatorMetrics struct {
	PayloadsProcessed atomic.Uint64
	TasksCompleted    atomic.Uint64
	RequestsSent      atomic.Uint64
	ActiveWorkers     atomic.Int32
	InFlightItems     atomic.Int32 // Tracks work items being processed
}

// NewPayloadCoordinator creates a new coordinator with callbacks for execution.
func NewPayloadCoordinator(q *queue.TaskQueue, workerCount int, callbacks *Callbacks) *PayloadCoordinator {
	return &PayloadCoordinator{
		queue:       q,
		workerCount: workerCount,
		callbacks:   callbacks,
		workChan:    make(chan *WorkItem, workerCount*2),
	}
}

// Run starts the coordinator and workers. Blocks until context is cancelled.
func (c *PayloadCoordinator) Run(ctx context.Context) error {
	// Start workers
	for i := 0; i < c.workerCount; i++ {
		c.wg.Go(func() {
			c.runWorker(ctx)
		})
	}

	// Run expander (blocks until queue stops or context cancelled)
	c.runExpander(ctx)

	// Close workChan to signal workers to exit
	close(c.workChan)

	// Wait for workers to finish processing remaining items
	c.wg.Wait()

	// Stop the queue when coordinator finishes (ensures WaitForQueues exits)
	c.queue.Stop()

	return ctx.Err()
}

// runExpander pulls tasks from queue and expands them into WorkItems.
func (c *PayloadCoordinator) runExpander(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		taskInfo, err := c.queue.Dequeue(ctx)
		if err != nil {
			if errors.Is(err, queue.ErrQueueStopped) || ctx.Err() != nil {
				return
			}
			continue
		}
		if taskInfo == nil {
			continue
		}

		task, ok := taskInfo.(Task)
		if !ok {
			logger.Error("Dequeued item is not a Task", zap.Any("taskInfo", taskInfo))
			continue
		}

		logger.Info("Starting task expansion",
			zap.String("description", task.Description()),
			zap.String("baseURL", string(task.FullURL())),
			zap.String("extension", task.Extension()),
			zap.Uint8("priority", task.Priority()))

		// CaseSenseDetectionTask: execute inline, skip workChan
		if csTask, ok := task.(*CaseSenseDetectionTask); ok {
			c.executeCaseSenseDetectionTask(ctx, csTask)
			c.metrics.TasksCompleted.Add(1)
			continue
		}

		// JSExtractedRequestTask: execute inline with custom Method/Body handling
		if jsExtTask, ok := task.(*JSExtractedRequestTask); ok {
			c.executeJSExtractedRequestTask(ctx, jsExtTask)
			c.metrics.TasksCompleted.Add(1)
			continue
		}

		// FormSubmissionTask: execute inline with custom Method/Body handling
		if formTask, ok := task.(*FormSubmissionTask); ok {
			c.executeFormSubmissionTask(ctx, formTask)
			c.metrics.TasksCompleted.Add(1)
			continue
		}

		// Expand task into WorkItems
		c.expandTask(ctx, task)
		c.metrics.TasksCompleted.Add(1)

		// Don't log completion if context was cancelled during expansion
		if ctx.Err() != nil {
			return
		}

		logger.Info("Task expansion completed",
			zap.String("description", task.Description()),
			zap.String("baseURL", string(task.FullURL())))
	}
}

// expandTask delegates URL expansion to the task's own Expand method.
// Each task type knows how to build its own URLs correctly.
func (c *PayloadCoordinator) expandTask(ctx context.Context, task Task) {
	_ = task.Expand(ctx, func(url string, depth uint16) {
		c.sendWorkItem(ctx, task, url, depth)
		c.metrics.PayloadsProcessed.Add(1)
	})
}

// sendWorkItem sends a URL to workChan.
// Skips queueing if the URL's prefix has been tripped by the breaker — saves
// an HTTP request and a downstream worker slot for known-dead prefixes.
func (c *PayloadCoordinator) sendWorkItem(
	ctx context.Context,
	task Task,
	urlStr string,
	depth uint16,
) {
	if c.callbacks.PrefixBreaker != nil {
		if u, err := url.Parse(urlStr); err == nil && c.callbacks.PrefixBreaker.IsDead(u) {
			return
		}
	}

	item := &WorkItem{
		URL:       urlStr,
		Depth:     depth,
		Task:      task,
		Callbacks: c.callbacks,
	}

	select {
	case c.workChan <- item:
	case <-ctx.Done():
	}
}

// runWorker pulls WorkItems from channel and executes them.
func (c *PayloadCoordinator) runWorker(ctx context.Context) {
	c.metrics.ActiveWorkers.Add(1)
	defer c.metrics.ActiveWorkers.Add(-1)

	for {
		select {
		case <-ctx.Done():
			return
		case item, ok := <-c.workChan:
			if !ok {
				return
			}
			// Track in-flight items to prevent premature idle detection.
			// This ensures verification requests complete before engine shutdown.
			c.metrics.InFlightItems.Add(1)
			c.executeWorkItem(ctx, item)
			c.metrics.InFlightItems.Add(-1)
		}
	}
}

// executeWorkItem executes a single HTTP request.
func (c *PayloadCoordinator) executeWorkItem(ctx context.Context, item *WorkItem) {
	cb := item.Callbacks

	// Build HTTP request with context for cancellation support
	req, err := pkghttp.NewRequest(item.URL).Context(ctx).Headers(cb.CustomHeaders).Build()
	if err != nil {
		logger.Warn("Failed to build request", zap.String("url", item.URL), zap.Error(err))
		return
	}

	// Send request
	rc, ok := c.sendDiscoveryRequest(ctx, req, item.URL, cb)
	if !ok {
		return
	}
	defer rc.Close()

	// Feed prefix breaker with this probe outcome. Done before any analyzer
	// gating so soft-200 / soft-403 traps still register signal even when the
	// fingerprinter classifies them out.
	if cb.PrefixBreaker != nil {
		resp := rc.Response()
		body := rc.BodyBytes()
		reason, tripped := cb.PrefixBreaker.Observe(req.URL, resp.StatusCode, resp.Header.Get("Content-Type"), int64(len(body)))
		if tripped {
			logger.Info("Prefix breaker tripped — stopping further probes under this prefix",
				zap.String("host", reason.Host),
				zap.String("prefix", reason.Prefix),
				zap.Int("samples", reason.Samples),
				zap.Int("dominant_status", reason.DominantStatus),
				zap.String("dominant_content_type", reason.DominantCT),
				zap.Int64("dominant_length_bucket_lower", reason.DominantLenLower),
				zap.Int("dominant_count", reason.DominantCount))
		}
	}

	// JSFetchTask: custom validation (status 200 + JS content-type)
	// Skip Analyzer + verification - just validate and process
	if jsTask, ok := item.Task.(*JSFetchTask); ok {
		c.executeJSFetchItem(ctx, req, item, jsTask, rc, cb)
		return
	}

	// Handle redirects
	if cb.RedirectDetector != nil {
		c.handleRedirect(ctx, req, item.URL, rc, item.Depth, cb)
	}

	// Analyze response
	found, err := cb.Analyzer.Analyze(ctx, req, rc)
	if err != nil {
		logger.Debug("Analysis failed", zap.String("url", item.URL), zap.Error(err))
		return
	}

	// Skip not found responses entirely
	if !found {
		return
	}

	// Discovery callbacks
	c.triggerDiscoveryCallbacks(item.URL, item.Depth, cb)

	// Result callback
	if cb.OnResult != nil {
		cb.OnResult(&Result{
			URL:     parseURL(item.URL),
			Request: &storage.RequestData{Method: req.Method},
			Metadata: &storage.DiscoveryMetadata{
				FoundBy:   item.Task.FoundByName(),
				Depth:     item.Depth,
				Timestamp: time.Now(),
			},
			rc: rc,
		})
	}
}

// maxJSSize is the maximum size of JS files to process (30MB).
const maxJSSize = 30 * 1024 * 1024

// executeJSFetchItem handles JSFetchTask responses with custom validation.
// Validates status 200 + JS content-type, extracts paths, and calls OnResult.
func (c *PayloadCoordinator) executeJSFetchItem(
	ctx context.Context,
	req *stdhttp.Request,
	item *WorkItem,
	jsTask *JSFetchTask,
	rc *responsechain.ResponseChain,
	cb *Callbacks,
) {
	resp := rc.Response()

	// Parse URL from WorkItem (batched task has multiple URLs)
	jsURL, err := url.Parse(item.URL)
	if err != nil {
		logger.Debug("Failed to parse JS URL",
			zap.String("url", item.URL),
			zap.Error(err))
		return
	}

	// Validate: status 200
	if resp.StatusCode != stdhttp.StatusOK {
		logger.Debug("JS returned non-200 status",
			zap.String("url", item.URL),
			zap.Int("status", resp.StatusCode))
		return
	}

	// Validate: JavaScript content-type
	if !isJavaScriptContentType(resp.Header.Get("Content-Type")) {
		logger.Debug("JS returned non-JS content-type",
			zap.String("url", item.URL),
			zap.String("content-type", resp.Header.Get("Content-Type")))
		return
	}

	// Check if we should skip path extraction (CDN/library files)
	// Still record the finding, but don't parse for paths
	if spider.ShouldSkipJSPathExtraction(jsURL) {
		logger.Debug("Skipping path extraction for CDN/library JS",
			zap.String("url", item.URL))
	} else {
		body := rc.BodyBytes()

		// Size check - skip path extraction for very large files
		if len(body) > maxJSSize {
			logger.Debug("JS too large, skipping path extraction",
				zap.String("url", item.URL),
				zap.Int("size", len(body)))
		} else {
			// Content to pass to linkfinder (default: raw body, may be replaced by CodeRecord)
			contentForLinkfinder := body

			// Run jsscan to extract HTTP requests and transformed code
			if cb.JSScanScanner != nil && cb.JSScanSem != nil {
				// Acquire semaphore
				select {
				case cb.JSScanSem <- struct{}{}:
					defer func() { <-cb.JSScanSem }()
				case <-ctx.Done():
					return
				}

				// Run jsscan
				scanResult, err := cb.JSScanScanner.Scan(ctx, body)
				if err != nil {
					logger.Debug("jsscan failed",
						zap.String("url", item.URL),
						zap.Error(err))
				} else {
					// Store extracted requests with dedup
					newRequests := 0
					if cb.AddExtractedRequest != nil {
						for i := range scanResult.Requests {
							if cb.AddExtractedRequest(&scanResult.Requests[i]) {
								newRequests++
							}
						}
					}

					// Persist to database
					if cb.StoreJSScanRequests != nil && len(scanResult.Requests) > 0 {
						cb.StoreJSScanRequests(jsURL, scanResult.Requests)
					}

					logger.Debug("jsscan extracted requests",
						zap.String("url", item.URL),
						zap.Int("total", len(scanResult.Requests)),
						zap.Int("new", newRequests))

					// Use CodeRecord.Content if available (transformed JS code)
					if scanResult.HasCode() {
						contentForLinkfinder = []byte(scanResult.Code.Content)
						logger.Debug("Using jsscan transformed code for linkfinder",
							zap.String("url", item.URL),
							zap.Int("original_size", len(body)),
							zap.Int("transformed_size", len(contentForLinkfinder)))
					}
				}
			}

			// Extract paths and add to observed collections
			paths := jsTask.ExtractPathsFromContent(contentForLinkfinder)
			namesAdded := 0
			pathsAdded := 0
			for _, path := range paths {
				name, _ := ExtractFilename(path)
				if name != "" && cb.AddObservedName != nil {
					cb.AddObservedName(name)
					namesAdded++
				}
				if path != "" && cb.AddObservedPath != nil {
					cb.AddObservedPath(path)
					pathsAdded++
				}
			}
			logger.Info("JS parsed, paths added to observed collections",
				zap.String("url", item.URL),
				zap.Int("paths_extracted", len(paths)),
				zap.Int("names_added", namesAdded),
				zap.Int("paths_added", pathsAdded))
		}
	}

	// Call OnResult to create finding (always, regardless of path extraction)
	if cb.OnResult != nil {
		cb.OnResult(&Result{
			URL:     jsURL,
			Request: &storage.RequestData{Method: req.Method},
			Metadata: &storage.DiscoveryMetadata{
				FoundBy:   jsTask.FoundByName(),
				Depth:     item.Depth,
				Timestamp: time.Now(),
			},
			rc: rc,
		})
	}
}

// isJavaScriptContentType checks if the content-type indicates JavaScript.
func isJavaScriptContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
}

// triggerDiscoveryCallbacks invokes OnFileDiscovered or OnDirectoryDiscovered.
func (c *PayloadCoordinator) triggerDiscoveryCallbacks(urlStr string, depth uint16, cb *Callbacks) {
	if strings.HasSuffix(urlStr, "/") {
		if cb.OnDirectoryDiscovered != nil {
			if err := cb.OnDirectoryDiscovered(urlStr, depth); err != nil {
				logger.Warn("Directory callback error", zap.String("url", urlStr), zap.Error(err))
			}
		}
	} else {
		if cb.OnFileDiscovered != nil {
			if err := cb.OnFileDiscovered(urlStr, depth); err != nil {
				logger.Warn("File callback error", zap.String("url", urlStr), zap.Error(err))
			}
		}
	}
}

// executeCaseSenseDetectionTask executes a case sensitivity detection task inline.
func (c *PayloadCoordinator) executeCaseSenseDetectionTask(ctx context.Context, task *CaseSenseDetectionTask) {
	callback := task.Callback()
	if callback == nil {
		logger.Warn("CaseSenseDetectionTask has no callback")
		return
	}

	logger.Debug("Executing case sensitivity detection task",
		zap.String("url", task.DiscoveredURL().String()),
		zap.Bool("isDirectory", task.IsDirectory()))

	callback(ctx, task.DiscoveredURL(), task.Sample(), task.IsDirectory())
}

// executeJSExtractedRequestTask executes all variants of extracted HTTP requests inline.
// Handles GET, POST (json), POST (form), and other method variants.
func (c *PayloadCoordinator) executeJSExtractedRequestTask(ctx context.Context, task *JSExtractedRequestTask) {
	cb := c.callbacks
	variants := task.GenerateAllVariants()

	logger.Info("Executing JS extracted request task",
		zap.String("directory", task.DirURL().Path),
		zap.Int("variant_count", len(variants)))

	for _, variant := range variants {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if variant.URL == "" {
			continue
		}

		// Scope check - skip out-of-scope URLs
		if cb.ScopeChecker != nil {
			variantURL, parseErr := url.Parse(variant.URL)
			if parseErr == nil && !cb.ScopeChecker.IsInScope(variantURL) {
				logger.Debug("Skipping out-of-scope JS extracted request",
					zap.String("url", variant.URL))
				continue
			}
		}

		// Dedup check with method and body (for variants with same URL but different bodies)
		if cb.RequestCache.IsSeen(variant.Method, variant.URL, variant.Body) {
			continue
		}

		// Build HTTP request with method, body, and content-type
		reqBuilder := pkghttp.NewRequest(variant.URL).
			Context(ctx).
			Method(variant.Method).
			Headers(cb.CustomHeaders)

		if variant.Body != "" {
			reqBuilder.BodyString(variant.Body)
		}

		req, err := reqBuilder.Build()
		if err != nil {
			logger.Debug("Failed to build JS extracted request",
				zap.String("url", variant.URL),
				zap.String("method", variant.Method),
				zap.Error(err))
			continue
		}

		// Set Content-Type header if specified
		if variant.ContentType != "" && variant.Body != "" {
			req.Header.Set("Content-Type", variant.ContentType)
		}

		// Send request with tracking
		rc, err := c.sendTrackedRequest(ctx, req, variant.URL, cb)
		if err != nil {
			logger.Debug("JS extracted request failed",
				zap.String("url", variant.URL),
				zap.String("method", variant.Method),
				zap.Error(err))
			continue
		}

		c.metrics.RequestsSent.Add(1)

		// Analyze response
		found, err := cb.Analyzer.Analyze(ctx, req, rc)
		if err != nil {
			logger.Debug("JS extracted request analysis failed",
				zap.String("url", variant.URL),
				zap.String("method", variant.Method),
				zap.Error(err))
			rc.Close()
			continue
		}

		if !found {
			rc.Close()
			continue
		}

		// Discovery callbacks
		c.triggerDiscoveryCallbacks(variant.URL, task.Depth(), cb)

		// Result callback
		if cb.OnResult != nil {
			cb.OnResult(&Result{
				URL: parseURL(variant.URL),
				Request: &storage.RequestData{
					Method: variant.Method,
					Body:   []byte(variant.Body),
				},
				Metadata: &storage.DiscoveryMetadata{
					FoundBy:   task.FoundByName(),
					Depth:     task.Depth(),
					Timestamp: time.Now(),
				},
				rc: rc,
			})
		}

		rc.Close()
	}
}

// executeFormSubmissionTask executes all form submission requests inline.
// Forms are already fully encoded by FormExtractor (GET params in URL, POST body encoded).
func (c *PayloadCoordinator) executeFormSubmissionTask(ctx context.Context, task *FormSubmissionTask) {
	cb := c.callbacks
	variants := task.GenerateAllVariants()

	logger.Info("Executing form submission task",
		zap.String("source", task.SourceURL().Path),
		zap.Int("variant_count", len(variants)))

	for _, variant := range variants {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if variant.URL == "" {
			continue
		}

		// Scope check - skip out-of-scope URLs
		if cb.ScopeChecker != nil {
			variantURL, parseErr := url.Parse(variant.URL)
			if parseErr == nil && !cb.ScopeChecker.IsInScope(variantURL) {
				logger.Debug("Skipping out-of-scope form submission",
					zap.String("url", variant.URL))
				continue
			}
		}

		// Dedup check with method and body (for form variants with same URL but different bodies)
		if cb.RequestCache.IsSeen(variant.Method, variant.URL, variant.Body) {
			continue
		}

		// Build HTTP request with method, body, and content-type
		reqBuilder := pkghttp.NewRequest(variant.URL).
			Context(ctx).
			Method(variant.Method).
			Headers(cb.CustomHeaders)

		if variant.Body != "" {
			reqBuilder.BodyString(variant.Body)
		}

		req, err := reqBuilder.Build()
		if err != nil {
			logger.Debug("Failed to build form submission request",
				zap.String("url", variant.URL),
				zap.String("method", variant.Method),
				zap.Error(err))
			continue
		}

		// Set Content-Type header if specified
		if variant.ContentType != "" {
			req.Header.Set("Content-Type", variant.ContentType)
		}

		// Send request with tracking
		rc, err := c.sendTrackedRequest(ctx, req, variant.URL, cb)
		if err != nil {
			logger.Debug("Form submission request failed",
				zap.String("url", variant.URL),
				zap.String("method", variant.Method),
				zap.Error(err))
			continue
		}

		c.metrics.RequestsSent.Add(1)

		// Analyze response
		found, err := cb.Analyzer.Analyze(ctx, req, rc)
		if err != nil {
			logger.Debug("Form submission analysis failed",
				zap.String("url", variant.URL),
				zap.String("method", variant.Method),
				zap.Error(err))
			rc.Close()
			continue
		}

		if !found {
			rc.Close()
			continue
		}

		// Discovery callbacks
		c.triggerDiscoveryCallbacks(variant.URL, task.Depth(), cb)

		// Result callback
		if cb.OnResult != nil {
			cb.OnResult(&Result{
				URL: parseURL(variant.URL),
				Request: &storage.RequestData{
					Method: variant.Method,
					Body:   []byte(variant.Body),
				},
				Metadata: &storage.DiscoveryMetadata{
					FoundBy:   task.FoundByName(),
					Depth:     task.Depth(),
					Timestamp: time.Now(),
				},
				rc: rc,
			})
		}

		rc.Close()
	}
}

// errWAFBlocked is returned when WAF blocks the request.
var errWAFBlocked = errors.New("request blocked by WAF")

// sendTrackedRequest sends HTTP request with error tracking and WAF detection.
// Caller handles dedup. Caller MUST close ResponseChain on success.
// Returns errWAFBlocked if WAF blocks the request.
func (c *PayloadCoordinator) sendTrackedRequest(
	ctx context.Context,
	req *stdhttp.Request,
	urlStr string,
	cb *Callbacks,
) (*responsechain.ResponseChain, error) {
	rc, err := cb.HTTPClient.Send(ctx, req)
	if err != nil {
		if cb.ErrorTracker != nil {
			cb.ErrorTracker.RecordError(err)
		}
		return nil, err
	}

	if cb.ErrorTracker != nil {
		cb.ErrorTracker.RecordSuccess()
	}

	// WAF block detection
	if cb.WAFBlockTracker != nil && cb.WAFDetector != nil {
		result := cb.WAFDetector.Detect(rc)
		if result != nil && result.IsBlocked {
			blockInfo := &waf.BlockInfo{
				WAFType:    result.WAFType,
				StatusCode: rc.Response().StatusCode,
				URL:        urlStr,
				Timestamp:  time.Now(),
				Indicators: result.Indicators,
			}
			cb.WAFBlockTracker.RecordBlock(blockInfo)
			rc.Close()
			return nil, errWAFBlocked
		}
		cb.WAFBlockTracker.RecordSuccess()
	}

	return rc, nil
}

// sendDiscoveryRequest sends an HTTP request for discovery tasks with dedup, error tracking, WAF detection, and metrics.
// Returns (ResponseChain, ok). If ok is false, caller should return early.
// CRITICAL: Caller MUST call rc.Close() when done with the ResponseChain.
func (c *PayloadCoordinator) sendDiscoveryRequest(
	ctx context.Context,
	req *stdhttp.Request,
	urlStr string,
	cb *Callbacks,
) (*responsechain.ResponseChain, bool) {
	// Dedup - single point of truth for all HTTP requests
	if cb.RequestCache.IsSeen(req.Method, urlStr, "") {
		return nil, false
	}

	rc, err := c.sendTrackedRequest(ctx, req, urlStr, cb)
	if err != nil {
		if !errors.Is(err, errWAFBlocked) {
			logger.Debug("HTTP request failed", zap.String("url", urlStr), zap.Error(err))
		}
		return nil, false
	}

	c.metrics.RequestsSent.Add(1)
	return rc, true
}

// handleRedirect handles trailing slash redirects.
func (c *PayloadCoordinator) handleRedirect(
	ctx context.Context,
	req *stdhttp.Request,
	urlStr string,
	rc *responsechain.ResponseChain,
	depth uint16,
	cb *Callbacks,
) {
	resp := rc.Response()
	redirectInfo, err := cb.RedirectDetector.DetectRedirect(resp, urlStr, depth, cb.MaxDepth)
	if err != nil {
		return
	}
	if !redirectInfo.IsRedirect {
		return
	}

	logger.Debug("Redirect detected",
		zap.String("url", urlStr),
		zap.Int("status", redirectInfo.StatusCode),
		zap.String("location", redirectInfo.LocationHeader))

	// Scope check - skip out-of-scope redirect targets
	if cb.ScopeChecker != nil {
		redirectURL, parseErr := url.Parse(redirectInfo.ResolvedLocation)
		if parseErr == nil && !cb.ScopeChecker.IsInScope(redirectURL) {
			logger.Debug("Skipping out-of-scope redirect target",
				zap.String("original", urlStr),
				zap.String("redirect", redirectInfo.ResolvedLocation))
			return
		}
	}

	// Handle trailing slash redirect
	if redirectInfo.IsTrailingSlash && redirectInfo.ShouldMarkDirectory {
		if cb.OnDirectoryDiscovered != nil {
			directoryURL := normalizeRedirectForDiscovery(urlStr, redirectInfo.ResolvedLocation)
			if err := cb.OnDirectoryDiscovered(directoryURL, depth); err != nil {
				logger.Warn("Directory callback error for redirect", zap.String("url", directoryURL), zap.Error(err))
			}
		}
	}

	// Handle non-trailing-slash redirects
	if !redirectInfo.IsTrailingSlash && redirectInfo.IsSameHost {
		// Analyze redirect response to filter soft-404 wildcards (e.g., all paths returning identical 302)
		found, err := cb.Analyzer.Analyze(ctx, req, rc)
		if err != nil {
			logger.Debug("Redirect analysis failed", zap.String("url", urlStr), zap.Error(err))
			return
		}
		if !found {
			logger.Debug("Redirect filtered as soft-404",
				zap.String("url", urlStr),
				zap.Int("status", redirectInfo.StatusCode))
			return
		}

		if redirectInfo.ExtractedDirPath != "" && cb.OnDirectoryDiscovered != nil {
			origParsed, parseErr := url.Parse(urlStr)
			if parseErr == nil {
				dirURL := origParsed.Scheme + "://" + origParsed.Host + redirectInfo.ExtractedDirPath
				logger.Debug("Queueing directory from redirect",
					zap.String("original", urlStr),
					zap.String("redirect", redirectInfo.ResolvedLocation),
					zap.String("directory", dirURL))
				_ = cb.OnDirectoryDiscovered(dirURL, depth)
			}
		}

		if redirectInfo.ExtractedFilename != "" && cb.OnFileDiscovered != nil {
			fileURL := normalizeRedirectForDiscovery(urlStr, redirectInfo.ResolvedLocation)
			_ = cb.OnFileDiscovered(fileURL, depth)
		}

		// Create Result for non-trailing-slash redirect
		if cb.OnResult != nil {
			cb.OnResult(&Result{
				URL:     parseURL(redirectInfo.ResolvedLocation),
				Request: &storage.RequestData{Method: req.Method},
				Metadata: &storage.DiscoveryMetadata{
					FoundBy:   "redirect",
					Depth:     depth,
					Timestamp: time.Now(),
				},
				rc: rc,
			})
		}
	}

	// Follow redirect to confirm directory exists
	if redirectInfo.IsTrailingSlash {
		targetReq, err := pkghttp.NewRequest(redirectInfo.ResolvedLocation).Headers(cb.CustomHeaders).Context(ctx).Build()
		if err != nil {
			return
		}

		targetRc, ok := c.sendDiscoveryRequest(ctx, targetReq, redirectInfo.ResolvedLocation, cb)
		if !ok {
			return
		}
		defer targetRc.Close()

		found, err := cb.Analyzer.Analyze(ctx, targetReq, targetRc)
		if err != nil {
			return
		}

		if !found {
			return
		}

		if cb.OnResult != nil {
			cb.OnResult(&Result{
				URL:     parseURL(redirectInfo.ResolvedLocation),
				Request: &storage.RequestData{Method: targetReq.Method},
				Metadata: &storage.DiscoveryMetadata{
					FoundBy:   "redirect",
					Depth:     depth,
					Timestamp: time.Now(),
				},
				rc: targetRc,
			})
		}
	}
}

// normalizeRedirectForDiscovery handles cross-origin redirects.
// Preserves query params from redirect target for accurate testing.
func normalizeRedirectForDiscovery(originalURL, redirectURL string) string {
	origParsed, err := url.Parse(originalURL)
	if err != nil {
		return redirectURL
	}

	redirParsed, err := url.Parse(redirectURL)
	if err != nil {
		return redirectURL
	}

	if origParsed.Scheme != redirParsed.Scheme || origParsed.Host != redirParsed.Host {
		normalized := *origParsed
		normalized.Path = redirParsed.Path
		normalized.RawQuery = redirParsed.RawQuery // Preserve query params from redirect

		logger.Debug("Cross-origin redirect normalized",
			zap.String("original", originalURL),
			zap.String("redirect", redirectURL),
			zap.String("normalized", normalized.String()))

		return normalized.String()
	}

	return redirectURL
}

// IsIdle returns true if no work is pending and no items are being processed.
func (c *PayloadCoordinator) IsIdle() bool {
	return len(c.workChan) == 0 && c.metrics.InFlightItems.Load() == 0
}

// Metrics returns coordinator metrics.
func (c *PayloadCoordinator) Metrics() *CoordinatorMetrics {
	return &c.metrics
}

// Stop signals the coordinator to stop.
// The queue.Stop() will cause runExpander to exit, which triggers workChan close,
// which causes workers to exit. Run() will wait for workers via wg.Wait().
func (c *PayloadCoordinator) Stop() {
	c.queue.Stop()
}

// CurrentTask returns nil - task tracking removed in channel-based design.
func (c *PayloadCoordinator) CurrentTask() Task {
	return nil
}

// Helper functions for result conversion
func parseURL(urlStr string) *url.URL {
	u, _ := url.Parse(urlStr)
	return u
}
