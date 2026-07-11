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
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
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
	PayloadsProcessed    atomic.Uint64
	TasksCompleted       atomic.Uint64
	RequestsSent         atomic.Uint64
	ActiveWorkers        atomic.Int32
	InFlightItems        atomic.Int32 // Tracks work items being processed
	InlineInFlight       atomic.Int32 // Tracks tasks executing inline in the expander (replay/form/case-sense/expand)
	JSReplayExact        atomic.Uint64
	JSReplayConservative atomic.Uint64
	JSReplaySucceeded    atomic.Uint64
	JSReplayFailed       atomic.Uint64
	JSReplayDeduped      atomic.Uint64
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

		// Account for the entire per-task handling (inline execution OR expansion)
		// as in-flight work. Inline task types send requests directly from this
		// goroutine and never touch InFlightItems, and there is a gap between
		// dequeue and the first workChan push during expansion — without this
		// counter, quiescence detection (IsIdle) could observe a false "idle" mid
		// task and stop the scan early. See IsIdle / WaitForQueues.
		c.metrics.InlineInFlight.Add(1)
		c.handleTask(ctx, task)
		c.metrics.InlineInFlight.Add(-1)

		if ctx.Err() != nil {
			return
		}
	}
}

// handleTask expands or inline-executes a single dequeued task. Inline task
// types (case-sensitivity detection, JS-extracted replay, form submission) run
// entirely in the expander goroutine and send HTTP requests directly; all other
// tasks are expanded into WorkItems dispatched to the worker pool.
func (c *PayloadCoordinator) handleTask(ctx context.Context, task Task) {
	logger.Info("Starting task expansion",
		zap.String("description", task.Description()),
		zap.String("baseURL", string(task.FullURL())),
		zap.String("extension", task.Extension()),
		zap.Uint8("priority", task.Priority()))

	switch t := task.(type) {
	case *CaseSenseDetectionTask:
		// CaseSenseDetectionTask: execute inline, skip workChan
		c.executeCaseSenseDetectionTask(ctx, t)
		c.metrics.TasksCompleted.Add(1)
		return
	case *JSExtractedRequestTask:
		// JSExtractedRequestTask: execute inline with custom Method/Body handling
		c.executeJSExtractedRequestTask(ctx, t)
		c.metrics.TasksCompleted.Add(1)
		return
	case *FormSubmissionTask:
		// FormSubmissionTask: execute inline with custom Method/Body handling
		c.executeFormSubmissionTask(ctx, t)
		c.metrics.TasksCompleted.Add(1)
		return
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

	// Discovery callbacks. This is the generic brute-force path (wordlist/fuzz/
	// observed-recombination/ext-variant/numeric tasks), so confirmExt is keyed on
	// the task's provenance — guessed paths must not confirm an extension off a
	// catch-all 200.
	foundBy := item.Task.FoundByName()
	c.triggerDiscoveryCallbacks(item.URL, item.Depth, cb, foundByConfirmsExtension(foundBy))

	// Result callback
	if cb.OnResult != nil {
		cb.OnResult(&Result{
			URL:     parseURL(item.URL),
			Request: &storage.RequestData{Method: req.Method},
			Metadata: &storage.DiscoveryMetadata{
				FoundBy:   foundBy,
				Depth:     item.Depth,
				Timestamp: time.Now(),
			},
			rc: rc,
		})
	}
}

// maxJSSize is the maximum size of JS files to process (50MB).
const maxJSSize = 50 * 1024 * 1024

// hasJavaScriptExtension reports whether the URL path looks like a JavaScript
// file by extension. Used as a fallback when the server serves a bundle with a
// non-JS content-type (e.g. text/plain or application/octet-stream).
func hasJavaScriptExtension(u *url.URL) bool {
	p := strings.ToLower(u.Path)
	return strings.HasSuffix(p, ".js") ||
		strings.HasSuffix(p, ".mjs") ||
		strings.HasSuffix(p, ".cjs")
}

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

	// Validate: status — accept 200/203 (success) and 304 (cached). 304 normally
	// carries no body and is filtered by the empty-body check below; it is
	// allowed here only so a spec-violating server that does return a body still
	// gets parsed. Other statuses are dropped.
	if resp.StatusCode != stdhttp.StatusOK &&
		resp.StatusCode != stdhttp.StatusNonAuthoritativeInfo &&
		resp.StatusCode != stdhttp.StatusNotModified {
		logger.Debug("JS returned non-success status",
			zap.String("url", item.URL),
			zap.Int("status", resp.StatusCode))
		return
	}

	// Validate: JavaScript or JSON content-type, with a .js/.json-extension
	// fallback for assets served as text/plain or application/octet-stream. JSON
	// is accepted because the JS-bundle sweep also harvests sibling config/data
	// files (config.json, settings.json, …): jstangle no-ops on them, but
	// linkfinder still extracts embedded paths and the file is recorded as an
	// http_record (so secret-scanning and later phases see its body).
	ct := resp.Header.Get("Content-Type")
	isSourceMap := strings.HasSuffix(strings.ToLower(jsURL.Path), ".map")
	if !isJavaScriptContentType(ct) && !isJSONContentType(ct) &&
		!hasJavaScriptExtension(jsURL) && !hasJSONExtension(jsURL) && !isSourceMap {
		logger.Debug("JS-fetch target is neither JavaScript nor JSON",
			zap.String("url", item.URL),
			zap.String("content-type", ct))
		return
	}

	body := rc.BodyBytes()

	// CDN/library bundles still get jstangle endpoint extraction (the API calls
	// they make are real regardless of where the JS is hosted); only their
	// path→wordlist extraction is suppressed to avoid flooding the bruteforcer.
	skipPathExtraction := spider.ShouldSkipJSPathExtraction(jsURL)

	switch {
	case len(body) == 0:
		logger.Debug("JS response had empty body, skipping parse",
			zap.String("url", item.URL))
	case len(body) > maxJSSize:
		logger.Debug("JS too large, skipping parse",
			zap.String("url", item.URL),
			zap.Int("size", len(body)))
	case isSourceMap:
		if cb.ProcessSourceMap != nil && len(body) <= maxSourceMapBytes {
			cb.ProcessSourceMap(ctx, jsURL, body)
		}
	default:
		// Content to pass to linkfinder (default: raw body, may be replaced by CodeRecord)
		contentForLinkfinder := body

		// Run jstangle to extract HTTP requests and transformed code (always,
		// even for CDN-hosted bundles).
		if cb.JSTangleService != nil {
			// SourceMap/X-SourceMap headers have the same policy as comment facts.
			for _, headerName := range []string{"SourceMap", "X-SourceMap"} {
				if reference := strings.TrimSpace(resp.Header.Get(headerName)); reference != "" && cb.ProcessAssetFacts != nil {
					cb.ProcessAssetFacts(ctx, item.URL, body, []jstangle.AssetReferenceFact{{
						Kind: "assetReference", AssetType: string(AssetSourceMap),
						URL:             jstangle.ValueTemplate{Rendered: reference, Static: true},
						ParentSourceURL: item.URL, Provenance: jstangle.Provenance{Extractor: "source-map-header", Confidence: "high"},
					}})
				}
			}
			// Run through the shared broker; it owns weighted admission and cache.
			options := jstangle.ScanOptions{Profile: jstangle.ProfileDiscovery, SourceURL: item.URL}
			if cb.JSTangleOptions != nil {
				options = cb.JSTangleOptions(jstangle.ProfileDiscovery, item.URL)
			}
			scanResult, err := cb.JSTangleService.ScanWithOptions(ctx, body, options)
			if err != nil {
				logger.Debug("jstangle failed",
					zap.String("url", item.URL),
					zap.Error(err))
			} else {
				// Retain typed source/provenance when protocol v2 facts are present.
				newRequests := 0
				if len(scanResult.RequestFacts) > 0 && cb.AddRequestFact != nil {
					for i := range scanResult.RequestFacts {
						if cb.AddRequestFact(item.URL, scanResult.RequestFacts[i]) {
							newRequests++
						}
					}
				} else if cb.AddExtractedRequest != nil {
					for i := range scanResult.Requests {
						if cb.AddExtractedRequest(&scanResult.Requests[i]) {
							newRequests++
						}
					}
				}

				// Persist to database
				if cb.StoreJSTangleFacts != nil && len(scanResult.RequestFacts) > 0 {
					cb.StoreJSTangleFacts(jsURL, scanResult.RequestFacts)
				} else if cb.StoreJSTangleRequests != nil && len(scanResult.Requests) > 0 {
					cb.StoreJSTangleRequests(jsURL, scanResult.Requests)
				}

				logger.Debug("jstangle extracted requests",
					zap.String("url", item.URL),
					zap.Int("total", len(scanResult.Requests)),
					zap.Int("new", newRequests))

				// Use CodeRecord.Content if available (transformed JS code)
				if scanResult.HasCode() {
					contentForLinkfinder = []byte(scanResult.Code.Content)
					logger.Debug("Using jstangle transformed code for linkfinder",
						zap.String("url", item.URL),
						zap.Int("original_size", len(body)),
						zap.Int("transformed_size", len(contentForLinkfinder)))
				}
				if cb.ProcessAssetFacts != nil && len(scanResult.AssetFacts) > 0 {
					cb.ProcessAssetFacts(ctx, item.URL, body, scanResult.AssetFacts)
				}
				if cb.ProcessJSTangleCapabilities != nil {
					cb.ProcessJSTangleCapabilities(item.URL, scanResult)
				}
			}
		}

		if skipPathExtraction {
			logger.Debug("Skipping path→wordlist extraction for CDN/library JS (endpoints still extracted)",
				zap.String("url", item.URL))
		} else {
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

	// SPA/PWA asset manifest or service worker: parse its asset list (lazy
	// webpack chunks, workers) and fan the listed files back through the JSFetch
	// pipeline so each is fetched and recorded. These chunk filenames are built
	// at runtime and so are invisible to link extraction — the manifest is the
	// only place they appear literally. Dispatches per framework by URL shape.
	if !isSourceMap {
		harvestSPAManifest(jsURL, body, cb)
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

// isJSONContentType checks if the content-type indicates JSON (application/json,
// text/json, application/ld+json, …). "javascript" does not contain "json".
func isJSONContentType(ct string) bool {
	return strings.Contains(strings.ToLower(ct), "json")
}

// hasJSONExtension reports whether the URL path ends in .json.
func hasJSONExtension(u *url.URL) bool {
	return strings.HasSuffix(strings.ToLower(u.Path), ".json")
}

// triggerDiscoveryCallbacks invokes OnFileDiscovered or OnDirectoryDiscovered.
// confirmExt (derived from the task's provenance via foundByConfirmsExtension)
// tells OnFileDiscovered whether the served extension may be trusted as proof the
// server runs that stack — true only for genuine application references.
func (c *PayloadCoordinator) triggerDiscoveryCallbacks(urlStr string, depth uint16, cb *Callbacks, confirmExt bool) {
	if strings.HasSuffix(urlStr, "/") {
		if cb.OnDirectoryDiscovered != nil {
			if err := cb.OnDirectoryDiscovered(urlStr, depth); err != nil {
				logger.Warn("Directory callback error", zap.String("url", urlStr), zap.Error(err))
			}
		}
	} else {
		if cb.OnFileDiscovered != nil {
			if err := cb.OnFileDiscovered(urlStr, depth, confirmExt); err != nil {
				logger.Warn("File callback error", zap.String("url", urlStr), zap.Error(err))
			}
		}
	}
}

// foundByConfirmsExtension reports whether a discovery's provenance is a genuine
// application reference whose *served* extension can be trusted as proof the
// server runs that stack — and may therefore confirm the extension and trigger a
// wordlist fuzz for hidden <word>.<ext> files.
//
// Only references the application itself emitted qualify: a spider <a href>, a
// JS-extracted request, a form action, a server-issued redirect target. Every
// brute-forced provenance — the fuzz wordlist, the dir/file wordlists, observed-
// name recombinations, extension variants, numeric fuzzing — is a *guess*. On a
// catch-all / SPA-shell / over-permissive host those guesses return a non-soft-404
// 200 for paths the server never serves (e.g. a fuzz.txt /axis2/…/HappyAxis.jsp
// answered 200 by a Next.js shell), so letting them confirm an extension is
// circular: the fuzzer's own guess bootstraps more fuzzing of that extension.
// Such paths are still harvested for names/paths — only the extension
// confirmation is withheld. The allow-list is conservative: an unknown/new task
// type defaults to a guess (no confirmation) rather than risking a false confirm
// — so a renamed FoundByName fails safe (a missed confirm, never a false one).
//
// This is the served-path (FoundBy-keyed) sibling of Engine.extensionConfirmAllowed,
// which gates the legacy link-time path on spider.LinkSourceType.IsGenuineReference.
func foundByConfirmsExtension(foundBy string) bool {
	switch foundBy {
	case "spider", "js-extracted", "jsfetch", "form", "redirect":
		return true
	default:
		return false
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
	foundBy := task.FoundByName()

	logger.Info("Executing JS extracted request task",
		zap.String("directory", task.DirURL().Path),
		zap.Int("variant_count", len(variants)))

	// GenerateAllVariants destructively claimed these templates from the pending
	// set. Track each claimed template and requeue any that never reach a
	// definitive outcome (a genuine send failure, or an early cancellation) so a
	// later end-of-scan flush round retries it instead of losing the work. A
	// template settles once any of its variants is handled definitively: a
	// response, a scope skip, a cache-dedup hit, an empty URL, or a deterministic
	// build failure — only transient send failures and cancellation leave it
	// unsettled.
	type replayRef struct{ sourceURL, templateID string }
	claimed := make(map[string]replayRef, len(variants))
	settled := make(map[string]struct{}, len(variants))
	templateKey := func(v RequestVariant) (string, bool) {
		if v.TemplateID == "" || v.SourceURL == "" {
			return "", false
		}
		return v.SourceURL + "\x00" + v.TemplateID, true
	}
	markSettled := func(v RequestVariant) {
		if k, ok := templateKey(v); ok {
			settled[k] = struct{}{}
		}
	}
	for _, variant := range variants {
		if k, ok := templateKey(variant); ok {
			claimed[k] = replayRef{variant.SourceURL, variant.TemplateID}
		}
	}
	defer func() {
		if cb.RequeueReplayTemplate == nil || len(settled) >= len(claimed) {
			return
		}
		requeued := 0
		for k, ref := range claimed {
			if _, isSettled := settled[k]; isSettled {
				continue
			}
			if cb.RequeueReplayTemplate(ref.sourceURL, ref.templateID) {
				requeued++
			}
		}
		if requeued > 0 {
			logger.Debug("Requeued unsent JS replay templates for retry",
				zap.Int("count", requeued),
				zap.String("directory", task.DirURL().Path))
		}
	}()

	for _, variant := range variants {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if variant.URL == "" {
			markSettled(variant)
			continue
		}

		// Scope check - skip out-of-scope URLs
		if cb.ScopeChecker != nil {
			variantURL, parseErr := url.Parse(variant.URL)
			if parseErr == nil && !cb.ScopeChecker.IsInScope(variantURL) {
				logger.Debug("Skipping out-of-scope JS extracted request",
					zap.String("url", variant.URL))
				markSettled(variant) // out-of-scope is definitive; a retry won't help
				continue
			}
		}

		// Replay identity includes safe semantic headers as well as method/URL/body.
		dedupBody := variant.Body + "\x00" + strings.Join(variant.Headers, "\x00")
		if cb.RequestCache.IsSeen(variant.Method, variant.URL, dedupBody) {
			c.metrics.JSReplayDeduped.Add(1)
			markSettled(variant) // already sent elsewhere; definitive
			continue
		}
		if variant.ReplayTier == "exact" {
			c.metrics.JSReplayExact.Add(1)
		} else {
			c.metrics.JSReplayConservative.Add(1)
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
			c.metrics.JSReplayFailed.Add(1)
			logger.Debug("Failed to build JS extracted request",
				zap.String("url", variant.URL),
				zap.String("method", variant.Method),
				zap.Error(err))
			markSettled(variant) // build failure is deterministic; a retry won't help
			continue
		}

		// Set Content-Type header if specified
		if variant.ContentType != "" && variant.Body != "" {
			if req.Header.Get("Content-Type") == "" {
				req.Header.Set("Content-Type", variant.ContentType)
			}
		}
		for _, header := range variant.Headers {
			name, value := splitHeader(header)
			// Explicit scan/auth configuration always wins over literals recovered
			// from a public bundle.
			if name != "" && req.Header.Get(name) == "" {
				req.Header.Set(name, value)
			}
		}

		// Send request with tracking. A send failure (network/WAF/timeout) is left
		// unsettled so the template is requeued for a retry round; every other
		// outcome below is definitive.
		rc, err := c.sendTrackedRequest(ctx, req, variant.URL, cb)
		if err != nil {
			c.metrics.JSReplayFailed.Add(1)
			logger.Debug("JS extracted request failed",
				zap.String("url", variant.URL),
				zap.String("method", variant.Method),
				zap.Error(err))
			continue
		}

		markSettled(variant) // got a response; definitive regardless of analysis outcome
		c.metrics.RequestsSent.Add(1)
		c.metrics.JSReplaySucceeded.Add(1)

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

		// Discovery callbacks. This task's provenance is a genuine application
		// reference, so a served extension confirms (keyed on provenance for
		// self-documentation rather than a bare true).
		c.triggerDiscoveryCallbacks(variant.URL, task.Depth(), cb, foundByConfirmsExtension(foundBy))

		// Result callback
		if cb.OnResult != nil {
			cb.OnResult(&Result{
				URL: parseURL(variant.URL),
				Request: &storage.RequestData{
					Method:  variant.Method,
					Headers: headerSliceToMap(variant.Headers),
					Body:    []byte(variant.Body),
				},
				Metadata: &storage.DiscoveryMetadata{
					FoundBy:   foundBy,
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
	foundBy := task.FoundByName()

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

		// Discovery callbacks. This task's provenance is a genuine application
		// reference, so a served extension confirms (keyed on provenance for
		// self-documentation rather than a bare true).
		c.triggerDiscoveryCallbacks(variant.URL, task.Depth(), cb, foundByConfirmsExtension(foundBy))

		// Result callback
		if cb.OnResult != nil {
			cb.OnResult(&Result{
				URL: parseURL(variant.URL),
				Request: &storage.RequestData{
					Method: variant.Method,
					Body:   []byte(variant.Body),
				},
				Metadata: &storage.DiscoveryMetadata{
					FoundBy:   foundBy,
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
			// A redirect only *confirms* a server-side extension when the server
			// points us at a genuinely different resource. A path-preserving
			// bounce — the host 3xx'ing /x.php back to /x.php (scheme upgrade,
			// auth/cookie round-trip, host/trailing-slash normalization) — fires
			// at the gateway before any handler runs, so it is no proof the server
			// executes that extension. The per-path-distinct Location also slips
			// past the wildcard soft-404 filter above, so on a catch-all/SPA
			// gateway that bounces every path to itself this would otherwise
			// confirm (and wordlist-fuzz) every guessed stack extension at once.
			// Names/paths are still harvested; only the extension confirmation is
			// withheld.
			confirmExt := foundByConfirmsExtension("redirect") &&
				!redirectPreservesPath(urlStr, fileURL)
			_ = cb.OnFileDiscovered(fileURL, depth, confirmExt)
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

// redirectPreservesPath reports whether a redirect merely sends the request back
// to the same path it asked for (ignoring scheme, host and query, tolerating a
// trailing slash). Such a self-bounce — an HTTP→HTTPS upgrade, an auth/cookie
// round-trip, host or trailing-slash normalization — is not a discovery of a new
// resource, so its extension must not be trusted to confirm a server-side stack.
func redirectPreservesPath(originalURL, redirectTargetURL string) bool {
	o, err := url.Parse(originalURL)
	if err != nil {
		return false
	}
	r, err := url.Parse(redirectTargetURL)
	if err != nil {
		return false
	}
	trim := func(p string) string {
		if len(p) > 1 {
			return strings.TrimRight(p, "/")
		}
		return p
	}
	return trim(o.Path) == trim(r.Path)
}

// IsIdle returns true if no work is pending and no items are being processed.
// This accounts for both worker-pool items (InFlightItems) and the expander's
// own inline task execution (InlineInFlight) so quiescence isn't declared while
// a JS replay / form / case-sense task is mid-flight in the expander goroutine.
func (c *PayloadCoordinator) IsIdle() bool {
	return len(c.workChan) == 0 &&
		c.metrics.InFlightItems.Load() == 0 &&
		c.metrics.InlineInFlight.Load() == 0
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
