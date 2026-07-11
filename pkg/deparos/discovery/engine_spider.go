package discovery

import (
	"net/url"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/internal/dedup"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"github.com/vigolium/vigolium/pkg/deparos/spider"
	"github.com/vigolium/vigolium/pkg/deparos/wordlist"
	"go.uber.org/zap"
)

// maxFormSubmissionsPerStructure is the maximum number of form submissions
// allowed per unique endpoint + field structure combination.
const maxFormSubmissionsPerStructure int32 = 3

// pathDepth calculates depth from URL path segments.
// /api/ = 1, /api/v1/ = 2, /api/v1/users/ = 3
// Empty or root path "/" returns 0.
func pathDepth(path string) uint16 {
	path = strings.Trim(path, "/")
	if path == "" {
		return 0
	}
	return uint16(strings.Count(path, "/") + 1)
}

// SpiderLinkBatch holds validated spider links ready for task creation.
type SpiderLinkBatch struct {
	Files       [][]byte // File paths (no trailing slash)
	Directories [][]byte // Directory paths (with trailing slash)
	Depth       uint16
	BaseURL     []byte // scheme://host
}

// extractLinks extracts URLs from HTTP response using spider coordinator.
// Discovered links are collected, validated, and batched into a single task.
func (e *Engine) extractLinks(baseURL *url.URL, rc *responsechain.ResponseChain, parentDepth uint16) {
	if e.spiderCoordinator == nil {
		return
	}

	// Extract words from response body for wordlist augmentation
	e.extractWordsFromResponse(rc)

	// Process script tags with jstangle for HTML responses.
	// This extracts HTTP requests from inline <script> content.
	e.processScriptTagsWithJSTangle(e.ctx, baseURL, rc)

	// Harvest Next.js route manifests (_buildManifest.js / _ssgManifest.js) for
	// the full page-route table and concrete pre-rendered paths, which are often
	// not linked anywhere in the HTML.
	e.queueNextJSManifests(baseURL, rc, parentDepth)

	// Harvest SPA/PWA asset manifests + service workers (Angular ngsw.json, CRA
	// asset-manifest.json, Nuxt builds, generic service workers + Workbox
	// precache). These enumerate the lazy-loaded chunks that are built from a
	// runtime chunk map and so are invisible to static link extraction — only the
	// framework runtime or a service worker (neither of which discovery runs)
	// would otherwise fetch them.
	e.queueSPAAssetManifests(baseURL, rc, parentDepth)

	result, err := e.spiderCoordinator.Extract(e.ctx, baseURL, rc)
	if err != nil {
		logger.Debug("Link extraction failed",
			zap.String("url", baseURL.String()),
			zap.Error(err))
		return
	}

	// Store spider links to database
	if len(result.DiscoveredLinks) > 0 {
		e.storeSpiderLinks(baseURL, result.DiscoveredLinks)
	}

	// Queue JS files for path extraction
	// These are processed by spider workers and populate observed collections
	if len(result.JSURLs) > 0 {
		e.queueJSFetch(result.JSURLs, parentDepth)
	}

	// Queue form requests for testing
	if len(result.FormRequests) > 0 {
		e.queueFormSubmission(result.FormRequests, baseURL, parentDepth)
	}

	if len(result.DiscoveredLinks) == 0 {
		return
	}

	logger.Debug("Links extracted from response",
		zap.String("url", baseURL.String()),
		zap.Int("count", len(result.DiscoveredLinks)),
		zap.Uint16("parent_depth", parentDepth))

	// Collect and validate all links (DiscoveredLinks carry the source type used
	// to gate server-side extension confirmation). Links are grouped by origin so
	// each batch is replayed against its own host — see collectValidatedLinks.
	batches := e.collectValidatedLinks(result.DiscoveredLinks, parentDepth)

	// Create one batched task set per origin.
	for _, batch := range batches {
		e.createSpiderBatchTask(batch)
	}
}

// extensionConfirmAllowed reports whether a spider link from the given source
// may *eagerly* confirm a server-side extension for wordlist fuzzing.
//
// This gate only applies in legacy (non-ConfirmRequired) mode. Under
// ConfirmRequired — the default — link-time confirmation is disabled entirely
// and the decision is made on the served response (see collectValidatedLinks /
// OnFileDiscovered), so a genuine reference is no longer treated as proof.
//
// Two guards keep this from firing on noise:
//
//   - SPA gate: on a JS-shell SPA (Next.js/React/Angular/Vue/Svelte) the server
//     returns the same index shell for every path, so a path bearing .php/.aspx/
//     .do/… is almost never a real route. Every confirmation candidate is a
//     server-side extension, so on a SPA we never confirm one from a link.
//   - Source gate: only links the application genuinely references count (see
//     LinkSourceType.IsGenuineReference); URL-like strings scavenged from JS/HTML
//     body text are not proof the server serves that extension.
func (e *Engine) extensionConfirmAllowed(src spider.LinkSourceType) bool {
	return !e.startURLIsModernApp && src.IsGenuineReference()
}

// collectValidatedLinks validates all extracted links and returns one batch per
// origin (scheme://host). Handles observed name/extension extraction and
// breadcrumb processing.
//
// Links are grouped by origin because the spider scope admits sibling
// subdomains, so a single page can legitimately reference links on multiple
// hosts (e.g. api.example.com/users and admin.example.com/panel). Batching all
// paths under one BaseURL — historically the first link's host — would replay
// every path against whichever host appeared first, silently requesting paths
// against the wrong host. One batch per origin keeps each path bound to its own
// host.
//
// NOTE: Spider tasks do NOT increment depth and have no maxDepth limit.
func (e *Engine) collectValidatedLinks(links []*spider.DiscoveredLink, parentDepth uint16) []*SpiderLinkBatch {
	// originBatch accumulates the files/directories for a single origin.
	type originBatch struct {
		files, dirs [][]byte
	}
	batches := make(map[string]*originBatch)
	var order []string // first-seen origin order → deterministic task creation

	// Pre-pass: record every directory that directly holds a content-hash
	// fingerprinted bundle before breadcrumb processing (below) recurses into any
	// of them, so the skip decision is independent of link order within the batch.
	for _, dl := range links {
		if dl != nil && dl.URL != nil {
			e.recordHashedAssetParent(dl.URL)
		}
	}

	for _, dl := range links {
		if dl == nil || dl.URL == nil {
			continue
		}
		link := dl.URL

		// Under ConfirmRequired (the default) a spider link never confirms a
		// server-side extension: a path like /citation.cfm or /sharer.php in an
		// <a href> — even a genuine same-host one — is no proof the server serves
		// it. Confirmation is deferred to the served path (OnFileDiscovered, gated
		// on scope + the analyzer's non-soft-404 verdict). Names/paths are still
		// harvested. Legacy mode keeps the old source-type-gated eager behaviour.
		eagerConfirm := !e.config.Extensions.ConfirmRequired && e.extensionConfirmAllowed(dl.SourceType)

		// Extract and track observed names/extensions using unified metadata extractor.
		// Pass depth=0 here; extension task generation is handled separately below.
		meta := e.applyFileMetadata(link.Path, 0, eagerConfirm)

		// Legacy-mode only: generate dynamic extension tasks for newly discovered
		// extensions during spidering. Under ConfirmRequired this whole branch is
		// off (eagerConfirm is false) — the served path drives confirmation + fuzz.
		if eagerConfirm && meta.Extension != "" {
			wasNew := e.addObservedExtensionIfNew(meta.Extension)
			linkDepth := pathDepth(link.Path)
			if wasNew && e.config.Extensions.TestObserved && linkDepth > 0 {
				logger.Info("New extension discovered during spidering, generating dynamic tasks",
					zap.String("extension", meta.Extension),
					zap.Uint16("depth", linkDepth))
				e.generateObservedExtensionTasks(meta.Extension, linkDepth)
			}
		}

		// Deduplicate spider links across all batches using normalized URL
		// to handle case differences (WWW vs www, HTTP vs https)
		normalizedURL := dedup.NormalizeURL(link.String())
		if e.seenDiscoveredURLs != nil && e.seenDiscoveredURLs.IsSeen(normalizedURL) {
			continue
		}

		// Validate link (no depth check for spider)
		// Out of scope
		if !e.spiderScope.IsInScope(link) {
			logger.Debug("Skipping out-of-scope link", zap.String("url", link.String()))
			continue
		}

		// Extract breadcrumbs (triggers recursive brute force)
		e.processSpiderPathBreadcrumbs(link, parentDepth)

		// Resolve the batch for this link's own origin (never re-based onto a
		// different sibling host).
		origin := link.Scheme + "://" + link.Host
		b := batches[origin]
		if b == nil {
			b = &originBatch{}
			batches[origin] = b
			order = append(order, origin)
		}

		// Build path with query params for HTTP request
		// Path-only operations (recursion, depth, etc.) use link.Path directly above
		pathWithQuery := link.Path
		if link.RawQuery != "" {
			pathWithQuery += "?" + link.RawQuery
		}

		// Categorize as file or directory based on path (not query)
		if len(link.Path) > 0 && link.Path[len(link.Path)-1] == '/' {
			b.dirs = append(b.dirs, []byte(pathWithQuery))
		} else {
			b.files = append(b.files, []byte(pathWithQuery))
		}
	}

	if len(order) == 0 {
		return nil
	}

	result := make([]*SpiderLinkBatch, 0, len(order))
	for _, origin := range order {
		b := batches[origin]
		if len(b.files) == 0 && len(b.dirs) == 0 {
			continue
		}
		result = append(result, &SpiderLinkBatch{
			Files:       b.files,
			Directories: b.dirs,
			Depth:       parentDepth, // Pass as-is, NOT incremented
			BaseURL:     []byte(origin),
		})
	}
	return result
}

// createSpiderBatchTask creates a single task from batched spider links.
func (e *Engine) createSpiderBatchTask(batch *SpiderLinkBatch) {
	// Create file task if we have files
	if len(batch.Files) > 0 {
		task := e.factory.CreateSpiderBatchTask(batch.BaseURL, batch.Files, false, batch.Depth)
		if task != nil {
			e.AddTask(task)
			logger.Debug("Created spider batch file task",
				zap.Int("count", len(batch.Files)),
				zap.Uint16("depth", batch.Depth))
		}
	}

	// Create directory task if we have directories
	if len(batch.Directories) > 0 {
		task := e.factory.CreateSpiderBatchTask(batch.BaseURL, batch.Directories, true, batch.Depth)
		if task != nil {
			e.AddTask(task)
			logger.Debug("Created spider batch directory task",
				zap.Int("count", len(batch.Directories)),
				zap.Uint16("depth", batch.Depth))
		}
	}
}

// vendorJSFetchBudget caps how many vendor/CDN/library JS bundles are fetched
// per scan for jstangle endpoint extraction. These bundles are analyzed for the
// real API calls they make (their path→wordlist amplification is suppressed
// separately in the coordinator), but a site that self-hosts many framework
// files must not flood the JS fetcher — hence a bounded, scan-lifetime budget.
const vendorJSFetchBudget = 50

// admitVendorJSFetch reports whether another vendor/CDN/library JS bundle may be
// fetched under the per-scan asset budget. Safe for concurrent callers.
func (e *Engine) admitVendorJSFetch() bool {
	return e.vendorJSFetched.Add(1) <= vendorJSFetchBudget
}

// queueJSFetch creates a single batched JSFetchTask for all JavaScript URLs.
// JS files are fetched and parsed to extract API paths
// that get added to observedPaths and observedNames collections.
//
// Vendor/CDN/library assets are NOT skipped entirely: they are still fetched for
// jstangle endpoint extraction (the API calls a bundle makes are real regardless
// of where it's hosted — the coordinator suppresses only their path→wordlist
// amplification), but under a bounded per-scan asset budget and excluded from the
// observed-JS-dir wordlist sweep. Previously they were dropped here, which made
// the coordinator's vendor-analysis branch dead code.
//
// URLs are deduplicated by normalized form (scheme://host/path, query params stripped)
// before batching to avoid fetching the same file multiple times.
func (e *Engine) queueJSFetch(jsURLs []*url.URL, _ uint16) {
	if len(jsURLs) == 0 {
		return
	}

	var validURLs []string

	for _, jsURL := range jsURLs {
		// Scope check - skip out-of-scope JS URLs
		if !e.spiderScope.IsInScope(jsURL) {
			logger.Debug("Skipping out-of-scope JS URL", zap.String("url", jsURL.String()))
			continue
		}

		// Normalize URL for dedup: scheme://host/path (strip query params)
		normalizedURL := strings.ToLower(jsURL.Scheme) + "://" +
			strings.ToLower(jsURL.Host) + jsURL.Path

		// URL-level dedup across all batches (before consuming any budget).
		if e.seenJSURLs != nil && e.seenJSURLs.IsSeen(normalizedURL) {
			logger.Debug("JS URL already seen, skipping",
				zap.String("url", jsURL.String()))
			continue
		}

		if spider.ShouldSkipJSPathExtraction(jsURL) {
			// Vendor/CDN/library asset: still fetched for jstangle endpoint
			// extraction, but capped by a separate asset budget so a site that
			// self-hosts many framework files can't flood the JS fetcher. Not fed
			// to the observed-JS-dir wordlist sweep.
			if !e.admitVendorJSFetch() {
				logger.Debug("Vendor JS asset budget exhausted, skipping",
					zap.String("url", jsURL.String()))
				continue
			}
		} else {
			// First-party JS: remember the app's real JS mount directory for the
			// JS-bundle sweep (e.g. /js/, /assets/js/) so it probes there too.
			e.recordObservedJSDir(jsURL)
		}

		// Add full URL (with query if present) for actual fetch
		validURLs = append(validURLs, jsURL.String())
	}

	if len(validURLs) == 0 {
		return
	}

	// Create single batched task
	task := NewJSFetchTask(&JSFetchTaskConfig{
		JSURLs: validURLs,
	})

	if task != nil && e.AddTask(task) {
		logger.Debug("Created batched JS fetch task",
			zap.Int("count", len(validURLs)))
	}
}

// processSpiderPathBreadcrumbs extracts parent directories from spider-discovered path
// and triggers OnDirectoryDiscovered for each with correct depth based on path level.
// No HTTP probe needed - spider finding a file proves all parent directories exist.
//
// Example: Spider finds /webmail/program/js/common.min.js
// → Extract ["/webmail/", "/webmail/program/", "/webmail/program/js/"]
// → Trigger OnDirectoryDiscovered for each with depth = path level
// → Each triggers recursive brute force task generation
func (e *Engine) processSpiderPathBreadcrumbs(fileURL *url.URL, _ uint16) {
	breadcrumbs := ExtractDirectoryBreadcrumbs(fileURL.Path)
	if len(breadcrumbs) == 0 {
		return
	}

	baseURL := fileURL.Scheme + "://" + fileURL.Host

	for i, dirPath := range breadcrumbs {
		dirURL := baseURL + dirPath
		// Depth = path level (index + 1): /api/ = 1, /api/v1/ = 2, etc.
		dirDepth := uint16(i + 1)
		_ = e.OnDirectoryDiscovered(dirURL, dirDepth)
	}
}

// queueFormSubmission creates FormSubmissionTask for extracted form requests.
// Forms are deduplicated globally - same form from different pages only submits once.
func (e *Engine) queueFormSubmission(forms []*spider.FormRequest, sourceURL *url.URL, _ uint16) {
	if len(forms) == 0 {
		return
	}

	// Filter forms that haven't been seen yet
	var newForms []*spider.FormRequest
	for _, form := range forms {
		if form.URL == nil {
			continue
		}

		// Scope check - skip out-of-scope form actions
		if !e.spiderScope.IsInScope(form.URL) {
			logger.Debug("Skipping out-of-scope form action",
				zap.String("action", form.URL.String()),
				zap.String("source", sourceURL.String()))
			continue
		}

		// Compute structural hash from sorted input field names (not values).
		// This groups forms with same endpoint + same fields, regardless of option values.
		inputNames := make([]string, 0, len(form.Inputs))
		for _, input := range form.Inputs {
			inputNames = append(inputNames, input.Name)
		}
		sort.Strings(inputNames)
		formHash := dedup.HashFormStructure(form.URL.String(), form.Method, inputNames)

		if !e.formStructureCounter.IncrementAndCheck(formHash, maxFormSubmissionsPerStructure) {
			logger.Debug("Form structure limit reached, skipping",
				zap.String("action", form.URL.String()),
				zap.String("method", form.Method))
			continue
		}

		newForms = append(newForms, form)
	}

	// Always store all forms to database for persistence
	// Database uses OnConflict DoNothing for its own dedup
	e.storeFormRequests(sourceURL, forms)

	// Skip task creation if no new forms
	if len(newForms) == 0 {
		logger.Debug("All forms already seen, skipping task creation",
			zap.String("source", sourceURL.Path),
			zap.Int("total_forms", len(forms)))
		return
	}

	// Capture filtered forms for closure
	formsSlice := newForms

	// FormSubmissionTask has Priority 2 but depth = 0 ensures it runs in Band 0
	task := NewFormSubmissionTask(&FormSubmissionTaskConfig{
		SourceURL: sourceURL,
		Depth:     0,
		GetFormRequests: func() []*spider.FormRequest {
			return formsSlice
		},
	})

	if e.AddTask(task) {
		logger.Debug("Created form submission task",
			zap.String("source", sourceURL.String()),
			zap.Int("new_forms", len(newForms)),
			zap.Int("total_forms", len(forms)))
	}
}

// extractWordsFromResponse extracts words from HTTP response body
// and adds them to the observedNames collection for wordlist augmentation.
// Uses content-type aware preprocessing to extract meaningful tokens.
func (e *Engine) extractWordsFromResponse(rc *responsechain.ResponseChain) {
	if e.wordlistExtractor == nil {
		return
	}

	// Get body from response chain
	body := rc.BodyBytes()
	if len(body) == 0 {
		return
	}

	// Get content-type from response headers
	resp := rc.Response()
	if resp == nil {
		return
	}
	contentType := resp.Header.Get("Content-Type")

	// Skip binary content types
	if !wordlist.ShouldProcess(contentType) {
		return
	}

	var extractedCount int
	err := e.wordlistExtractor.ExtractBytes(e.ctx, body, contentType, func(token *wordlist.Token) {
		e.AddObservedName(token.Value)
		extractedCount++
	})

	if err != nil {
		logger.Debug("Wordlist extraction failed",
			zap.String("content_type", contentType),
			zap.Error(err))
		return
	}

	if extractedCount > 0 {
		logger.Debug("Words extracted from response body",
			zap.String("content_type", contentType),
			zap.Int("count", extractedCount))
	}
}
