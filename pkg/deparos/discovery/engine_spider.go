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

	// Process script tags with jsscan for HTML responses.
	// This extracts HTTP requests from inline <script> content.
	e.processScriptTagsWithJSScan(e.ctx, baseURL, rc)

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

	if len(result.Links) == 0 {
		return
	}

	logger.Debug("Links extracted from response",
		zap.String("url", baseURL.String()),
		zap.Int("count", len(result.Links)),
		zap.Uint16("parent_depth", parentDepth))

	// Collect and validate all links
	batch := e.collectValidatedLinks(result.Links, parentDepth)
	if batch == nil {
		return
	}

	// Create single batched task
	e.createSpiderBatchTask(batch)
}

// collectValidatedLinks validates all extracted links and returns a batch.
// Handles observed name/extension extraction and breadcrumb processing.
// NOTE: Spider tasks do NOT increment depth and have no maxDepth limit.
func (e *Engine) collectValidatedLinks(links []*url.URL, parentDepth uint16) *SpiderLinkBatch {
	var files, dirs [][]byte
	var baseURL []byte

	for _, link := range links {
		// Extract and track observed names/extensions using unified metadata extractor.
		// Spider links are trusted sources - they come from actual URLs in the response.
		// Pass depth=0 here; extension task generation is handled separately below.
		meta := e.applyFileMetadata(link.Path, 0)

		// Generate dynamic extension tasks for newly discovered extensions during spidering
		if meta.Extension != "" {
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

		// Set base URL from first valid link
		if baseURL == nil {
			baseURL = []byte(link.Scheme + "://" + link.Host)
		}

		// Build path with query params for HTTP request
		// Path-only operations (recursion, depth, etc.) use link.Path directly above
		pathWithQuery := link.Path
		if link.RawQuery != "" {
			pathWithQuery += "?" + link.RawQuery
		}

		// Categorize as file or directory based on path (not query)
		if len(link.Path) > 0 && link.Path[len(link.Path)-1] == '/' {
			dirs = append(dirs, []byte(pathWithQuery))
		} else {
			files = append(files, []byte(pathWithQuery))
		}
	}

	if len(files) == 0 && len(dirs) == 0 {
		return nil
	}

	return &SpiderLinkBatch{
		Files:       files,
		Directories: dirs,
		Depth:       parentDepth, // Pass as-is, NOT incremented
		BaseURL:     baseURL,
	}
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

// queueJSFetch creates a single batched JSFetchTask for all JavaScript URLs.
// JS files are fetched and parsed to extract API paths
// that get added to observedPaths and observedNames collections.
//
// CDN domains and known library files are skipped entirely
// as they don't contain application-specific endpoints.
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

		// Skip CDN domains and library files entirely
		if spider.ShouldSkipJSPathExtraction(jsURL) {
			continue
		}

		// Normalize URL for dedup: scheme://host/path (strip query params)
		normalizedURL := strings.ToLower(jsURL.Scheme) + "://" +
			strings.ToLower(jsURL.Host) + jsURL.Path

		// URL-level dedup across all batches
		if e.seenJSURLs != nil && e.seenJSURLs.IsSeen(normalizedURL) {
			logger.Debug("JS URL already seen, skipping",
				zap.String("url", jsURL.String()))
			continue
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
