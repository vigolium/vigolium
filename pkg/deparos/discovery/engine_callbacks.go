package discovery

import (
	"bytes"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/internal/dedup"
	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/module"
	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
	pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
	"go.uber.org/zap"
)

const (
	// maxConsecutiveDuplicateSegments defines the maximum allowed number of
	// identical consecutive path segments. Paths with more than this many
	// consecutive duplicates are rejected to prevent infinite recursion.
	// Example: 2 means /backup/backup/ is OK, /backup/backup/backup/ is rejected.
	maxConsecutiveDuplicateSegments = 2
)

// OnDirectoryDiscovered handles directory discovery during scan execution.
// Creates recursive tasks and numeric fuzzing tasks for discovered directories.
// Uses MarkSeenIfNew for deduplication - returns early if directory already processed.
func (e *Engine) OnDirectoryDiscovered(dirPath string, depth uint16) error {
	// Early return if context cancelled (graceful shutdown)
	if err := e.ctx.Err(); err != nil {
		return err
	}

	parsedURL, err := url.Parse(dirPath)
	if err != nil {
		return fmt.Errorf("parse directory URL %s: %w", dirPath, err)
	}

	// Scope check - skip out-of-scope directories to prevent recursive tasks on external domains
	if e.spiderScope != nil && !e.spiderScope.IsInScope(parsedURL) {
		logger.Debug("Skipping out-of-scope directory",
			zap.String("path", dirPath))
		return nil
	}

	// Skip if path contains useless segments (., .., or URL-encoded variants)
	// This prevents recursive brute-force on paths like "/../admin/" or "/%2e%2e/config/"
	if containsUselessPathSegment(parsedURL.Path) {
		logger.Debug("Directory contains useless path segment, skipping recursion",
			zap.String("path", dirPath))
		return nil
	}

	cleanedPath := e.cleanDirectoryPath(parsedURL)

	// Deduplication: normalize URL (sorted param names) for consistent dedup
	// Use normalized form for dedup check, but keep original cleanedPath for HTTP requests
	normalizedForDedup := dedup.NormalizeURL(cleanedPath)
	if !e.testedDirectories.MarkSeenIfNew(normalizedForDedup) {
		logger.Debug("Directory already processed, skipping",
			zap.String("path", cleanedPath))
		return nil
	}

	logger.Info("Directory discovered",
		zap.String("path", cleanedPath),
		zap.Uint16("depth", depth))

	// Execute modules if configured
	if e.moduleExecutor != nil && e.moduleExecutor.HasEnabledModules() {
		shouldContinue, err := e.handleDirectoryModules(parsedURL, cleanedPath, depth)
		if err != nil {
			logger.Warn("Module execution error", zap.Error(err))
		}
		if !shouldContinue {
			return nil
		}
	}

	e.createDirectoryTasks(parsedURL, cleanedPath, depth)
	return nil
}

// cleanDirectoryPath normalizes directory path by collapsing double slashes.
func (e *Engine) cleanDirectoryPath(parsedURL *url.URL) string {
	cleanPath := path.Clean(parsedURL.Path)
	if cleanPath != "/" && parsedURL.Path[len(parsedURL.Path)-1] == '/' {
		cleanPath += "/"
	}
	parsedURL.Path = cleanPath
	return parsedURL.String()
}

// handleDirectoryModules executes modules for directory discovery.
// Returns false if default task creation should be skipped.
func (e *Engine) handleDirectoryModules(parsedURL *url.URL, cleanedPath string, depth uint16) (bool, error) {
	event := &module.DirectoryEvent{
		URL:        cleanedPath,
		Path:       parsedURL.Path,
		Depth:      depth,
		ParentPath: path.Dir(strings.TrimSuffix(parsedURL.Path, "/")),
		Segments:   strings.Split(strings.Trim(parsedURL.Path, "/"), "/"),
	}

	result, err := e.moduleExecutor.ExecuteDirectory(e.ctx, event)
	if err != nil {
		return true, err
	}

	if result == nil {
		return true, nil
	}

	// Handle queue cleanup request
	if result.QueueCleanup != nil {
		removed := e.taskQueue.RemoveByPattern(result.QueueCleanup.Pattern)
		logger.Info("Queue cleanup by module",
			zap.String("pattern", result.QueueCleanup.Pattern),
			zap.Int("removed", removed))
	}

	if result.StopRecursion {
		logger.Debug("Module stopped recursion", zap.String("path", cleanedPath))
		return false, nil
	}

	// Handle module tasks - pass URL without query params
	if len(result.Tasks) > 0 {
		pathOnlyURL := &url.URL{
			Scheme: parsedURL.Scheme,
			Host:   parsedURL.Host,
			Path:   parsedURL.Path,
		}
		e.createModuleTasks(pathOnlyURL.String(), depth, result.Tasks)
	}

	if result.SkipDefaultLogic {
		logger.Debug("Module skipped default logic", zap.String("path", cleanedPath))
		return false, nil
	}

	return true, nil
}

// createModuleTasks creates tasks from module task specifications.
// Respects recursion settings - skips if recursion disabled or max depth reached.
// pathOnlyStr should be URL without query params.
func (e *Engine) createModuleTasks(pathOnlyStr string, depth uint16, taskSpecs []module.TaskSpec) {
	// Check recursion settings before creating module tasks
	if !e.config.Target.Recursion.Enabled {
		logger.Debug("Skipping module tasks (recursion disabled)",
			zap.String("path", pathOnlyStr))
		return
	}

	nextDepth := depth + 1
	if nextDepth > uint16(e.config.Target.Recursion.MaxDepth) {
		logger.Debug("Skipping module tasks (max depth reached)",
			zap.String("path", pathOnlyStr),
			zap.Uint16("depth", depth),
			zap.Uint16("max_depth", uint16(e.config.Target.Recursion.MaxDepth)))
		return
	}

	// Extract schemeHost and path from pathOnlyStr
	schemeHost := []byte(extractSchemeHost(pathOnlyStr))
	dirPath := []byte(extractPathFromURL(pathOnlyStr))

	tasks, err := e.factory.CreateModuleTasks(
		schemeHost,
		dirPath,
		nextDepth,
		taskSpecs,
		e.observedNames,
		e.observedPaths,
	)
	if err != nil {
		logger.Warn("Failed to create module tasks", zap.Error(err))
		return
	}

	added := e.addTasks(tasks)
	if added > 0 {
		logger.Info("Created module tasks",
			zap.String("path", pathOnlyStr),
			zap.Int("count", added))
	}
}

// createDirectoryTasks creates discovery tasks for a directory.
func (e *Engine) createDirectoryTasks(parsedURL *url.URL, cleanedPath string, depth uint16) {
	// Learn baseline fingerprint for this directory BEFORE creating bruteforce tasks.
	// This enables detection of directory-specific soft-404 patterns (e.g., /bob/* → redirect).
	if !e.config.Engine.SkipFingerprintLearning {
		if err := e.learnBaselineForDirectory(parsedURL); err != nil {
			logger.Warn("Failed to learn directory baseline",
				zap.String("path", cleanedPath),
				zap.Error(err))
			// Continue anyway - parent directory baseline may still work via cascade
		}
	}

	// Calculate nextDepth once for both observed and wordlist tasks
	nextDepth := depth + 1

	// Check recursion settings - applies to ALL recursive tasks (observed + wordlist)
	if !e.config.Target.Recursion.Enabled {
		logger.Debug("Skipping recursion (disabled)", zap.String("path", cleanedPath))
		return
	}
	if nextDepth > uint16(e.config.Target.Recursion.MaxDepth) {
		logger.Debug("Skipping recursion (max depth reached)",
			zap.String("path", cleanedPath),
			zap.Uint16("depth", depth),
			zap.Uint16("next_depth", nextDepth),
			zap.Uint16("max_depth", uint16(e.config.Target.Recursion.MaxDepth)))
		return
	}

	// Build URL without query params for wordlist/observed tasks.
	// Query params should NOT be included in bruteforce base URLs - only spider tasks
	// preserve query params since they test actual discovered URLs.
	pathOnlyURL := &url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
		Path:   parsedURL.Path,
	}
	pathOnlyStr := pathOnlyURL.String()

	// Create observed name/extension tasks (only when UseObservedNames is enabled)
	if e.config.Filenames.UseObservedNames {
		observedExtensions := e.getObservedExtensionsSnapshot()
		tasksToAdd := e.factory.CreateRecursiveDirectoryTasks(
			pathOnlyStr,
			nextDepth,
			e.observedNames,
			observedExtensions,
			e.observedPaths,
			e.observedFiles,
		)

		added := e.addTasks(tasksToAdd)
		if added > 0 {
			logger.Debug("Added observed name tasks for directory",
				zap.String("directory", pathOnlyStr),
				zap.Int("task_count", added))
		}
	} else if e.config.Filenames.UseObservedPaths {
		// Create observed path tasks independently when only UseObservedPaths is enabled
		tasksToAdd := e.factory.CreateObservedPathTasks(
			[]byte(pathOnlyStr),
			nextDepth,
			e.observedPaths,
		)

		added := e.addTasks(tasksToAdd)
		if added > 0 {
			logger.Debug("Added observed path tasks for directory",
				zap.String("directory", pathOnlyStr),
				zap.Int("task_count", added))
		}
	}

	// Create recursive wordlist tasks
	tasks, err := e.factory.CreateInitialTasks([]byte(pathOnlyStr), nextDepth)
	if err != nil {
		logger.Error("Failed to create initial tasks for directory",
			zap.String("path", pathOnlyStr),
			zap.Error(err))
		return
	}

	added := e.addTasks(tasks)
	if added > 0 {
		logger.Debug("Added recursive wordlist tasks for directory",
			zap.String("path", pathOnlyStr),
			zap.Int("task_count", added))
	}

	// Numeric parameter detection and fuzzing - use pathOnlyStr (no query params)
	if e.config.Filenames.EnableNumericFuzzing {
		if _, _, _, found := FindNumericParameter([]byte(parsedURL.Path)); found {
			logger.Debug("Numeric parameter found in directory path, creating fuzz task",
				zap.String("path", pathOnlyStr))
			numericTask := e.factory.CreateNumericFuzzTask([]byte(pathOnlyStr), nextDepth)
			if numericTask != nil {
				e.AddTask(numericTask)
			}
		}
	}

	// Create JS extracted request task for this directory.
	// Use pathOnlyURL (no query params) - JSExtractedRequestTask only needs directory path.
	if e.jsscanScanner != nil {
		jsExtTask := e.factory.CreateJSExtractedRequestTask(
			pathOnlyURL,
			e.GetExtractedRequests,
			nextDepth,
		)
		if jsExtTask != nil {
			e.AddTask(jsExtTask)
			logger.Debug("Added JS extracted request task for directory",
				zap.String("directory", pathOnlyStr))
		}
	}

	// Malformed path probe for discovered directory
	if e.config.Filenames.EnableMalformedPathProbe {
		probeTask := e.factory.CreateMalformedPathProbeTask(
			[]byte(extractSchemeHost(pathOnlyStr)),
			[]byte(extractPathFromURL(pathOnlyStr)),
			nextDepth,
		)
		if probeTask != nil {
			e.AddTask(probeTask)
			logger.Debug("Added malformed path probe task for directory",
				zap.String("directory", pathOnlyStr))
		}
	}
}

// OnFileDiscovered handles file discovery during scan execution.
// Creates derivation tasks (extension variants + numeric fuzzing) for discovered files.
// Uses deduplication - returns early if file already processed.
func (e *Engine) OnFileDiscovered(filePath string, depth uint16) error {
	// Early return if context cancelled (graceful shutdown)
	if err := e.ctx.Err(); err != nil {
		return err
	}

	// Parse URL for validation
	parsedFileURL, _ := url.Parse(filePath)

	// Scope check - skip out-of-scope files to prevent derivation tasks on external domains
	if parsedFileURL != nil && e.spiderScope != nil && !e.spiderScope.IsInScope(parsedFileURL) {
		logger.Debug("Skipping out-of-scope file",
			zap.String("path", filePath))
		return nil
	}

	// Skip if path contains useless segments (., .., or URL-encoded variants)
	if parsedFileURL != nil && containsUselessPathSegment(parsedFileURL.Path) {
		logger.Debug("File contains useless path segment, skipping",
			zap.String("path", filePath))
		return nil
	}

	// Deduplication: normalize URL (sorted param names) for consistent dedup
	// Use normalized form for dedup check, but keep original filePath for HTTP requests
	normalizedForDedup := dedup.NormalizeURL(filePath)
	if !e.testedFiles.MarkSeenIfNew(normalizedForDedup) {
		logger.Debug("File already processed, skipping",
			zap.String("path", filePath))
		return nil
	}

	logger.Info("File discovered, extracting metadata",
		zap.String("path", filePath),
		zap.Uint16("depth", depth))

	// Strip query params for basePath/filename calculation.
	// Query params should NOT be included in derivation task URLs.
	filePathNoQuery := filePath
	if parsedFileURL != nil && parsedFileURL.RawQuery != "" {
		pathOnlyURL := &url.URL{
			Scheme: parsedFileURL.Scheme,
			Host:   parsedFileURL.Host,
			Path:   parsedFileURL.Path,
		}
		filePathNoQuery = pathOnlyURL.String()
	}

	pathBytes := []byte(filePathNoQuery)
	lastSlash := bytes.LastIndexByte(pathBytes, '/')
	if lastSlash == -1 {
		return nil
	}

	basePath := pathBytes[:lastSlash+1]
	filename := pathBytes[lastSlash+1:]

	// Execute modules if configured
	if e.moduleExecutor != nil && e.moduleExecutor.HasEnabledModules() {
		shouldContinue, err := e.handleFileModules(filePath, pathBytes, filename, basePath, depth)
		if err != nil {
			logger.Warn("Module file execution error", zap.Error(err))
		}
		if !shouldContinue {
			return nil
		}
	}

	// Extract and track filename/extension
	e.extractFileMetadata(filePath, depth)

	// Extract breadcrumb directories (triggers recursive brute force)
	e.processFilePathBreadcrumbs(filePath, depth)

	// Create derivation tasks
	e.createFileDerivationTasks(filePath, pathBytes, filename, basePath, depth)

	return nil
}

// handleFileModules executes modules for file discovery.
func (e *Engine) handleFileModules(filePath string, pathBytes, filename, basePath []byte, depth uint16) (bool, error) {
	parsedFileURL, _ := url.Parse(filePath)
	ext := ""
	if parsedFileURL != nil {
		ext = path.Ext(parsedFileURL.Path)
	}

	event := &module.FileEvent{
		URL:        filePath,
		Path:       string(pathBytes),
		Filename:   string(filename),
		Extension:  ext,
		Depth:      depth,
		ParentPath: string(basePath),
	}

	result, err := e.moduleExecutor.ExecuteFile(e.ctx, event)
	if err != nil {
		return true, err
	}

	if result != nil && result.SkipDefaultLogic {
		logger.Debug("Module skipped default file logic", zap.String("path", filePath))
		return false, nil
	}

	return true, nil
}

// extractFileMetadata extracts and tracks filename/extension from discovered file.
// Discovered files are trusted sources - they are actual files found on the server.
func (e *Engine) extractFileMetadata(filePath string, depth uint16) {
	parsedURL, err := url.Parse(filePath)
	if err != nil {
		return
	}

	name, ext := ExtractFilename(parsedURL.Path)

	if name != "" {
		e.AddObservedNameTrusted(name)
		logger.Debug("Added observed name from file discovery",
			zap.String("name", name),
			zap.String("path", filePath))
	}

	if ext != "" {
		e.handleNewExtension(ext, depth)
	}

	// Store full filename for literal file testing (preserves hashes like app.b5ca88ec.js)
	rawFilename, rawExt := ExtractRawFilename(parsedURL.Path)
	if rawFilename != "" && rawExt != "" {
		if _, ok := config.AllowedObservedExtensions[rawExt]; ok {
			e.AddObservedFileTrusted(rawFilename)
		}
	}

	// Extract paths and segments
	if e.config.Filenames.UseObservedPaths {
		// Store raw full path (overlap merging happens at task execution time)
		fullPath := ExtractPathForFuzzing(parsedURL.Path)
		if fullPath != "" {
			e.AddObservedPathTrusted(fullPath)
		}

		// Extract name/extension from each segment to avoid adding full filenames like "app.js"
		segments := ExtractPathSegments(parsedURL.Path)
		for _, segment := range segments {
			name, ext := ExtractFilename("/" + segment)
			if name != "" {
				e.AddObservedNameTrusted(name)
			}
			if ext != "" {
				e.addObservedExtensionIfNew(ext)
			}
		}
	}
}

// createFileDerivationTasks creates extension variant and numeric fuzz tasks.
// Respects recursion settings - skips if recursion disabled or max depth reached.
func (e *Engine) createFileDerivationTasks(filePath string, _, filename, basePath []byte, depth uint16) {
	// Check recursion settings BEFORE creating any derivation tasks
	if !e.config.Target.Recursion.Enabled {
		logger.Debug("Skipping file derivation (recursion disabled)",
			zap.String("path", filePath))
		return
	}

	nextDepth := depth + 1
	if nextDepth > uint16(e.config.Target.Recursion.MaxDepth) {
		logger.Debug("Skipping file derivation (max depth reached)",
			zap.String("path", filePath),
			zap.Uint16("depth", depth),
			zap.Uint16("max_depth", uint16(e.config.Target.Recursion.MaxDepth)))
		return
	}

	derivationCount := 0

	// Extension Variant Task
	if e.config.Extensions.TestVariants && ShouldCreateVariantTask(filename) {
		// Extract schemeHost and path from basePath (which is full URL without query)
		schemeHost := []byte(extractSchemeHost(string(basePath)))
		dirPath := []byte(extractPathFromURL(string(basePath)))
		variantTask := e.factory.CreateExtensionVariantTask(filename, schemeHost, dirPath, nextDepth)
		if variantTask != nil {
			logger.Debug("Creating extension variant task", zap.String("path", filePath))
			if e.AddTask(variantTask) {
				derivationCount++
			}
		}
	}

	// Numeric Mutation Task - use URL without query params
	parsedURL, _ := url.Parse(filePath)
	if e.config.Filenames.EnableNumericFuzzing && parsedURL != nil {
		if _, _, _, found := FindNumericParameter([]byte(parsedURL.Path)); found {
			// Strip query params for numeric fuzz task
			pathOnlyURL := &url.URL{
				Scheme: parsedURL.Scheme,
				Host:   parsedURL.Host,
				Path:   parsedURL.Path,
			}
			numericTask := e.factory.CreateNumericFuzzTask([]byte(pathOnlyURL.String()), nextDepth)
			if numericTask != nil {
				logger.Debug("Creating numeric fuzz task", zap.String("path", pathOnlyURL.String()))
				if e.AddTask(numericTask) {
					derivationCount++
				}
			}
		}
	}

	if derivationCount > 0 {
		logger.Debug("File derivation tasks created",
			zap.String("path", filePath),
			zap.Int("count", derivationCount))
	}
}

// processFilePathBreadcrumbs extracts parent directories from discovered file path
// and triggers OnDirectoryDiscovered for each with correct depth based on path level.
// No HTTP probe needed - file existence proves all parent directories exist.
func (e *Engine) processFilePathBreadcrumbs(filePath string, _ uint16) {
	fileURL, err := url.Parse(filePath)
	if err != nil {
		return
	}

	breadcrumbs := ExtractDirectoryBreadcrumbs(fileURL.Path)
	if len(breadcrumbs) == 0 {
		return
	}

	basePath := normalizeSchemeHost(fileURL)

	for i, dirPath := range breadcrumbs {
		dirURL := basePath + dirPath
		// Depth = path level (index + 1): /api/ = 1, /api/v1/ = 2, etc.
		dirDepth := uint16(i + 1)
		_ = e.OnDirectoryDiscovered(dirURL, dirDepth)
	}
}

// onResult is the callback invoked when a discovery result is available.
func (e *Engine) onResult(result *Result) {
	if result == nil || result.URL == nil {
		return
	}

	// Trigger case sensitivity detection on first valid discovery (if auto-detect enabled)
	e.triggerCaseSensitivityDetection(result)

	// Skip displaying root URL matches - they're starting points, not discoveries.
	// Root URLs (with or without trailing slash) should not appear as results.
	if e.displayCallback != nil && !e.isRootURL(result.URL) {
		e.displayCallback(result)
	}

	urlStr := result.URL.String()

	// Compute fingerprint from ResponseChain if available
	fpAttrs := e.computeFingerprint(result)

	// Build storage result - extract data directly from ResponseChain
	rc := result.ResponseChain()

	// Extract request headers from ResponseChain
	var reqHeaders map[string]string
	if rc != nil && rc.Has() {
		if httpReq := rc.Request(); httpReq != nil && len(httpReq.Header) > 0 {
			reqHeaders = make(map[string]string, len(httpReq.Header))
			for k, v := range httpReq.Header {
				if len(v) > 0 {
					reqHeaders[k] = v[0]
				}
			}
		}
	}

	// Use body from Result.Request if provided (form submissions, JS extracted requests)
	var reqBody []byte
	if result.Request != nil && len(result.Request.Body) > 0 {
		reqBody = result.Request.Body
	}

	builder := storage.NewResultBuilder().
		WithURL(result.URL).
		WithRequest(result.Request.Method, reqHeaders, reqBody).
		WithMetadata(result.Metadata.FoundBy, result.Metadata.Depth, result.Metadata.Timestamp).
		WithFingerprint(fpAttrs)

	if rc != nil && rc.Has() {
		resp := rc.Response()
		// Extract headers directly
		headers := make(map[string]string, len(resp.Header))
		for k, v := range resp.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		// Extract MIME type from Content-Type
		mimeType := extractMIMEType(resp.Header.Get("Content-Type"))

		// Get actual content length from original body BEFORE filtering
		var actualContentLength int64
		bodyBytes := rc.BodyBytes()
		if len(bodyBytes) > 0 {
			actualContentLength = int64(len(bodyBytes))
		}

		// Copy body bytes, filtering media content and large responses (>30MB)
		const maxBodySize = 30 * 1024 * 1024 // 30MB
		var bodyCopy []byte
		if len(bodyBytes) > 0 {
			if !pkghttp.IsMediaContent(mimeType, result.URL.Path) && len(bodyBytes) <= maxBodySize {
				bodyCopy = make([]byte, len(bodyBytes))
				copy(bodyCopy, bodyBytes)
			}
		}

		// Extract Location header (case-insensitive)
		var location string
		for k, v := range headers {
			if strings.EqualFold(k, "location") {
				location = v
				break
			}
		}

		// Extract title using regex (if HTML content)
		var title string
		if len(bodyCopy) > 0 && isHTMLContent(mimeType) {
			title = extractTitleRegex(bodyCopy)
		}

		// Compute words and lines from body
		var words, lines int64
		if len(bodyCopy) > 0 {
			bodyStr := string(bodyCopy)
			words = int64(len(strings.Fields(bodyStr)))
			if bodyStr != "" {
				lines = int64(strings.Count(bodyStr, "\n") + 1)
			}
		}

		builder = builder.WithResponse(resp.StatusCode, headers, bodyCopy, actualContentLength, mimeType, location, title, words, lines)
	}

	storageResult := builder.Build()

	// Compute tags from response
	if e.tagAnalyzer != nil {
		storageResult.Tags = e.tagAnalyzer.AnalyzeResult(storageResult)
	}

	// Buffer response body for batch kingfisher scanning (runs after crawl completes)
	if e.kingfisherScanner != nil && storageResult.Response != nil {
		e.bufferForKingfisher(
			result.BodyBytes(),
			storageResult.Response.MIMEType,
			result.URL.Path,
			urlStr,
		)
	}

	if e.storage != nil {
		if err := e.storage.Store(storageResult); err != nil {
			logger.Warn("storage error",
				zap.String("url", urlStr),
				zap.Error(err))
		} else if len(storageResult.KingfisherFindings) > 0 {
			logger.Debug("Kingfisher findings stored to DB",
				zap.String("url", urlStr),
				zap.Int("count", len(storageResult.KingfisherFindings)))
		}
	}

	// Process spider links inline if enabled
	e.processSpiderLinks(result)
}

// computeFingerprint computes fingerprint attributes from result.
// Uses ResponseChain if available, otherwise returns nil.
func (e *Engine) computeFingerprint(result *Result) map[uint8]uint32 {
	rc := result.ResponseChain()
	if rc == nil {
		return nil
	}

	sample, _ := fingerprint.NewSampleFromRC(rc)
	if sample == nil {
		return nil
	}

	attrs := sample.AllAttributes()
	fpAttrs := make(map[uint8]uint32, len(attrs))
	for k, v := range attrs {
		fpAttrs[uint8(k)] = v
	}
	return fpAttrs
}

// processSpiderLinks extracts links from result response inline.
// Always runs for every discovered resource to enable recursive crawling.
func (e *Engine) processSpiderLinks(result *Result) {
	rc := result.ResponseChain()
	if rc == nil {
		return
	}

	e.extractLinks(result.URL, rc, result.Metadata.Depth)
}

// generateObservedExtensionTasks creates dynamic tasks when new extension discovered.
// Respects recursion settings - skips if recursion disabled or filters directories by max depth.
func (e *Engine) generateObservedExtensionTasks(extension string, currentDepth uint16) {
	// Skip if recursion disabled
	if !e.config.Target.Recursion.Enabled {
		logger.Debug("Skipping dynamic extension tasks (recursion disabled)",
			zap.String("extension", extension))
		return
	}

	maxDepth := uint16(e.config.Target.Recursion.MaxDepth)

	// Collect all discovered directory URLs, including start URL
	directoryURLs := collectDirectoryURLs(e.storage)
	if !slices.Contains(directoryURLs, e.config.Target.StartURL) {
		directoryURLs = append(directoryURLs, e.config.Target.StartURL)
	}

	// Filter out directories exceeding maxDepth
	filtered := make([]string, 0, len(directoryURLs))
	for _, dirURL := range directoryURLs {
		parsed, err := url.Parse(dirURL)
		if err != nil {
			continue
		}
		dirDepth := pathDepth(parsed.Path)
		if dirDepth <= maxDepth {
			filtered = append(filtered, dirURL)
		}
	}

	// Use capped depth for task creation
	taskDepth := currentDepth
	if taskDepth > maxDepth {
		taskDepth = maxDepth
	}

	tasks := e.factory.CreateDynamicExtensionTasks(
		extension,
		filtered,
		e.observedNames,
		taskDepth,
	)

	e.addTasks(tasks)
}

// isRootURL checks if a URL is the root/start URL (with or without trailing slash).
// Root URLs should not be displayed as discovery results - they're starting points.
func (e *Engine) isRootURL(u *url.URL) bool {
	if u == nil {
		return false
	}

	startURL, err := url.Parse(e.config.Target.StartURL)
	if err != nil {
		return false
	}

	// Compare scheme and host
	if u.Scheme != startURL.Scheme || u.Host != startURL.Host {
		return false
	}

	// Normalize paths for comparison
	uPath := u.Path
	startPath := startURL.Path

	// Empty path is equivalent to "/"
	if uPath == "" {
		uPath = "/"
	}
	if startPath == "" {
		startPath = "/"
	}

	// Normalize trailing slashes for comparison
	uPathNorm := strings.TrimSuffix(uPath, "/")
	startPathNorm := strings.TrimSuffix(startPath, "/")

	// Match if normalized paths are equal
	return uPathNorm == startPathNorm
}

// extractMIMEType extracts content type without charset from Content-Type header.
func extractMIMEType(contentType string) string {
	if contentType == "" {
		return ""
	}
	if idx := strings.IndexByte(contentType, ';'); idx >= 0 {
		return strings.TrimSpace(contentType[:idx])
	}
	return strings.TrimSpace(contentType)
}

// triggerCaseSensitivityDetection queues a case sensitivity detection task.
// Detection runs as Priority 0 task - will execute after current task finishes.
// This avoids blocking the result handler while still running detection early.
func (e *Engine) triggerCaseSensitivityDetection(result *Result) {
	if e.caseSenseManager == nil || !e.caseSenseManager.IsEnabled() {
		return
	}

	// Quick check: skip if already detected for this type
	isDirectory := strings.HasSuffix(result.URL.Path, "/")
	if isDirectory && e.caseSenseManager.DirDetected() {
		return
	}
	if !isDirectory && e.caseSenseManager.FileDetected() {
		return
	}

	rc := result.ResponseChain()
	if rc == nil {
		return
	}

	// Extract fingerprint sample for comparison
	sample, err := fingerprint.NewSampleFromRC(rc)
	if err != nil || sample == nil {
		return
	}

	// Strip query params - CaseSenseDetectionTask only needs path for case testing.
	// Query params should NOT be included in case sensitivity detection.
	pathOnlyURL := &url.URL{
		Scheme: result.URL.Scheme,
		Host:   result.URL.Host,
		Path:   result.URL.Path,
	}

	// Queue detection task with critical priority (0)
	// Task will execute inline by coordinator after current task finishes
	task := NewCaseSenseDetectionTask(&CaseSenseDetectionTaskConfig{
		DiscoveredURL: pathOnlyURL,
		Sample:        sample,
		IsDirectory:   isDirectory,
		Callback:      e.OnValidDiscovery,
	})

	e.AddTask(task)
}

// isHTMLContent checks if the MIME type indicates HTML content.
func isHTMLContent(mimeType string) bool {
	mt := strings.ToLower(mimeType)
	return strings.Contains(mt, "/html") || strings.Contains(mt, "/xhtml")
}

// titleRegex matches <title> tag content.
var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>([^<]*)</title>`)

// extractTitleRegex extracts the page title from HTML body using regex.
func extractTitleRegex(body []byte) string {
	match := titleRegex.FindSubmatch(body)
	if len(match) > 1 {
		return strings.TrimSpace(string(match[1]))
	}
	return ""
}

// isTextBasedMIME checks if the MIME type indicates text-based content.
// Returns true for text/*, JSON, JavaScript, XML, and related formats.
func isTextBasedMIME(mimeType string) bool {
	if mimeType == "" {
		return true // Unknown MIME, attempt scan
	}
	mt := strings.ToLower(mimeType)
	if strings.HasPrefix(mt, "text/") {
		return true
	}
	textTypes := []string{
		"/json",
		"/javascript",
		"/x-javascript",
		"/xml",
		"/x-yaml",
		"/yaml",
	}
	for _, t := range textTypes {
		if strings.Contains(mt, t) {
			return true
		}
	}
	return strings.HasSuffix(mt, "+json") || strings.HasSuffix(mt, "+xml")
}

// containsUselessPathSegment checks if URL path contains any useless segment.
// Returns true if:
// 1. ANY segment (after 2-level URL decode) equals exactly "." or ".."
// 2. Path has more than maxConsecutiveDuplicateSegments identical segments in a row
//
// This prevents recursive brute-force on paths like "/../admin/" or "/backup/backup/backup/".
//
// Bypass patterns like "..;/" or "..%00/" are NOT rejected since they're valid
// path traversal bypass techniques worth testing.
func containsUselessPathSegment(urlPath string) bool {
	segments := strings.Split(urlPath, "/")

	consecutiveCount := 1
	prevDecoded := ""

	for _, seg := range segments {
		if seg == "" {
			continue
		}

		// URL decode up to 2 times (catch double-encoding)
		decoded := urlDecodeN(seg, 2)

		// Check if decoded segment is exactly "." or ".."
		if decoded == "." || decoded == ".." {
			return true
		}

		// Check for consecutive duplicates
		if decoded == prevDecoded && prevDecoded != "" {
			consecutiveCount++
			if consecutiveCount > maxConsecutiveDuplicateSegments {
				return true
			}
		} else {
			consecutiveCount = 1
		}
		prevDecoded = decoded
	}

	return false
}

// urlDecodeN performs URL decoding up to n times.
// Stops early if decoding produces no change or error.
func urlDecodeN(seg string, n int) string {
	decoded := seg
	for range n {
		unescaped, err := url.PathUnescape(decoded)
		if err != nil || unescaped == decoded {
			break
		}
		decoded = unescaped
	}
	return decoded
}
