package discovery

import (
	"bytes"
	"context"
	"hash/fnv"
	"net/url"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/jsscan"
	"github.com/vigolium/vigolium/pkg/deparos/jsscan/linkfinder"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"go.uber.org/zap"
	"golang.org/x/net/html"
)

// hashBodyContent computes FNV-1a 64-bit hash of response body for deduplication.
func hashBodyContent(body []byte) string {
	h := fnv.New64a()
	h.Write(body)
	return strconv.FormatUint(h.Sum64(), 16)
}

// processScriptTagsWithJSScan extracts <script> tag content from HTML and runs jsscan + linkfinder.
// Called from extractLinks for HTML responses.
//
// For each inline script tag:
// 1. Run jsscan to extract HTTP requests (endpoints with method, params, body)
// 2. Run linkfinder to extract paths and add to observed collections
//
// Thread-safe: uses semaphore for jsscan rate limiting, DiskSet for dedup.
func (e *Engine) processScriptTagsWithJSScan(ctx context.Context, sourceURL *url.URL, rc *responsechain.ResponseChain) {
	// Skip if jsscan not initialized
	if e.jsscanScanner == nil || e.jsscanSem == nil {
		return
	}

	resp := rc.Response()
	if resp == nil {
		return
	}

	// Only process HTML responses
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "/html") &&
		!strings.Contains(strings.ToLower(contentType), "/xhtml") {
		return
	}

	body := rc.BodyBytes()
	if len(body) < 10 {
		return
	}

	// Response body deduplication - skip if we've already processed this exact content
	bodyHash := hashBodyContent(body)
	if e.seenBodyHashes != nil && e.seenBodyHashes.IsSeen(bodyHash) {
		logger.Debug("Response body already processed, skipping jsscan",
			zap.String("url", sourceURL.String()),
			zap.String("hash", bodyHash))
		return
	}

	// Extract script tags from HTML
	scripts := extractScriptTags(body)
	if len(scripts) == 0 {
		return
	}

	logger.Debug("Extracted script tags for jsscan",
		zap.String("url", sourceURL.String()),
		zap.Int("count", len(scripts)))

	// Collect all extracted requests from all scripts
	var allRequests []jsscan.ExtractedRequest

	// Track total paths extracted for logging
	var totalNamesAdded, totalPathsAdded int

	// Process each script tag
	for i, scriptContent := range scripts {
		if len(scriptContent) == 0 {
			continue
		}

		// Skip very large inline scripts (same limit as standalone JS)
		if len(scriptContent) > maxJSSize {
			logger.Debug("Inline script too large, skipping jsscan",
				zap.String("url", sourceURL.String()),
				zap.Int("script_index", i),
				zap.Int("size", len(scriptContent)))
			continue
		}

		// Acquire semaphore
		select {
		case e.jsscanSem <- struct{}{}:
			// Got semaphore
		case <-ctx.Done():
			return
		}

		// Run jsscan on script content
		scanResult, err := e.jsscanScanner.Scan(ctx, scriptContent)

		// Release semaphore
		<-e.jsscanSem

		if err != nil {
			logger.Debug("jsscan failed for inline script",
				zap.String("url", sourceURL.String()),
				zap.Int("script_index", i),
				zap.Error(err))
			// Still run linkfinder on raw script content even if jsscan fails
			namesAdded, pathsAdded := e.extractPathsFromScript(scriptContent)
			totalNamesAdded += namesAdded
			totalPathsAdded += pathsAdded
			continue
		}

		// Collect extracted requests
		if len(scanResult.Requests) > 0 {
			allRequests = append(allRequests, scanResult.Requests...)
		}

		// Run linkfinder on script content
		// Use transformed code from jsscan if available, otherwise use raw script
		contentForLinkfinder := scriptContent
		if scanResult.HasCode() {
			contentForLinkfinder = []byte(scanResult.Code.Content)
		}

		namesAdded, pathsAdded := e.extractPathsFromScript(contentForLinkfinder)
		totalNamesAdded += namesAdded
		totalPathsAdded += pathsAdded
	}

	// Process all collected requests
	if len(allRequests) > 0 {
		newRequests := 0
		for i := range allRequests {
			if e.AddExtractedRequest(&allRequests[i]) {
				newRequests++
			}
		}

		// Store to database using existing method
		e.storeJSScanRequests(sourceURL, allRequests)

		logger.Debug("jsscan extracted requests from inline scripts",
			zap.String("url", sourceURL.String()),
			zap.Int("total_scripts", len(scripts)),
			zap.Int("total_requests", len(allRequests)),
			zap.Int("new_requests", newRequests))
	}

	// Log linkfinder results
	if totalNamesAdded > 0 || totalPathsAdded > 0 {
		logger.Debug("Linkfinder extracted paths from inline scripts",
			zap.String("url", sourceURL.String()),
			zap.Int("names_added", totalNamesAdded),
			zap.Int("paths_added", totalPathsAdded))
	}
}

// extractPathsFromScript runs linkfinder on script content and adds results to observed collections.
// Returns the count of names and paths added.
func (e *Engine) extractPathsFromScript(content []byte) (namesAdded, pathsAdded int) {
	paths := linkfinder.ExtractPaths(content)
	if len(paths) == 0 {
		return 0, 0
	}

	for _, path := range paths {
		name, _ := ExtractFilename(path)
		if name != "" {
			e.AddObservedName(name)
			namesAdded++
		}
		if path != "" {
			e.AddObservedPath(path)
			pathsAdded++
		}
	}

	return namesAdded, pathsAdded
}

// extractScriptTags extracts content from all inline <script> tags in HTML.
// Skips external scripts (those with src attribute) as they're handled by JSFetchTask.
func extractScriptTags(body []byte) [][]byte {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}

	var scripts [][]byte
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "script") {
			// Check for external script (has src attribute)
			for _, attr := range n.Attr {
				if strings.EqualFold(attr.Key, "src") && attr.Val != "" {
					// External script - skip, handled by JSFetchTask
					goto traverseChildren
				}
			}

			// Extract inline script content
			var content strings.Builder
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.TextNode {
					content.WriteString(c.Data)
				}
			}
			if s := strings.TrimSpace(content.String()); s != "" {
				scripts = append(scripts, []byte(s))
			}
		}

	traverseChildren:
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)

	return scripts
}
