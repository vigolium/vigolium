package discovery

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/url"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/linkfinder"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"go.uber.org/zap"
	"golang.org/x/net/html"
)

func (e *Engine) jsTangleOptions(profile jstangle.AnalysisProfile, sourceURL string) jstangle.ScanOptions {
	options := jstangle.ScanOptions{Profile: profile, SourceURL: sourceURL}
	if e.config.JSTangle.MaxRequestsPerFile > 0 {
		options.MaxRequests = e.config.JSTangle.MaxRequestsPerFile
	}
	if e.config.JSTangle.MaxASTNodes > 0 {
		options.MaxASTNodes = e.config.JSTangle.MaxASTNodes
	}
	if e.config.JSTangle.JobTimeout > 0 {
		options.Deadline = e.config.JSTangle.JobTimeout
	}
	if e.config.JSTangle.HardInputMB > 0 {
		options.MaxInputBytes = e.config.JSTangle.HardInputMB * 1024 * 1024
	}
	return options
}

// hashBodyContent computes FNV-1a 64-bit hash of response body for deduplication.
func hashBodyContent(body []byte) string {
	h := fnv.New64a()
	h.Write(body)
	return strconv.FormatUint(h.Sum64(), 16)
}

// processScriptTagsWithJSTangle extracts <script> tag content from HTML and runs jstangle + linkfinder.
// Called from extractLinks for HTML responses.
//
// For each inline script tag:
// 1. Run jstangle to extract HTTP requests (endpoints with method, params, body)
// 2. Run linkfinder to extract paths and add to observed collections
//
// Thread-safe: the shared service owns admission; DiskSet handles body dedup.
func (e *Engine) processScriptTagsWithJSTangle(ctx context.Context, sourceURL *url.URL, rc *responsechain.ResponseChain) {
	// Skip if jstangle not initialized
	if e.jstangleService == nil {
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
		logger.Debug("Response body already processed, skipping jstangle",
			zap.String("url", sourceURL.String()),
			zap.String("hash", bodyHash))
		return
	}

	// Extract script tags from HTML. Reuse the ResponseChain's cached HTML parse
	// (sync.Once) — the spider coordinator parses the same body right after this
	// in extractLinks, so sharing one parse halves the per-page DOM-build cost.
	doc, err := rc.ParseHTML()
	if err != nil || doc == nil {
		return
	}
	scripts := extractScriptTags(doc)
	if len(scripts) == 0 {
		return
	}

	logger.Debug("Extracted script tags for jstangle",
		zap.String("url", sourceURL.String()),
		zap.Int("count", len(scripts)))

	// Collect all extracted requests from all scripts
	var allRequests []jstangle.ExtractedRequest

	// Track total paths extracted for logging
	var totalNamesAdded, totalPathsAdded int

	// Process each script tag
	for i, scriptContent := range scripts {
		if len(scriptContent) == 0 {
			continue
		}

		// Skip very large inline scripts (same limit as standalone JS)
		if len(scriptContent) > maxJSSize {
			logger.Debug("Inline script too large, skipping jstangle",
				zap.String("url", sourceURL.String()),
				zap.Int("script_index", i),
				zap.Int("size", len(scriptContent)))
			continue
		}

		// Run jstangle on script content. A fragment keeps inline provenance unique
		// without changing browser URL resolution semantics in the replay layer.
		inlineURL := *sourceURL
		inlineURL.Fragment = fmt.Sprintf("inline-script-%d", i)
		scanResult, err := e.jstangleService.ScanWithOptions(ctx, scriptContent, e.jsTangleOptions(jstangle.ProfileDiscovery, inlineURL.String()))

		if err != nil {
			logger.Debug("jstangle failed for inline script",
				zap.String("url", sourceURL.String()),
				zap.Int("script_index", i),
				zap.Error(err))
			// Still run linkfinder on raw script content even if jstangle fails
			namesAdded, pathsAdded := e.extractPathsFromScript(scriptContent)
			totalNamesAdded += namesAdded
			totalPathsAdded += pathsAdded
			continue
		}

		// Protocol v2 facts retain the inline asset identity and extractor. Only
		// fall back to the flat v1 collection for compatibility output.
		if len(scanResult.RequestFacts) > 0 {
			for factIndex := range scanResult.RequestFacts {
				// Return value (whether newly counted) is surfaced in the
				// aggregate log below via the compatibility view.
				e.AddRequestFact(inlineURL.String(), scanResult.RequestFacts[factIndex])
			}
			e.storeJSTangleFacts(sourceURL, scanResult.RequestFacts)
		} else if len(scanResult.Requests) > 0 {
			allRequests = append(allRequests, scanResult.Requests...)
		}
		e.processAssetFacts(ctx, inlineURL.String(), scriptContent, scanResult.AssetFacts)
		e.processJSTangleCapabilityFacts(inlineURL.String(), scanResult)

		// Always run linkfinder in addition to jstangle and merge results — they
		// are complementary (AST request extraction vs regex path discovery),
		// matching the external-JS path which runs both unconditionally.
		// Use transformed code from jstangle if available, otherwise use raw script.
		contentForLinkfinder := scriptContent
		if scanResult.HasCode() {
			contentForLinkfinder = []byte(scanResult.Code.Content)
		}

		namesAdded, pathsAdded := e.extractPathsFromScript(contentForLinkfinder)
		totalNamesAdded += namesAdded
		totalPathsAdded += pathsAdded
	}

	// Process only protocol-v1 fallback requests. Typed facts were registered
	// with their per-inline-script source above.
	if len(allRequests) > 0 {
		newRequests := 0
		for i := range allRequests {
			if e.AddExtractedRequest(&allRequests[i]) {
				newRequests++
			}
		}

		// Store to database using existing method
		e.storeJSTangleRequests(sourceURL, allRequests)

		logger.Debug("jstangle extracted requests from inline scripts",
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

// extractScriptTags extracts content from all inline <script> tags in a parsed
// HTML DOM. Skips external scripts (those with src attribute) as they're handled
// by JSFetchTask. The caller passes the shared ResponseChain.ParseHTML() node so
// the page is parsed once per extractLinks pass.
func extractScriptTags(doc *html.Node) [][]byte {
	if doc == nil {
		return nil
	}

	var scripts [][]byte
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "script") {
			isJavaScript := true
			// External scripts are fetched separately. Explicit data/template script
			// types are not JavaScript and should not consume an AST job.
			for _, attr := range n.Attr {
				if strings.EqualFold(attr.Key, "src") && attr.Val != "" {
					goto traverseChildren
				}
				if strings.EqualFold(attr.Key, "type") {
					typeValue := strings.ToLower(strings.TrimSpace(attr.Val))
					isJavaScript = typeValue == "" || typeValue == "module" ||
						typeValue == "text/javascript" || typeValue == "application/javascript" ||
						typeValue == "text/ecmascript" || typeValue == "application/ecmascript"
				}
			}
			if !isJavaScript {
				goto traverseChildren
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
