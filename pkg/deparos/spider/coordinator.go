package spider

import (
	"context"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// ExtractionCoordinator orchestrates all link extractors in the correct order.
//
// The coordinator implements the spider's extraction pipeline:
//  1. Always run inline URL scanner (scans raw bytes)
//  2. Skip HTML processing if body < 10 bytes
//  3. Parse HTML if not already parsed
//  4. Run HTTP header extractor
//  5. If HTML parsed successfully: run attribute + comment extractors
//  6. Run robots.txt parser
//  7. Extract forms
type ExtractionCoordinator struct {
	inlineScanner *InlineURLScanner
	httpHeaders   *HTTPHeaderExtractor
	htmlAttrs     *HTMLAttributeExtractor
	comments      *CommentsExtractor
	robotsParser  *RobotsTxtParser
	jsExtractor   *JavaScriptStringExtractor
	eventHandlers *EventHandlersExtractor
	metaRefresh   *MetaRefreshExtractor
	scriptContent *ScriptContentExtractor
	formExtractor *FormExtractor
}

// NewExtractionCoordinator creates a coordinator with all extractors.
func NewExtractionCoordinator(
	inlineScanner *InlineURLScanner,
	httpHeaders *HTTPHeaderExtractor,
	htmlAttrs *HTMLAttributeExtractor,
	comments *CommentsExtractor,
	robotsParser *RobotsTxtParser,
	jsExtractor *JavaScriptStringExtractor,
	eventHandlers *EventHandlersExtractor,
	metaRefresh *MetaRefreshExtractor,
	scriptContent *ScriptContentExtractor,
	formExtractor *FormExtractor,
) *ExtractionCoordinator {
	return &ExtractionCoordinator{
		inlineScanner: inlineScanner,
		httpHeaders:   httpHeaders,
		htmlAttrs:     htmlAttrs,
		comments:      comments,
		robotsParser:  robotsParser,
		jsExtractor:   jsExtractor,
		eventHandlers: eventHandlers,
		metaRefresh:   metaRefresh,
		scriptContent: scriptContent,
		formExtractor: formExtractor,
	}
}

// Extract runs all extractors in the correct order and collects discovered links.
//
// Extraction pipeline order:
//  1. Inline URL scanner - always runs
//  2. Check body size >= 10 bytes
//  3. Parse HTML if needed
//  4. HTTP header extractor
//  5. If HTML parsed: HTML attribute + comment extractors
//  6. Robots.txt parser
//  7. Regex path extractor
//  8. Form extractor (new)
//
// Parameters:
//   - ctx: Context for cancellation
//   - baseURL: Base URL for resolving relative URLs
//   - rc: ResponseChain containing the HTTP response
//
// Returns:
//   - ExtractionResult containing discovered links, JS URLs, and form requests
//   - Error if extraction fails
func (ec *ExtractionCoordinator) Extract(ctx context.Context, baseURL *url.URL, rc *responsechain.ResponseChain) (*ExtractionResult, error) {
	resp := rc.Response()
	body := rc.BodyBytes()

	// Reuse the ResponseChain's cached HTML parse (sync.Once) so the page is
	// parsed once per extractLinks pass — the script-tag scanner already parsed
	// it via the same rc.ParseHTML(). Only for bodies in the size band the
	// coordinator would itself parse; oversize bodies fall back to NewHTTPResponse
	// so the coordinator's own MaxBodySize DoS guard still applies, and tiny
	// bodies skip parsing entirely (extractInternal returns early below 10 bytes).
	var response *HTTPResponse
	switch {
	case len(body) < 10 || len(body) > MaxBodySize:
		// Too small to parse, or oversized (ParseHTML's own size guard applies).
		response = NewHTTPResponse(baseURL, resp.Header, body, 0)
	case !isHTMLParseableContentType(resp.Header.Get("Content-Type")):
		// MIME-aware: skip the HTML parser on JSON/JS/CSS/binary bodies — running
		// html.Parse over a large non-HTML body is wasted work. Pre-seed HTML=nil
		// with the not-HTML sentinel so extractInternal's lazy ParseHTML no-ops and
		// the DOM extractors are skipped; the inline URL scanner still runs on the
		// raw bytes (so URLs inside JSON/JS are still discovered).
		response = NewHTTPResponseWithHTML(baseURL, resp.Header, body, 0, nil, ErrNotHTMLContentType)
	default:
		doc, parseErr := rc.ParseHTML()
		response = NewHTTPResponseWithHTML(baseURL, resp.Header, body, 0, doc, parseErr)
	}
	return ec.extractInternal(ctx, baseURL, response)
}

// extractInternal performs the actual extraction logic on an HTTPResponse.
// This is separated to allow tests to use pre-constructed HTTPResponse objects.
func (ec *ExtractionCoordinator) extractInternal(ctx context.Context, baseURL *url.URL, response *HTTPResponse) (*ExtractionResult, error) {
	var links []*DiscoveredLink

	// Single callback to collect all links
	callback := func(link *DiscoveredLink) {
		links = append(links, link)
	}

	// Step 1: Always run inline URL scanner
	if err := ec.inlineScanner.Extract(ctx, baseURL, response, callback); err != nil {
		return nil, err
	}

	// Step 2: Check if body is large enough for HTML processing
	if len(response.Body) < 10 {
		return &ExtractionResult{
			Links:           extractURLs(links),
			DiscoveredLinks: links,
			JSURLs:          extractJSURLs(links),
		}, nil
	}

	// Step 3: Parse HTML if not already parsed (uses sync.Once for caching)
	_ = response.ParseHTML()

	// Step 4: HTTP header extractor
	if err := ec.httpHeaders.Extract(ctx, baseURL, response, callback); err != nil {
		return nil, err
	}

	// Step 5: HTML-based extractors (only if HTML parsed successfully)
	if response.HTML != nil {
		// HTML attribute extractor
		if err := ec.htmlAttrs.Extract(ctx, baseURL, response, callback); err != nil {
			return nil, err
		}

		// Comment extractor
		if err := ec.comments.Extract(ctx, baseURL, response, callback); err != nil {
			return nil, err
		}

		// JavaScript string extractor
		if err := ec.jsExtractor.Extract(ctx, baseURL, response, callback); err != nil {
			return nil, err
		}

		// Event handlers extractor
		if err := ec.eventHandlers.Extract(ctx, baseURL, response, callback); err != nil {
			return nil, err
		}

		// Meta refresh extractor
		if err := ec.metaRefresh.Extract(ctx, baseURL, response, callback); err != nil {
			return nil, err
		}

		// Script content extractor
		if err := ec.scriptContent.Extract(ctx, baseURL, response, callback); err != nil {
			return nil, err
		}
	}

	// Step 6: Robots.txt parser
	if err := ec.robotsParser.Extract(ctx, baseURL, response, callback); err != nil {
		return nil, err
	}

	// Step 7: Form extractor (extracts actionable form submissions)
	var formRequests []*FormRequest
	if ec.formExtractor != nil {
		forms, err := ec.formExtractor.ExtractForms(ctx, baseURL, response)
		if err == nil && len(forms) > 0 {
			formRequests = forms
		}
		// Errors are logged but don't fail extraction - forms are optional
	}

	return &ExtractionResult{
		Links:           extractURLs(links),
		DiscoveredLinks: links,
		JSURLs:          extractJSURLs(links),
		FormRequests:    formRequests,
	}, nil
}

// extractURLs extracts URL pointers from DiscoveredLink slice.
func extractURLs(links []*DiscoveredLink) []*url.URL {
	if len(links) == 0 {
		return nil
	}
	urls := make([]*url.URL, len(links))
	for i, link := range links {
		urls[i] = link.URL
	}
	return urls
}

// extractJSURLs filters JavaScript URLs from discovered links.
// JS files are identified by ResourceType == ResourceScript.
func extractJSURLs(links []*DiscoveredLink) []*url.URL {
	var js []*url.URL
	for _, link := range links {
		if link.ResourceType == ResourceScript || strings.HasSuffix(link.URL.Path, ".js") {
			js = append(js, link.URL)
		}
	}
	return js
}
