package runner

import (
	"bytes"
	"context"
	"fmt"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// HeuristicsResult holds the analysis of a single target's root page.
type HeuristicsResult struct {
	Target        string
	StatusCode    int16
	ContentType   string // "blank", "html", "json", "xml", "text"
	BodyLength    int
	LinkCount     int  // advanced only
	IsSPA         bool // advanced only
	SkipSpidering bool
	Reason        string
}

// runHeuristicsCheckPhase probes the root page of each CLI target and
// classifies the response to decide whether spidering is worthwhile.
func (r *Runner) runHeuristicsCheckPhase(ctx context.Context, infra *phaseInfra) (map[string]*HeuristicsResult, error) {
	phaseStart := time.Now()
	r.printPhaseStart("HeuristicsCheck", "probing CLI target root pages to optimize phase selection")

	level := r.options.HeuristicsCheck
	r.printPhaseDetail(fmt.Sprintf("Level: %s | Targets: %s",
		terminal.HiTeal(level),
		terminal.Orange(fmt.Sprintf("%d", len(r.options.Targets)))))

	results := make(map[string]*HeuristicsResult, len(r.options.Targets))
	for _, target := range r.options.Targets {
		rootURL := normalizeToRoot(target)
		result := probeTarget(ctx, infra.httpRequester, rootURL, level)
		results[target] = result

		// Log each result
		if result.SkipSpidering {
			zap.L().Info("HeuristicsCheck: target flagged",
				zap.String("target", target),
				zap.String("reason", result.Reason),
				zap.String("content_type", result.ContentType))
			if !r.options.Silent {
				fmt.Fprintf(os.Stderr, "  %s %s — %s\n",
					terminal.Orange(terminal.SymbolArrow),
					terminal.Gray(target),
					terminal.Orange(result.Reason))
			}
		} else {
			zap.L().Info("HeuristicsCheck: target passed",
				zap.String("target", target),
				zap.String("content_type", result.ContentType))
			if r.options.Verbose && !r.options.Silent {
				fmt.Fprintf(os.Stderr, "  %s HeuristicsCheck: target passed | Target: %s | Content-Type: %s\n",
					terminal.Purple(terminal.SymbolInfo),
					terminal.Orange(target),
					terminal.Orange(result.ContentType))
			}
		}
	}

	elapsed := time.Since(phaseStart)
	skipped := 0
	for _, res := range results {
		if res.SkipSpidering {
			skipped++
		}
	}
	if skipped > 0 {
		r.printPhaseDetail(fmt.Sprintf("Skipping spidering: %s | Elapsed: %s",
			terminal.Orange(fmt.Sprintf("%d/%d targets", skipped, len(results))),
			terminal.Orange(fmtDuration(elapsed))))
	} else {
		r.printPhaseDetail(fmt.Sprintf("Elapsed: %s", terminal.Orange(fmtDuration(elapsed))))
	}

	return results, nil
}

// normalizeToRoot strips the path and query from a URL, returning scheme://host/.
func normalizeToRoot(target string) string {
	u, err := neturl.Parse(target)
	if err != nil {
		return target
	}
	// Ensure scheme
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	u.Path = "/"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// probeTarget sends a GET request to the root URL and classifies the response.
func probeTarget(_ context.Context, requester *http.Requester, rootURL string, level string) *HeuristicsResult {
	result := &HeuristicsResult{
		Target: rootURL,
	}

	rr, err := httpmsg.GetRawRequestFromURL(rootURL)
	if err != nil {
		zap.L().Warn("HeuristicsCheck: failed to build request",
			zap.String("url", rootURL), zap.Error(err))
		result.ContentType = "error"
		result.Reason = "failed to build request"
		// Don't skip on errors — let phases try
		return result
	}

	respChain, _, err := requester.Execute(rr, http.Options{DisableCompression: true})
	if err != nil {
		zap.L().Warn("HeuristicsCheck: request failed",
			zap.String("url", rootURL), zap.Error(err))
		result.ContentType = "error"
		result.Reason = "request failed"
		// Don't skip on errors — let phases try
		return result
	}

	fullResp := respChain.FullResponse().Bytes()
	if len(fullResp) == 0 {
		result.ContentType = "blank"
		result.SkipSpidering = true
		result.Reason = "empty response"
		return result
	}

	result.StatusCode = httpmsg.GetStatusCode(fullResp)

	// Classify using GetStartType
	startType := httpmsg.GetStartType(fullResp)

	// Calculate body length
	bodyOffset := httpmsg.FindBodyOffset(fullResp)
	if bodyOffset >= 0 && bodyOffset < len(fullResp) {
		result.BodyLength = len(fullResp) - bodyOffset
	}

	// Basic classification
	switch startType {
	case "[blank]":
		// Before concluding the target is blank, probe secondary paths to
		// guard against decompression issues or servers that return an
		// empty root but serve content elsewhere.
		if confirmBlank(requester, rootURL) {
			result.ContentType = "blank"
			result.SkipSpidering = true
			result.Reason = "blank/empty root page (confirmed via /robots.txt and /index.html)"
		} else {
			result.ContentType = "html"
			result.SkipSpidering = false
			zap.L().Info("HeuristicsCheck: root page blank but secondary paths returned content",
				zap.String("url", rootURL))
		}
	case "json":
		result.ContentType = "json"
		result.SkipSpidering = true
		result.Reason = "API endpoint (JSON)"
	case "<?xml":
		result.ContentType = "xml"
		result.SkipSpidering = true
		result.Reason = "API endpoint (XML)"
	case "xml":
		// GetStartType returns "xml" for any generic <tag. Check if the body
		// actually starts with a known HTML element before treating it as XML.
		// Also search deeper in the body for HTML markers.
		if bodyOffset >= 0 && bodyOffset < len(fullResp) &&
			(looksLikeHTMLTag(fullResp[bodyOffset:]) || containsHTMLMarker(fullResp[bodyOffset:])) {
			result.ContentType = "html"
			result.SkipSpidering = false
		} else {
			result.ContentType = "xml"
			result.SkipSpidering = true
			result.Reason = "API endpoint (XML)"
		}
	case "<html", "<head", "<body", "<!DOCTYPE", "<!--":
		result.ContentType = "html"
		result.SkipSpidering = false
	case "text":
		result.ContentType = "text"
		result.SkipSpidering = false
	default:
		result.ContentType = startType
		result.SkipSpidering = false
	}

	// Advanced classification (on top of basic)
	if level == "advanced" && result.ContentType == "html" && bodyOffset >= 0 && bodyOffset < len(fullResp) {
		body := fullResp[bodyOffset:]
		classifyAdvanced(result, body)
	}

	return result
}

// htmlTagPrefixes lists lowercase HTML element prefixes that GetStartType
// reports as generic "xml" but should be treated as HTML for heuristics.
// Compared case-insensitively.
var htmlTagPrefixes = [][]byte{
	[]byte("<a "),
	[]byte("<link"),
	[]byte("<script"),
	[]byte("<noscript"),
	[]byte("<div"),
	[]byte("<span"),
	[]byte("<p>"),
	[]byte("<p "),
	[]byte("<meta"),
	[]byte("<title"),
	[]byte("<style"),
	[]byte("<form"),
	[]byte("<table"),
	[]byte("<img"),
	[]byte("<nav"),
	[]byte("<header"),
	[]byte("<footer"),
	[]byte("<section"),
	[]byte("<main"),
}

// looksLikeHTMLTag checks whether the body (after skipping whitespace) starts
// with a known HTML element tag that GetStartType would misclassify as "xml".
func looksLikeHTMLTag(body []byte) bool {
	// Skip leading whitespace
	i := 0
	for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\n' || body[i] == '\r') {
		i++
	}
	remaining := body[i:]
	for _, prefix := range htmlTagPrefixes {
		if len(remaining) >= len(prefix) && bytes.EqualFold(remaining[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

// containsHTMLMarker searches the body for common HTML structural markers,
// catching pages where GetStartType returns "xml" but the content is HTML
// (e.g., body starts with a comment or non-standard tag).
func containsHTMLMarker(body []byte) bool {
	limit := len(body)
	if limit > 4096 {
		limit = 4096
	}
	lower := bytes.ToLower(body[:limit])
	markers := [][]byte{
		[]byte("<html"),
		[]byte("<head"),
		[]byte("<body"),
		[]byte("<!doctype"),
	}
	for _, m := range markers {
		if bytes.Contains(lower, m) {
			return true
		}
	}
	return false
}

// classifyAdvanced performs additional analysis on HTML responses:
// link counting and SPA framework detection.
func classifyAdvanced(result *HeuristicsResult, body []byte) {
	lowerBody := bytes.ToLower(body)

	// Count <a tags
	result.LinkCount = bytes.Count(lowerBody, []byte("<a "))

	// Detect SPA frameworks
	spaIndicators := [][]byte{
		[]byte("__next_data__"),
		[]byte("__nuxt__"),
		[]byte("ng-app"),
	}
	for _, indicator := range spaIndicators {
		if bytes.Contains(lowerBody, indicator) {
			result.IsSPA = true
			break
		}
	}

	// Check for id="app" + <script pattern (Vue/React SPA)
	if !result.IsSPA && bytes.Contains(lowerBody, []byte(`id="app"`)) && bytes.Contains(lowerBody, []byte("<script")) {
		result.IsSPA = true
	}

	// If HTML has zero links and is not a SPA, skip spidering
	if result.LinkCount == 0 && !result.IsSPA {
		result.SkipSpidering = true
		result.Reason = "HTML with no links and not a SPA"
	}
}

// confirmBlank probes /robots.txt and /index.html to verify the target truly
// has no content. Returns true only if all secondary paths also appear blank.
func confirmBlank(requester *http.Requester, rootURL string) bool {
	secondaryPaths := []string{"robots.txt", "index.html"}
	base := strings.TrimRight(rootURL, "/")

	for _, path := range secondaryPaths {
		probeURL := base + "/" + path
		rr, err := httpmsg.GetRawRequestFromURL(probeURL)
		if err != nil {
			continue
		}
		respChain, _, err := requester.Execute(rr, http.Options{DisableCompression: true})
		if err != nil {
			continue
		}
		fullResp := respChain.FullResponse().Bytes()
		if len(fullResp) == 0 {
			continue
		}

		statusCode := httpmsg.GetStatusCode(fullResp)
		if statusCode >= 400 {
			continue
		}

		startType := httpmsg.GetStartType(fullResp)
		if startType != "[blank]" {
			zap.L().Debug("HeuristicsCheck: secondary probe returned content",
				zap.String("url", probeURL),
				zap.String("start_type", startType))
			return false
		}
	}
	return true
}

// filterTargetsByHeuristics returns only the targets that should proceed,
// filtering out CLI targets flagged by the heuristics check.
// Targets not present in the results map (e.g. DB-discovered hosts) pass through.
func filterTargetsByHeuristics(targets []string, results map[string]*HeuristicsResult, skipFn func(*HeuristicsResult) bool) []string {
	filtered := make([]string, 0, len(targets))
	for _, t := range targets {
		hr, found := results[t]
		if !found || !skipFn(hr) {
			filtered = append(filtered, t)
		}
	}
	return filtered
}
