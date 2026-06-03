package discovery

import (
	"context"
	"encoding/json"
	"hash/fnv"
	"net/url"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/jsscan"
)

// JSExtractedRequestTask processes HTTP requests extracted from JavaScript files.
// One task per directory, processes ALL extracted requests from jsscan.
// Generates GET + POST (json) + POST (form) + original method variants.
//
// Priority 3 - same level as observed extensions.
type JSExtractedRequestTask struct {
	dirURL               *url.URL
	depth                uint16
	cachedHash           uint64
	getExtractedRequests func() []jsscan.ExtractedRequest
}

// JSExtractedRequestTaskConfig contains configuration for creating a JSExtractedRequestTask.
type JSExtractedRequestTaskConfig struct {
	DirURL               *url.URL
	Depth                uint16
	GetExtractedRequests func() []jsscan.ExtractedRequest
}

// RequestVariant represents a single HTTP request variant to execute.
type RequestVariant struct {
	Method      string
	URL         string
	Body        string
	ContentType string // application/json or application/x-www-form-urlencoded
}

// nonReplayableMethods are pseudo-methods jsscan emits for non-HTTP protocols
// (WebSocket, Server-Sent Events). They are recorded as extracted requests for
// discovery/reporting but must never be replayed as HTTP request variants.
var nonReplayableMethods = map[string]struct{}{
	"WS":  {}, // new WebSocket(url)
	"SSE": {}, // new EventSource(url)
}

// isReplayableMethod reports whether an extracted request method maps to a real
// HTTP verb that can safely be replayed against the target.
func isReplayableMethod(method string) bool {
	_, skip := nonReplayableMethods[strings.ToUpper(method)]
	return !skip
}

// NewJSExtractedRequestTask creates a new JS extracted request task with cached hash.
func NewJSExtractedRequestTask(cfg *JSExtractedRequestTaskConfig) *JSExtractedRequestTask {
	task := &JSExtractedRequestTask{
		dirURL:               cfg.DirURL,
		depth:                cfg.Depth,
		getExtractedRequests: cfg.GetExtractedRequests,
	}
	task.cachedHash = task.computeHash()
	return task
}

// Hash returns the cached hash computed at creation time.
func (t *JSExtractedRequestTask) Hash() uint64 {
	return t.cachedHash
}

// computeHash computes FNV-1a 64-bit hash for task deduplication.
// Hash includes directory URL to allow same endpoints tested against different directories.
func (t *JSExtractedRequestTask) computeHash() uint64 {
	h := fnv.New64a()

	// Include priority
	h.Write([]byte{PriorityJSExtractedRequest})
	h.Write([]byte{0})

	// Include task type marker
	h.Write([]byte("jsextracted"))
	h.Write([]byte{0})

	// Include directory URL (normalized)
	h.Write([]byte(t.dirURL.Scheme))
	h.Write([]byte("://"))
	h.Write([]byte(t.dirURL.Host))
	h.Write([]byte(t.dirURL.Path))

	return h.Sum64()
}

// Priority returns the task's priority level.
func (t *JSExtractedRequestTask) Priority() uint8 {
	return PriorityJSExtractedRequest
}

// Description returns a human-readable task description.
func (t *JSExtractedRequestTask) Description() string {
	return "JS extracted requests (" + t.dirURL.Path + ")"
}

// FoundByName returns a short identifier for result attribution.
func (t *JSExtractedRequestTask) FoundByName() string {
	return "js-extracted"
}

// PayloadProvider returns nil - this task iterates extracted requests directly.
func (t *JSExtractedRequestTask) PayloadProvider() payload.Provider {
	return nil
}

// FullURL returns the directory URL.
func (t *JSExtractedRequestTask) FullURL() []byte {
	return []byte(t.dirURL.String())
}

// Extension returns empty string - this task doesn't test extensions.
func (t *JSExtractedRequestTask) Extension() string {
	return ""
}

// Depth returns the discovery depth.
func (t *JSExtractedRequestTask) Depth() uint16 {
	return t.depth
}

// IsFromSpider returns false.
func (t *JSExtractedRequestTask) IsFromSpider() bool {
	return false
}

// DirURL returns the directory URL for coordinator access.
func (t *JSExtractedRequestTask) DirURL() *url.URL {
	return t.dirURL
}

// GetExtractedRequestsFunc returns the function to get extracted requests.
func (t *JSExtractedRequestTask) GetExtractedRequestsFunc() func() []jsscan.ExtractedRequest {
	return t.getExtractedRequests
}

// Expand iterates through all extracted requests and emits URL variants.
// For each extracted request, generates GET + POST variants with merged paths.
func (t *JSExtractedRequestTask) Expand(ctx context.Context, callback func(url string, depth uint16)) error {
	requests := t.getExtractedRequests()

	for i := range requests {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		variants := t.generateVariants(&requests[i])
		for _, v := range variants {
			if v.URL != "" {
				callback(v.URL, t.depth)
			}
		}
	}

	return nil
}

// GenerateAllVariants returns all request variants for coordinator to execute.
// This is called by coordinator to get Method/Body/ContentType for each request.
func (t *JSExtractedRequestTask) GenerateAllVariants() []RequestVariant {
	requests := t.getExtractedRequests()
	var allVariants []RequestVariant

	for i := range requests {
		variants := t.generateVariants(&requests[i])
		allVariants = append(allVariants, variants...)
	}

	return allVariants
}

// generateVariants generates all HTTP request variants for a single extracted request.
// Returns: GET, POST(json), POST(form), and original method variants.
func (t *JSExtractedRequestTask) generateVariants(req *jsscan.ExtractedRequest) []RequestVariant {
	resolvedURL := t.resolveRequestURL(req)
	if resolvedURL == "" {
		return nil
	}

	params := ReplaceTemplateVars(req.Params)
	body := ReplaceTemplateVars(req.Body)
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = "GET"
	}

	// Non-HTTP pseudo-methods (WS/SSE) are recorded but never replayed as HTTP.
	if !isReplayableMethod(method) {
		return nil
	}

	var variants []RequestVariant

	// Variant 1: GET with params as query string
	getURL := resolvedURL
	if params != "" {
		if strings.Contains(getURL, "?") {
			getURL += "&" + params
		} else {
			getURL += "?" + params
		}
	}
	variants = append(variants, RequestVariant{
		Method: "GET",
		URL:    getURL,
	})

	// Variant 2 & 3: POST with both Content-Types
	if method != "GET" || body != "" || params != "" {
		postBody := body
		if postBody == "" && params != "" {
			postBody = params
		}

		// POST with JSON
		jsonBody := t.convertToJSON(postBody)
		variants = append(variants, RequestVariant{
			Method:      "POST",
			URL:         resolvedURL,
			Body:        jsonBody,
			ContentType: "application/json",
		})

		// POST with form-urlencoded
		formBody := t.convertToForm(postBody)
		variants = append(variants, RequestVariant{
			Method:      "POST",
			URL:         resolvedURL,
			Body:        formBody,
			ContentType: "application/x-www-form-urlencoded",
		})
	}

	// Variant 4+: Original method if not GET/POST
	if method != "GET" && method != "POST" {
		methodBody := body
		if methodBody == "" && params != "" {
			methodBody = params
		}

		// Original method with JSON
		jsonBody := t.convertToJSON(methodBody)
		variants = append(variants, RequestVariant{
			Method:      method,
			URL:         resolvedURL,
			Body:        jsonBody,
			ContentType: "application/json",
		})

		// Original method with form-urlencoded
		formBody := t.convertToForm(methodBody)
		variants = append(variants, RequestVariant{
			Method:      method,
			URL:         resolvedURL,
			Body:        formBody,
			ContentType: "application/x-www-form-urlencoded",
		})
	}

	return variants
}

// resolveRequestURL resolves the extracted request URL against the directory URL.
// Uses MergePathWithBase for intelligent path merging.
func (t *JSExtractedRequestTask) resolveRequestURL(req *jsscan.ExtractedRequest) string {
	rawURL := req.URL
	if rawURL == "" {
		return ""
	}

	// Normalize template variables: ${apiURL} → 1
	rawURL = ReplaceTemplateVars(rawURL)

	// Parse the extracted URL to separate path from query params
	parsedReq, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	var resolvedPath string

	// Case 1: Absolute URL with scheme and host
	if parsedReq.Scheme != "" && parsedReq.Host != "" {
		// Different host - use as-is
		if parsedReq.Host != t.dirURL.Host {
			return rawURL
		}
		// Same host - use path only
		resolvedPath = parsedReq.Path
	} else {
		// Case 2 & 3: Absolute path or relative path - merge with directory
		pathOnly := parsedReq.Path
		if pathOnly == "" {
			pathOnly = "/"
		}

		// Use MergePathWithBase for intelligent path merging
		dirPath := t.dirURL.Path
		if dirPath == "" {
			dirPath = "/"
		}
		mergedPath := payload.MergePathWithBase(pathOnly, dirPath)
		if mergedPath == "" {
			return "" // Skip (parent, exact match, etc.)
		}
		resolvedPath = mergedPath
	}

	// Build final URL with original query params from extracted request
	result := *t.dirURL
	result.Path = resolvedPath
	result.RawQuery = parsedReq.RawQuery // Keep original query params
	result.Fragment = ""
	return result.String()
}

// convertToJSON converts a body string to JSON format.
// If already JSON, returns as-is. Otherwise, converts form-encoded to JSON.
func (t *JSExtractedRequestTask) convertToJSON(body string) string {
	if body == "" {
		return "{}"
	}

	trimmed := strings.TrimSpace(body)

	// Already JSON
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return body
	}

	// Convert form-encoded to JSON
	values, err := url.ParseQuery(body)
	if err != nil {
		// Can't parse, wrap as simple JSON
		return `{"data":"` + escapeJSONString(body) + `"}`
	}

	jsonMap := make(map[string]interface{})
	for k, v := range values {
		if len(v) == 1 {
			jsonMap[k] = v[0]
		} else {
			jsonMap[k] = v
		}
	}

	jsonBytes, err := json.Marshal(jsonMap)
	if err != nil {
		return "{}"
	}
	return string(jsonBytes)
}

// convertToForm converts a body string to form-urlencoded format.
// If already form-encoded, returns as-is. Otherwise, converts JSON to form.
func (t *JSExtractedRequestTask) convertToForm(body string) string {
	if body == "" {
		return ""
	}

	trimmed := strings.TrimSpace(body)

	// Not JSON - assume already form-encoded
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return body
	}

	// Convert JSON to form-encoded
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		// Can't parse JSON, return as-is
		return body
	}

	values := url.Values{}
	for k, v := range data {
		switch val := v.(type) {
		case string:
			values.Set(k, val)
		case float64:
			// Format number without trailing zeros
			if val == float64(int64(val)) {
				values.Set(k, strconv.FormatInt(int64(val), 10))
			} else {
				values.Set(k, strconv.FormatFloat(val, 'f', -1, 64))
			}
		case bool:
			if val {
				values.Set(k, "true")
			} else {
				values.Set(k, "false")
			}
		case nil:
			values.Set(k, "")
		default:
			// For complex types, marshal to JSON string
			jsonVal, _ := json.Marshal(val)
			values.Set(k, string(jsonVal))
		}
	}

	return values.Encode()
}

// escapeJSONString escapes a string for use in JSON.
func escapeJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	// Remove surrounding quotes
	return string(b[1 : len(b)-1])
}
