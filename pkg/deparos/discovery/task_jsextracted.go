package discovery

import (
	"context"
	"hash/fnv"
	"net/url"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
)

// JSExtractedRequestTask replays source-scoped request templates. The registry
// returns each new template once, so adding crawler directories cannot multiply
// request traffic by directories × endpoints.
type JSExtractedRequestTask struct {
	dirURL               *url.URL
	depth                uint16
	cachedHash           uint64
	getExtractedRequests func() []jstangle.ExtractedRequest // v1 compatibility
	getRequestTemplates  func() []ExtractedRequestTemplate
}

type JSExtractedRequestTaskConfig struct {
	DirURL               *url.URL
	Depth                uint16
	GetExtractedRequests func() []jstangle.ExtractedRequest
	GetRequestTemplates  func() []ExtractedRequestTemplate
}

type RequestVariant struct {
	Method       string
	URL          string
	Body         string
	ContentType  string
	Headers      []string
	TemplateID   string
	SourceURL    string
	Extractor    string
	Confidence   string
	ReplayTier   string // exact | conservative | mutation
	Generated    bool
	SourceMapped bool
}

var nonReplayableMethods = map[string]struct{}{
	"WS":  {},
	"SSE": {},
}

func isReplayableMethod(method string) bool {
	_, skip := nonReplayableMethods[strings.ToUpper(method)]
	return !skip
}

func NewJSExtractedRequestTask(cfg *JSExtractedRequestTaskConfig) *JSExtractedRequestTask {
	task := &JSExtractedRequestTask{
		dirURL: cfg.DirURL, depth: cfg.Depth,
		getExtractedRequests: cfg.GetExtractedRequests,
		getRequestTemplates:  cfg.GetRequestTemplates,
	}
	task.cachedHash = task.computeHash()
	return task
}

func (t *JSExtractedRequestTask) Hash() uint64 { return t.cachedHash }

func (t *JSExtractedRequestTask) computeHash() uint64 {
	h := fnv.New64a()
	h.Write([]byte{PriorityJSExtractedRequest, 0})
	h.Write([]byte("jsextracted"))
	// Keep directory in the scheduling hash. Each execution atomically claims
	// only newly-added templates, so later JS discoveries still get a chance to
	// replay without reprocessing older templates.
	h.Write([]byte{0})
	h.Write([]byte(t.dirURL.Scheme))
	h.Write([]byte("://"))
	h.Write([]byte(t.dirURL.Host))
	h.Write([]byte(t.dirURL.Path))
	return h.Sum64()
}

func (t *JSExtractedRequestTask) Priority() uint8 { return PriorityJSExtractedRequest }
func (t *JSExtractedRequestTask) Description() string {
	return "JS extracted requests (" + t.dirURL.Path + ")"
}
func (t *JSExtractedRequestTask) FoundByName() string               { return "js-extracted" }
func (t *JSExtractedRequestTask) PayloadProvider() payload.Provider { return nil }
func (t *JSExtractedRequestTask) FullURL() []byte                   { return []byte(t.dirURL.String()) }
func (t *JSExtractedRequestTask) Extension() string                 { return "" }
func (t *JSExtractedRequestTask) Depth() uint16                     { return t.depth }
func (t *JSExtractedRequestTask) IsFromSpider() bool                { return false }
func (t *JSExtractedRequestTask) DirURL() *url.URL                  { return t.dirURL }
func (t *JSExtractedRequestTask) GetExtractedRequestsFunc() func() []jstangle.ExtractedRequest {
	return t.getExtractedRequests
}

func (t *JSExtractedRequestTask) Expand(ctx context.Context, callback func(url string, depth uint16)) error {
	for _, variant := range t.GenerateAllVariants() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if variant.URL != "" {
			callback(variant.URL, t.depth)
		}
	}
	return nil
}

func (t *JSExtractedRequestTask) GenerateAllVariants() []RequestVariant {
	if t.getRequestTemplates != nil {
		templates := t.getRequestTemplates()
		variants := make([]RequestVariant, 0, len(templates))
		for i := range templates {
			variants = append(variants, t.generateTemplateVariants(&templates[i])...)
		}
		return deduplicateReplayVariants(variants)
	}

	// Temporary v1 compatibility for direct unit/API users. Legacy requests are
	// replayed exactly; method/content-type permutations are no longer implicit.
	if t.getExtractedRequests == nil {
		return nil
	}
	requests := t.getExtractedRequests()
	variants := make([]RequestVariant, 0, len(requests))
	for i := range requests {
		variants = append(variants, t.generateVariants(&requests[i])...)
	}
	return deduplicateReplayVariants(variants)
}

func (t *JSExtractedRequestTask) generateTemplateVariants(template *ExtractedRequestTemplate) []RequestVariant {
	fact := &template.Request
	confidence := fact.Provenance.Confidence
	if confidence == "low" || !isReplayableMethod(fact.Method.Rendered) {
		return nil // Tier C: discovery hint only; never direct network traffic.
	}
	method := strings.ToUpper(fact.Method.Rendered)
	if method == "" {
		method = "GET"
	}
	query := renderFactFields(fact.Query)
	body := ""
	contentType := ""
	if fact.Body != nil {
		body = ReplaceTemplateVars(fact.Body.Value.Rendered)
		contentType = fact.Body.ContentType
	}
	headers := safeReplayHeaders(fact)
	if contentType == "" {
		contentType = headerValue(headers, "Content-Type")
	}

	urls := append([]string{fact.URL.Rendered}, fact.URL.Alternatives...)
	maxURLs := 3
	replayTier := "exact"
	if confidence == "medium" {
		maxURLs = 2
		replayTier = "conservative"
	}
	variants := make([]RequestVariant, 0, min(maxURLs, len(urls)))
	for _, candidate := range urls {
		if len(variants) >= maxURLs {
			break
		}
		resolved := resolveReplayURL(candidate, template.SourceURL, t.dirURL)
		if resolved == "" {
			continue
		}
		resolved = mergeRenderedQuery(resolved, query)
		variants = append(variants, RequestVariant{
			Method: method, URL: resolved, Body: body, ContentType: contentType,
			Headers: append([]string(nil), headers...), TemplateID: template.ID,
			SourceURL: template.SourceURL, Extractor: fact.Provenance.Extractor,
			Confidence: confidence, ReplayTier: replayTier,
			SourceMapped: sourceMappedFact(fact),
		})
	}
	return variants
}

func (t *JSExtractedRequestTask) generateVariants(req *jstangle.ExtractedRequest) []RequestVariant {
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = "GET"
	}
	if !isReplayableMethod(method) {
		return nil
	}
	resolved := resolveReplayURL(req.URL, "", t.dirURL)
	if resolved == "" {
		return nil
	}
	resolved = mergeRenderedQuery(resolved, req.Params)
	headers := safeLegacyHeaders(req.Headers)
	return []RequestVariant{{
		Method: method, URL: resolved, Body: ReplaceTemplateVars(req.Body),
		ContentType: headerValue(headers, "Content-Type"), Headers: headers,
		Confidence: "medium", ReplayTier: "conservative", Extractor: "legacy-v1",
	}}
}

// resolveReplayURL resolves a JS-extracted endpoint reference to the absolute URL
// to replay. Every fact that reaches this HTTP-request replay path comes from a
// browser network client (fetch / XHR / axios / generic / graphql / protocol),
// all of which resolve a relative endpoint against the DOCUMENT that loaded the
// script (document.baseURI) — NOT against the script's own URL. Module-URL
// resolution (dynamic import(), import.meta.url, new URL(x, import.meta.url))
// applies to asset references, a separate fact type handled by the asset graph,
// not replayed here — so the module/script URL is deliberately never used as the
// base for a replay.
//
// We do not observe the exact document, so relative references resolve against
// the application origin root (scheme://host/): always correct for root-relative
// refs ("/api"), and correct for the common SPA-served-at-root case for
// path-relative refs ("api", "./api", "../api"). The previous behavior resolved
// against the bundle's asset directory, which turned fetch('api/users') on
// https://h/assets/app.js into the non-existent https://h/assets/api/users.
// sourceURL (the bundle) and fallback (the crawl directory) are consulted only to
// recover the origin, never its path.
func resolveReplayURL(rawURL, sourceURL string, fallback *url.URL) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" || strings.HasPrefix(rawURL, "${") {
		return ""
	}
	rawURL = ReplaceTemplateVars(rawURL)
	reference, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if reference.IsAbs() {
		reference.Fragment = ""
		return reference.String()
	}
	origin := originRoot(sourceURL)
	if origin == nil && fallback != nil && fallback.Scheme != "" && fallback.Host != "" {
		// fallback is already parsed — read its origin directly rather than
		// re-stringifying and re-parsing it.
		origin = &url.URL{Scheme: fallback.Scheme, Host: fallback.Host, Path: "/"}
	}
	if origin == nil {
		return ""
	}
	resolved := origin.ResolveReference(reference)
	resolved.Fragment = ""
	return resolved.String()
}

// originRoot returns scheme://host/ for a URL string that carries both a scheme
// and a host, else nil. It intentionally discards the path so a relative endpoint
// resolves against the application root rather than an asset subdirectory.
func originRoot(rawURL string) *url.URL {
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}
}

func mergeRenderedQuery(rawURL, renderedQuery string) string {
	if renderedQuery == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	renderedQuery = ReplaceTemplateVars(renderedQuery)
	if u.RawQuery == "" {
		u.RawQuery = renderedQuery
	} else {
		u.RawQuery += "&" + renderedQuery
	}
	return u.String()
}

func renderFactFields(fields []jstangle.FieldTemplate) string {
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		parts = append(parts,
			url.QueryEscape(ReplaceTemplateVars(field.Name.Rendered))+"="+
				url.QueryEscape(ReplaceTemplateVars(field.Value.Rendered)))
	}
	return strings.Join(parts, "&")
}

func parseTemplateFields(value string) url.Values {
	fields, err := url.ParseQuery(value)
	if err == nil {
		return fields
	}
	return url.Values{"value": []string{value}}
}

func splitHeader(header string) (string, string) {
	name, value, found := strings.Cut(header, ":")
	if !found {
		return strings.TrimSpace(header), ""
	}
	return strings.TrimSpace(name), strings.TrimSpace(value)
}

func isSensitiveHeader(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return lower == "authorization" || lower == "proxy-authorization" || lower == "cookie" ||
		lower == "x-api-key" || strings.Contains(lower, "csrf") || strings.Contains(lower, "xsrf")
}

func isBrowserControlledHeader(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return lower == "host" || lower == "content-length" || lower == "connection" || lower == "upgrade" ||
		lower == "origin" || lower == "referer" || strings.HasPrefix(lower, "sec-")
}

func safeReplayHeaders(fact *jstangle.HTTPRequestFact) []string {
	if fact == nil {
		return nil
	}
	result := make([]string, 0, len(fact.Headers))
	protocolHandshake := fact.Provenance.Extractor == "websocket-handshake"
	for _, header := range fact.Headers {
		name, value := header.Name.Rendered, header.Value.Rendered
		controlled := isBrowserControlledHeader(name)
		if protocolHandshake && (strings.EqualFold(name, "Connection") || strings.EqualFold(name, "Upgrade") || strings.HasPrefix(strings.ToLower(name), "sec-websocket-")) {
			controlled = false
		}
		if name == "" || header.Sensitive || isSensitiveHeader(name) || controlled ||
			!header.Name.Static || !header.Value.Static {
			continue
		}
		result = append(result, name+": "+value)
	}
	sort.Strings(result)
	return result
}

func safeLegacyHeaders(headers []string) []string {
	result := make([]string, 0, len(headers))
	for _, header := range headers {
		name, value := splitHeader(header)
		if name == "" || isSensitiveHeader(name) || isBrowserControlledHeader(name) || ContainsTemplateVar(value) {
			continue
		}
		result = append(result, name+": "+value)
	}
	sort.Strings(result)
	return result
}

func headerValue(headers []string, wanted string) string {
	for _, header := range headers {
		name, value := splitHeader(header)
		if strings.EqualFold(name, wanted) {
			return value
		}
	}
	return ""
}

func headerSliceToMap(headers []string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	result := make(map[string]string, len(headers))
	for _, header := range headers {
		name, value := splitHeader(header)
		if name != "" {
			result[name] = value
		}
	}
	return result
}

func inferBodyKind(body string, headers []string) string {
	contentType := headerValue(headers, "Content-Type")
	trimmed := strings.TrimSpace(body)
	if strings.Contains(strings.ToLower(contentType), "json") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "json"
	}
	if strings.Contains(strings.ToLower(contentType), "x-www-form-urlencoded") || strings.Contains(body, "=") {
		return "form"
	}
	return "text"
}

func deduplicateReplayVariants(variants []RequestVariant) []RequestVariant {
	seen := make(map[string]int, len(variants))
	result := make([]RequestVariant, 0, len(variants))
	for _, variant := range variants {
		key := variant.Method + "\x00" + variant.URL + "\x00" + variant.Body + "\x00" + strings.Join(variant.Headers, "\x00")
		if index, ok := seen[key]; ok {
			if variant.SourceMapped && !result[index].SourceMapped {
				result[index] = variant
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, variant)
	}
	return result
}

func sourceMappedFact(fact *jstangle.HTTPRequestFact) bool {
	if fact == nil {
		return false
	}
	for _, step := range fact.Provenance.ResolutionSteps {
		if step.Kind == "source-map" {
			return true
		}
	}
	return false
}
