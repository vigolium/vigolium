package postman

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"go.uber.org/zap"
)

// Options contains Postman-specific parsing options.
type Options struct {
	// BaseURL replaces {{baseUrl}}, {{url}}, and similar variables
	BaseURL string

	// Variables maps variable names to values for {{varName}} substitution
	Variables map[string]string
}

// Format implements formats.Format for Postman Collection v2.1.
type Format struct {
	formatOpts  formats.InputFormatOptions
	postmanOpts Options
}

// New creates a new Postman Format parser.
func New() *Format {
	return &Format{}
}

var _ formats.Format = &Format{}

// Name returns the format name.
func (f *Format) Name() string {
	return "postman"
}

// SetOptions sets generic format options.
func (f *Format) SetOptions(options formats.InputFormatOptions) {
	f.formatOpts = options
}

// SetPostmanOptions sets Postman-specific options.
func (f *Format) SetPostmanOptions(opts Options) {
	f.postmanOpts = opts
}

// Parse reads a Postman Collection v2.1 JSON file and calls callback for each request.
func (f *Format) Parse(input string, callback formats.ParseReqRespCallback) error {
	data, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("failed to read postman collection: %w", err)
	}

	items, variables, err := f.unmarshalCollection(data)
	if err != nil {
		return fmt.Errorf("failed to parse postman collection: %w", err)
	}

	// Merge collection-level variables into the variable map
	varMap := f.buildVariableMap(variables)

	f.walkItems(items, varMap, callback)
	return nil
}

// ParseFromData parses a Postman Collection from raw bytes (no file I/O).
func (f *Format) ParseFromData(data []byte, callback formats.ParseReqRespCallback) error {
	items, variables, err := f.unmarshalCollection(data)
	if err != nil {
		return fmt.Errorf("failed to parse postman collection: %w", err)
	}

	varMap := f.buildVariableMap(variables)
	f.walkItems(items, varMap, callback)
	return nil
}

// Count returns the number of requests in the collection.
func (f *Format) Count(input string) (int64, error) {
	data, err := os.ReadFile(input)
	if err != nil {
		return 0, err
	}

	items, _, err := f.unmarshalCollection(data)
	if err != nil {
		return 0, err
	}

	return countItems(items), nil
}

// --- Postman JSON structures ---

type collection struct {
	Info       json.RawMessage `json:"info"`
	Item       []item          `json:"item"`
	Variable   []variable      `json:"variable"`
	Collection *collectionWrap `json:"collection"`
}

type collectionWrap struct {
	Item     []item     `json:"item"`
	Variable []variable `json:"variable"`
}

type item struct {
	Name    string   `json:"name"`
	Item    []item   `json:"item"` // nested folder
	Request *request `json:"request"`
}

type request struct {
	Method string   `json:"method"`
	Header []header `json:"header"`
	Body   *body    `json:"body"`
	URL    urlField `json:"url"`
}

type header struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Disabled bool   `json:"disabled"`
}

type body struct {
	Mode       string     `json:"mode"`
	Raw        string     `json:"raw"`
	URLEncoded []keyValue `json:"urlencoded"`
	FormData   []keyValue `json:"formdata"`
}

type keyValue struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Disabled bool   `json:"disabled"`
}

type urlField struct {
	Raw      string     `json:"raw"`
	Host     []string   `json:"host"`
	Path     []string   `json:"path"`
	Query    []keyValue `json:"query"`
	Variable []keyValue `json:"variable"`
}

type variable struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// --- Internal methods ---

// unmarshalCollection handles both wrapped ({collection: {item: [...]}}) and
// unwrapped ({item: [...]}) Postman collection formats.
func (f *Format) unmarshalCollection(data []byte) ([]item, []variable, error) {
	var col collection
	if err := json.Unmarshal(data, &col); err != nil {
		return nil, nil, err
	}

	// Wrapped format: {collection: {item: [...]}}
	if col.Collection != nil && len(col.Collection.Item) > 0 {
		return col.Collection.Item, col.Collection.Variable, nil
	}

	// Unwrapped format: {item: [...]}
	return col.Item, col.Variable, nil
}

// buildVariableMap merges collection variables, user-provided variables, and BaseURL.
func (f *Format) buildVariableMap(collectionVars []variable) map[string]string {
	vars := make(map[string]string)

	// Collection-level variables (lowest priority)
	for _, v := range collectionVars {
		vars[v.Key] = v.Value
	}

	// User-provided variables (higher priority)
	for k, v := range f.postmanOpts.Variables {
		vars[k] = v
	}

	// BaseURL override (highest priority for common URL variables)
	if f.postmanOpts.BaseURL != "" {
		vars["baseUrl"] = f.postmanOpts.BaseURL
		vars["base_url"] = f.postmanOpts.BaseURL
		vars["url"] = f.postmanOpts.BaseURL
	}

	return vars
}

var varPattern = regexp.MustCompile(`\{\{([^}]+)\}\}`)

// replaceVariables substitutes {{varName}} with values from the variable map.
func replaceVariables(s string, vars map[string]string) string {
	return varPattern.ReplaceAllStringFunc(s, func(match string) string {
		key := match[2 : len(match)-2] // strip {{ and }}
		if val, ok := vars[key]; ok {
			return val
		}
		// For Postman dynamic variables like $randomXxx, use a placeholder
		if strings.HasPrefix(key, "$") {
			return "test"
		}
		return match // keep as-is if unknown
	})
}

// walkItems recursively processes items, calling callback for each request found.
func (f *Format) walkItems(items []item, vars map[string]string, callback formats.ParseReqRespCallback) {
	for i := range items {
		it := &items[i]

		// Recurse into folders
		if len(it.Item) > 0 {
			f.walkItems(it.Item, vars, callback)
		}

		if it.Request == nil {
			continue
		}

		rr, err := f.buildRequest(it.Request, vars)
		if err != nil {
			zap.L().Debug("postman: skipping request",
				zap.String("name", it.Name),
				zap.Error(err))
			continue
		}

		if !callback(rr) {
			return
		}
	}
}

// buildRequest converts a Postman request into an HttpRequestResponse.
func (f *Format) buildRequest(req *request, vars map[string]string) (*httpmsg.HttpRequestResponse, error) {
	// Build the full URL
	fullURL := f.buildURL(req, vars)
	if fullURL == "" {
		return nil, fmt.Errorf("empty URL")
	}

	// Build raw HTTP request
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = "GET"
	}

	// Parse URL to get path and host
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", fullURL, err)
	}

	path := parsedURL.RequestURI()
	host := parsedURL.Host

	// Build headers
	var headerLines []string
	headerLines = append(headerLines, fmt.Sprintf("Host: %s", host))

	hasContentType := false
	for _, h := range req.Header {
		if h.Disabled || h.Key == "" {
			continue
		}
		value := replaceVariables(h.Value, vars)
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", h.Key, value))
		if strings.EqualFold(h.Key, "Content-Type") {
			hasContentType = true
		}
	}

	// Build body
	bodyStr := f.buildBody(req.Body, vars)

	// Add Content-Type if body present but no Content-Type header
	if bodyStr != "" && !hasContentType {
		headerLines = append(headerLines, "Content-Type: application/json")
	}

	// Add Content-Length for requests with body
	if bodyStr != "" {
		headerLines = append(headerLines, fmt.Sprintf("Content-Length: %d", len(bodyStr)))
	}

	// Assemble raw HTTP request
	var raw strings.Builder
	fmt.Fprintf(&raw, "%s %s HTTP/1.1\r\n", method, path)
	for _, h := range headerLines {
		raw.WriteString(h)
		raw.WriteString("\r\n")
	}
	raw.WriteString("\r\n")
	if bodyStr != "" {
		raw.WriteString(bodyStr)
	}

	return httpmsg.ParseRawRequestWithURL(raw.String(), fullURL)
}

// buildURL constructs the full URL from a Postman request's URL field.
func (f *Format) buildURL(req *request, vars map[string]string) string {
	u := &req.URL

	// Try to use the raw URL first
	if u.Raw != "" {
		rawURL := replaceVariables(u.Raw, vars)

		// Replace path variables like :username with variable values or defaults
		rawURL = f.replacePathVariables(rawURL, u.Variable, vars)

		// Add query parameters if present
		if len(u.Query) > 0 {
			sep := "?"
			if strings.Contains(rawURL, "?") {
				sep = "&"
			}
			var params []string
			for _, q := range u.Query {
				if q.Disabled {
					continue
				}
				key := replaceVariables(q.Key, vars)
				val := replaceVariables(q.Value, vars)
				params = append(params, fmt.Sprintf("%s=%s", url.QueryEscape(key), url.QueryEscape(val)))
			}
			if len(params) > 0 {
				rawURL += sep + strings.Join(params, "&")
			}
		}

		return rawURL
	}

	// Fallback: construct from host + path
	hostStr := replaceVariables(strings.Join(u.Host, "."), vars)
	pathStr := "/" + strings.Join(u.Path, "/")
	pathStr = replaceVariables(pathStr, vars)
	pathStr = f.replacePathVariables(pathStr, u.Variable, vars)

	return hostStr + pathStr
}

// replacePathVariables replaces :paramName path variables with values from
// Postman URL variables or the variable map.
func (f *Format) replacePathVariables(urlStr string, urlVars []keyValue, vars map[string]string) string {
	// Build a lookup from URL-level variables
	varLookup := make(map[string]string)
	for _, v := range urlVars {
		if v.Value != "" {
			varLookup[v.Key] = replaceVariables(v.Value, vars)
		}
	}

	// Replace :paramName patterns in path segments
	parts := strings.Split(urlStr, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, ":") {
			paramName := part[1:]
			if val, ok := varLookup[paramName]; ok {
				parts[i] = url.PathEscape(val)
			} else if val, ok := vars[paramName]; ok {
				parts[i] = url.PathEscape(val)
			} else {
				parts[i] = "test" // fallback placeholder
			}
		}
	}

	return strings.Join(parts, "/")
}

// buildBody builds the request body string from a Postman body object.
func (f *Format) buildBody(b *body, vars map[string]string) string {
	if b == nil {
		return ""
	}

	switch b.Mode {
	case "raw":
		return replaceVariables(b.Raw, vars)

	case "urlencoded":
		var pairs []string
		for _, kv := range b.URLEncoded {
			if kv.Disabled {
				continue
			}
			key := replaceVariables(kv.Key, vars)
			val := replaceVariables(kv.Value, vars)
			pairs = append(pairs, fmt.Sprintf("%s=%s", url.QueryEscape(key), url.QueryEscape(val)))
		}
		return strings.Join(pairs, "&")

	case "formdata":
		var pairs []string
		for _, kv := range b.FormData {
			if kv.Disabled {
				continue
			}
			key := replaceVariables(kv.Key, vars)
			val := replaceVariables(kv.Value, vars)
			pairs = append(pairs, fmt.Sprintf("%s=%s", url.QueryEscape(key), url.QueryEscape(val)))
		}
		return strings.Join(pairs, "&")

	default:
		return ""
	}
}

// countItems recursively counts the number of requests.
func countItems(items []item) int64 {
	var count int64
	for i := range items {
		if items[i].Request != nil {
			count++
		}
		if len(items[i].Item) > 0 {
			count += countItems(items[i].Item)
		}
	}
	return count
}
