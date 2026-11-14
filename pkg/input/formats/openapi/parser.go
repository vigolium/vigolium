package openapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/invopop/yaml"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// ResultCallback is called for each generated HttpRequestResponse.
type ResultCallback func(*httpmsg.HttpRequestResponse) bool

// pathOperation holds a single operation for sorting
type pathOperation struct {
	path     string
	method   string
	pathItem *openapi3.PathItem
	op       *openapi3.Operation
}

// methodPriority defines the sorting order for HTTP methods
// Lower value = higher priority (processed first)
var methodPriority = map[string]int{
	"GET":     0,
	"POST":    1,
	"PUT":     2,
	"PATCH":   3,
	"OPTIONS": 4,
	"HEAD":    5,
	"DELETE":  6,
}

// collectAndSortOperations collects all operations from schema and sorts them
// Primary sort: method priority (GET > POST > PUT > PATCH > OPTIONS > HEAD > DELETE)
// Secondary sort: path alphabetically
func collectAndSortOperations(paths *openapi3.Paths) []pathOperation {
	var ops []pathOperation

	for path, pathItem := range paths.Map() {
		for method, op := range pathItem.Operations() {
			ops = append(ops, pathOperation{
				path:     path,
				method:   method,
				pathItem: pathItem,
				op:       op,
			})
		}
	}

	slices.SortFunc(ops, func(a, b pathOperation) int {
		// Primary: method priority
		aPriority := methodPriority[a.method]
		bPriority := methodPriority[b.method]
		if aPriority != bPriority {
			return aPriority - bPriority
		}
		// Secondary: path alphabetically
		return strings.Compare(a.path, b.path)
	})

	return ops
}

// firstSpecServerPath returns the path prefix declared by the spec's first
// usable server, after substituting default server-variable values. Used when
// the caller pins the host via BaseURL but still wants the spec's basePath
// (e.g. "/api/v3"). A relative server URL ("/api/v3") has no scheme/host but
// url.Parse still fills Path; an absolute URL yields just its path component.
// Returns "" when no server declares a meaningful path.
func firstSpecServerPath(schema *openapi3.T) string {
	if schema == nil {
		return ""
	}
	for _, server := range schema.Servers {
		if server == nil || server.URL == "" {
			continue
		}
		raw := server.URL
		for name, v := range server.Variables {
			if v != nil {
				raw = strings.ReplaceAll(raw, "{"+name+"}", v.Default)
			}
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		p := strings.TrimSuffix(u.Path, "/")
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		return p
	}
	return ""
}

// unwrapSpec detects and extracts OpenAPI/Swagger spec from wrapper structures.
// Common wrapper: {"swaggerDoc": {...}, "customOptions": {...}}
// Supports both JSON and YAML formats.
func unwrapSpec(data []byte) []byte {
	// Try JSON first - preserves exact bytes
	var jsonWrapper struct {
		SwaggerDoc json.RawMessage `json:"swaggerDoc"`
	}
	if err := json.Unmarshal(data, &jsonWrapper); err == nil && len(jsonWrapper.SwaggerDoc) > 0 {
		zap.L().Debug("Unwrapped spec from JSON swaggerDoc wrapper")
		return jsonWrapper.SwaggerDoc
	}

	// Try YAML
	var yamlWrapper struct {
		SwaggerDoc any `yaml:"swaggerDoc"`
	}
	if err := yaml.Unmarshal(data, &yamlWrapper); err == nil && yamlWrapper.SwaggerDoc != nil {
		// Re-serialize the inner content to YAML
		if unwrapped, err := yaml.Marshal(yamlWrapper.SwaggerDoc); err == nil {
			zap.L().Debug("Unwrapped spec from YAML swaggerDoc wrapper")
			return unwrapped
		}
	}

	return data
}

// IsOpenAPISpec returns true if data looks like an OpenAPI 3.x or Swagger 2.x spec.
func IsOpenAPISpec(data []byte) bool {
	data = unwrapSpec(data)

	var spec struct {
		OpenAPI string `json:"openapi" yaml:"openapi"`
		Swagger string `json:"swagger" yaml:"swagger"`
	}

	// Try JSON
	if err := json.Unmarshal(data, &spec); err == nil {
		if strings.HasPrefix(spec.OpenAPI, "3.") || spec.Swagger != "" {
			return true
		}
	}

	// Try YAML
	if err := yaml.Unmarshal(data, &spec); err == nil {
		if strings.HasPrefix(spec.OpenAPI, "3.") || spec.Swagger != "" {
			return true
		}
	}

	return false
}

// detectSpecVersion detects whether the spec is OpenAPI 3.x or Swagger 2.x.
// Supports both JSON and YAML formats.
// Returns "openapi3" or "swagger2".
func detectSpecVersion(data []byte) string {
	var spec struct {
		OpenAPI string `json:"openapi" yaml:"openapi"`
		Swagger string `json:"swagger" yaml:"swagger"`
	}

	// Try JSON first
	if err := json.Unmarshal(data, &spec); err == nil {
		if strings.HasPrefix(spec.OpenAPI, "3.") {
			return "openapi3"
		}
		if spec.Swagger != "" {
			return "swagger2"
		}
	}

	// Try YAML
	if err := yaml.Unmarshal(data, &spec); err == nil {
		if strings.HasPrefix(spec.OpenAPI, "3.") {
			return "openapi3"
		}
	}

	return "swagger2"
}

// ParseOpenAPI parses an OpenAPI 3.0 spec and generates HttpRequestResponse.
func ParseOpenAPI(data []byte, opts Options, callback ResultCallback) error {
	loader := openapi3.NewLoader()
	schema, err := loader.LoadFromData(data)
	if err != nil {
		return fmt.Errorf("failed to parse OpenAPI spec: %w", err)
	}

	// Resolve $ref references (internal and external)
	if err := loader.ResolveRefsIn(schema, nil); err != nil {
		return fmt.Errorf("failed to resolve OpenAPI references: %w", err)
	}

	return generateRequestsFromSchema(schema, opts, callback)
}

// generateRequestsFromSchema generates HTTP requests from an OpenAPI 3.0 document.
func generateRequestsFromSchema(schema *openapi3.T, opts Options, callback ResultCallback) error {
	// Normalize BaseURL: remove trailing slash to avoid double //
	opts.BaseURL = strings.TrimSuffix(opts.BaseURL, "/")

	if opts.Stats == nil {
		opts.Stats = &ParseStats{}
	}
	defer reportParseStats(opts.Stats)

	// Get global security parameters
	globalParams := openapi3.NewParameters()
	if len(schema.Security) > 0 && schema.Components != nil {
		params, err := getGlobalParamsForSecurityRequirement(schema, &schema.Security, opts.Variables)
		if err != nil {
			zap.L().Debug("Failed to get global security params", zap.Error(err))
		} else {
			globalParams = append(globalParams, params...)
		}
	}

	// If BaseURL is provided, use it exclusively (ignore servers in spec)
	if opts.BaseURL != "" {
		baseU, err := url.Parse(opts.BaseURL)
		if err != nil {
			return fmt.Errorf("failed to parse base URL: %w", err)
		}
		baseURL := fmt.Sprintf("%s://%s", baseU.Scheme, baseU.Host)
		serverPath := baseU.Path

		// Pin the host via BaseURL but keep the spec's declared basePath/server
		// path prefix, so auto-ingested endpoints resolve correctly instead of
		// 404ing at the document root.
		if opts.PreserveSpecServerPath {
			if sp := firstSpecServerPath(schema); sp != "" {
				serverPath = sp
			}
		}

		if schema.Paths != nil {
			sortedOps := collectAndSortOperations(schema.Paths)
			for _, pop := range sortedOps {
				requestPath := pop.path
				if serverPath != "" {
					requestPath = serverPath + pop.path
				}

				if err := generateRequestsFromOp(&generateReqOptions{
					method:       pop.method,
					pathURL:      baseURL,
					requestPath:  requestPath,
					op:           pop.op,
					schema:       schema,
					globalParams: globalParams,
					reqParams:    pop.pathItem.Parameters,
					opts:         opts,
					callback:     callback,
				}); err != nil {
					opts.Stats.SkippedOperations++
					zap.L().Debug("Failed to generate request",
						zap.String("method", pop.method),
						zap.String("path", requestPath),
						zap.Error(err))
				}
			}
		}
		return nil
	}

	// BaseURL not provided - check if we should use spec servers
	if !opts.UseSpecServers {
		return fmt.Errorf("base URL required: pass -t/--target, or --spec-url to use the servers declared in the spec")
	}

	// Collect server URLs from spec
	var serverURLs []string
	for _, server := range schema.Servers {
		serverURLs = append(serverURLs, server.URL)
	}

	if len(serverURLs) == 0 {
		return fmt.Errorf("no servers found in spec and no base URL provided")
	}

	// Process each server URL from spec
	for _, serverURL := range serverURLs {
		u, err := url.Parse(serverURL)
		if err != nil {
			zap.L().Debug("Failed to parse server URL", zap.String("url", serverURL), zap.Error(err))
			continue
		}

		if u.Scheme == "" || u.Host == "" {
			zap.L().Warn("Server URL is relative but no base URL provided, skipping",
				zap.String("serverURL", serverURL))
			continue
		}

		baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		serverPath := u.Path

		if schema.Paths == nil {
			continue
		}

		sortedOps := collectAndSortOperations(schema.Paths)
		for _, pop := range sortedOps {
			requestPath := pop.path
			if serverPath != "" {
				requestPath = serverPath + pop.path
			}

			if err := generateRequestsFromOp(&generateReqOptions{
				method:       pop.method,
				pathURL:      baseURL,
				requestPath:  requestPath,
				op:           pop.op,
				schema:       schema,
				globalParams: globalParams,
				reqParams:    pop.pathItem.Parameters,
				opts:         opts,
				callback:     callback,
			}); err != nil {
				opts.Stats.SkippedOperations++
				zap.L().Debug("Failed to generate request",
					zap.String("method", pop.method),
					zap.String("path", requestPath),
					zap.Error(err))
			}
		}
	}

	return nil
}

type generateReqOptions struct {
	method       string
	pathURL      string
	requestPath  string
	schema       *openapi3.T
	op           *openapi3.Operation
	callback     ResultCallback
	globalParams openapi3.Parameters
	reqParams    openapi3.Parameters
	opts         Options
}

// getFirstExample extracts the first example value from an Examples map.
func getFirstExample(examples openapi3.Examples) any {
	for _, ex := range examples {
		if ex.Value != nil && ex.Value.Value != nil {
			return ex.Value.Value
		}
	}
	return nil
}

// getExtensionExample extracts example from x-example extension.
func getExtensionExample(extensions map[string]any) (any, bool) {
	if extensions == nil {
		return nil, false
	}
	if ex, ok := extensions["x-example"]; ok {
		return ex, true
	}
	return nil, false
}

// getParameterExample extracts example value from parameter with priority.
// Priority: Parameter.Example > Parameter.Examples > Parameter.Content > Schema.Example > Schema.Default > Enum > x-example
func getParameterExample(param *openapi3.Parameter) (any, bool) {
	// Parameter-level example (highest priority after Variables)
	if param.Example != nil {
		return param.Example, true
	}
	if len(param.Examples) > 0 {
		if ex := getFirstExample(param.Examples); ex != nil {
			return ex, true
		}
	}

	// Parameter.Content - when using content instead of schema
	if len(param.Content) > 0 {
		for _, mediaType := range param.Content {
			if mediaType.Example != nil {
				return mediaType.Example, true
			}
			if len(mediaType.Examples) > 0 {
				if ex := getFirstExample(mediaType.Examples); ex != nil {
					return ex, true
				}
			}
		}
	}

	// Schema-level example
	if param.Schema != nil && param.Schema.Value != nil {
		schema := param.Schema.Value
		if schema.Example != nil {
			return schema.Example, true
		}
		if schema.Default != nil {
			return schema.Default, true
		}
		if len(schema.Enum) > 0 {
			return schema.Enum[0], true
		}
	}

	// x-example extension
	if ex, ok := getExtensionExample(param.Extensions); ok {
		return ex, true
	}

	return nil, false
}

// getMediaTypeExample extracts example value from media type.
// Priority: MediaType.Example > MediaType.Examples > Schema
func getMediaTypeExample(mediaType *openapi3.MediaType, fieldTypeDefaults map[string][]string, requiredOnly bool) (any, error) {
	if mediaType.Example != nil {
		return mediaType.Example, nil
	}
	if len(mediaType.Examples) > 0 {
		if ex := getFirstExample(mediaType.Examples); ex != nil {
			return ex, nil
		}
	}
	if mediaType.Schema != nil && mediaType.Schema.Value != nil {
		return generateExampleFromSchemaOpts(mediaType.Schema.Value, fieldTypeDefaults, requiredOnly)
	}
	return map[string]any{}, nil
}

// generateRequestsFromOp generates requests from an operation.
func generateRequestsFromOp(opts *generateReqOptions) error {
	req, err := http.NewRequest(opts.method, opts.pathURL+opts.requestPath, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Collect all parameters
	reqParams := opts.reqParams
	if reqParams == nil {
		reqParams = openapi3.NewParameters()
	}
	reqParams = append(reqParams, opts.op.Parameters...)

	// Handle operation-specific security
	if opts.op.Security != nil && opts.schema.Components != nil {
		params, err := getGlobalParamsForSecurityRequirement(opts.schema, opts.op.Security, opts.opts.Variables)
		if err != nil {
			zap.L().Debug("Failed to get operation security params", zap.Error(err))
		} else {
			reqParams = append(reqParams, params...)
		}
	} else {
		reqParams = append(reqParams, opts.globalParams...)
	}

	query := url.Values{}
	for _, parameter := range reqParams {
		if parameter.Value == nil {
			continue
		}

		value := parameter.Value
		var paramValue any

		// Priority: Variables > Parameter.Example > DefaultFallbackValue (for required) > Schema generated.
		// A security-scheme parameter already carries its finished value (e.g.
		// "Bearer <token>"); the raw variable it came from must not replace it.
		if ex, ok := securityParamValue(value); ok {
			paramValue = ex
		} else if val, ok := opts.opts.Variables[value.Name]; ok {
			paramValue = val
		} else if ex, ok := getParameterExample(value); ok {
			paramValue = ex
		} else if value.Required && opts.opts.DefaultFallbackValue != "" {
			// Use fallback for required params without explicit example
			paramValue = opts.opts.DefaultFallbackValue
			zap.L().Debug("Using default fallback for required param",
				zap.String("param", value.Name),
				zap.String("value", opts.opts.DefaultFallbackValue))
		} else if !value.Required && opts.opts.RequiredOnly {
			// --required-only: an optional parameter with no explicit value
			// is left out rather than filled from its schema.
			opts.requestPath = strings.ReplaceAll(opts.requestPath, fmt.Sprintf("{%s}", value.Name), "")
			continue
		} else if idVal, ok := idLikeParamValue(value); ok {
			paramValue = idVal
		} else if exampleVal, ok := schemaParamExample(value, opts.opts.FieldTypeDefaults); ok {
			paramValue = exampleVal
		} else if value.Required {
			// A required parameter with nothing to go on used to drop the whole
			// operation. Synthesize a type-shaped placeholder instead: the
			// endpoint is still worth a request, and the active modules
			// replace the value anyway.
			paramValue = synthesizeParamValue(value)
			opts.opts.Stats.SynthesizedParams++
			zap.L().Debug("Synthesized value for required param without example",
				zap.String("method", opts.method),
				zap.String("path", opts.requestPath),
				zap.String("param", value.Name),
				zap.Any("value", paramValue))
		} else {
			opts.requestPath = strings.ReplaceAll(opts.requestPath, fmt.Sprintf("{%s}", value.Name), "")
			continue
		}

		switch value.In {
		case "query":
			query.Set(value.Name, toString(paramValue))
		case "header":
			req.Header.Set(value.Name, toString(paramValue))
		case "path":
			// Escape the value as one path segment: a "/" in it must not
			// become a path separator (a/b → a%2Fb).
			opts.requestPath = strings.ReplaceAll(opts.requestPath, "{"+value.Name+"}", url.PathEscape(toString(paramValue)))
		case "cookie":
			req.AddCookie(&http.Cookie{Name: value.Name, Value: toString(paramValue)})
		}
	}

	req.URL.RawQuery = query.Encode()
	// requestPath is in escaped form (path values were PathEscaped). RawPath
	// keeps an escaped "/" inside a segment through serialization; Path is
	// its decoded twin.
	if decoded, err := url.PathUnescape(opts.requestPath); err == nil {
		req.URL.Path = decoded
		req.URL.RawPath = opts.requestPath
	} else {
		req.URL.Path = opts.requestPath
	}

	// Add custom headers from options
	for k, v := range opts.opts.Headers {
		req.Header.Set(k, v)
	}

	// Handle request body
	if opts.op.RequestBody != nil && opts.op.RequestBody.Value != nil {
		for contentType, mediaType := range opts.op.RequestBody.Value.Content {
			cloned := req.Clone(req.Context())

			val, err := getMediaTypeExample(mediaType, opts.opts.FieldTypeDefaults, opts.opts.RequiredOnly)
			if err != nil {
				opts.opts.Stats.SkippedOperations++
				zap.L().Debug("Failed to build request body example",
					zap.String("method", opts.method), zap.String("path", opts.requestPath),
					zap.String("contentType", contentType), zap.Error(err))
				continue
			}

			if err := setRequestBody(cloned, contentType, val, mediaType.Schema); err != nil {
				opts.opts.Stats.SkippedOperations++
				zap.L().Debug("Failed to set request body", zap.String("contentType", contentType), zap.Error(err))
				continue
			}

			callbackWithRequest(cloned, opts)
		}
		return nil
	}

	// No body - just callback
	callbackWithRequest(req, opts)
	return nil
}

// setRequestBody sets the request body based on content type.
func setRequestBody(req *http.Request, contentType string, val any, schemaRef *openapi3.SchemaRef) error {
	switch canonicalMediaType(contentType) {
	case "application/json":
		marshalled, err := marshalJSON(val)
		if err != nil {
			return err
		}
		req.Body = io.NopCloser(bytes.NewReader(marshalled))
		req.ContentLength = int64(len(marshalled))
		req.Header.Set("Content-Type", declaredOr(contentType, "application/json"))

	case "application/xml":
		xmlData, err := marshalXML(val)
		if err != nil {
			return err
		}
		req.Body = io.NopCloser(bytes.NewReader(xmlData))
		req.ContentLength = int64(len(xmlData))
		req.Header.Set("Content-Type", declaredOr(contentType, "application/xml"))

	case "application/x-www-form-urlencoded":
		if values, ok := val.(map[string]any); ok {
			form := url.Values{}
			for k, v := range values {
				form.Set(k, toString(v))
			}
			encoded := form.Encode()
			req.Body = io.NopCloser(strings.NewReader(encoded))
			req.ContentLength = int64(len(encoded))
			req.Header.Set("Content-Type", declaredOr(contentType, "application/x-www-form-urlencoded"))
		}

	case "multipart/form-data":
		if values, ok := val.(map[string]any); ok {
			buffer := &bytes.Buffer{}
			writer := multipart.NewWriter(buffer)
			for k, v := range values {
				// Check if this is a file field
				if schemaRef != nil && schemaRef.Value != nil {
					if prop, ok := schemaRef.Value.Properties[k]; ok && prop.Value.Format == "binary" {
						if w, err := writer.CreateFormFile(k, k); err == nil {
							_, _ = w.Write([]byte(toString(v)))
						}
						continue
					}
				}
				_ = writer.WriteField(k, toString(v))
			}
			_ = writer.Close()
			req.Body = io.NopCloser(buffer)
			req.ContentLength = int64(buffer.Len())
			req.Header.Set("Content-Type", writer.FormDataContentType())
		}

	case "text/plain":
		str := toString(val)
		req.Body = io.NopCloser(strings.NewReader(str))
		req.ContentLength = int64(len(str))
		req.Header.Set("Content-Type", declaredOr(contentType, "text/plain"))

	case "application/octet-stream":
		str := toString(val)
		if str == "" {
			str = "binary-data"
		}
		req.Body = io.NopCloser(strings.NewReader(str))
		req.ContentLength = int64(len(str))
		req.Header.Set("Content-Type", "application/octet-stream")

	default:
		// Try as plain text
		str := toString(val)
		req.Body = io.NopCloser(strings.NewReader(str))
		req.ContentLength = int64(len(str))
		req.Header.Set("Content-Type", contentType)
	}

	return nil
}

// callbackWithRequest converts http.Request to HttpRequestResponse and calls callback.
func callbackWithRequest(req *http.Request, opts *generateReqOptions) {
	rr, err := httpmsg.FromStdRequest(req)
	if err != nil {
		opts.opts.Stats.SkippedOperations++
		zap.L().Debug("Failed to convert request", zap.Error(err))
		return
	}

	opts.opts.Stats.Emitted++
	opts.callback(rr)
}

// reportParseStats logs, once per parse, what the spec could not produce as
// written. Skipped operations are a warning (the scan covers less of the API
// than the spec declares); synthesized values are informational.
func reportParseStats(st *ParseStats) {
	if st.SkippedOperations > 0 {
		zap.L().Warn("openapi: some operations produced no request",
			zap.Int("skipped_operations", st.SkippedOperations),
			zap.Int("emitted", st.Emitted))
	}
	if st.SynthesizedParams > 0 {
		zap.L().Info("openapi: filled required parameters that had no example with placeholders",
			zap.Int("synthesized_params", st.SynthesizedParams))
	}
}

// schemaParamExample generates a value for a parameter from its schema, or from
// the schema of its content media type when it uses `content` instead.
func schemaParamExample(param *openapi3.Parameter, fieldTypeDefaults map[string][]string) (any, bool) {
	if param.Schema != nil && param.Schema.Value != nil {
		if ex, err := generateExampleFromSchema(param.Schema.Value, fieldTypeDefaults); err == nil {
			return ex, true
		}
	}
	for _, mt := range param.Content {
		if mt != nil && mt.Schema != nil && mt.Schema.Value != nil {
			if ex, err := generateExampleFromSchema(mt.Schema.Value, fieldTypeDefaults); err == nil {
				return ex, true
			}
		}
	}
	return nil, false
}

// zeroUUID is the placeholder for a uuid-formatted parameter.
const zeroUUID = "00000000-0000-0000-0000-000000000000"

// synthesizeParamValue returns a placeholder shaped by the parameter's declared
// type when nothing better exists: 1 for numbers, true for booleans, the zero
// UUID for uuid strings, "1" otherwise (a value most ID-like slots accept).
func synthesizeParamValue(param *openapi3.Parameter) any {
	if param.Schema == nil || param.Schema.Value == nil {
		return "1"
	}
	sc := param.Schema.Value
	switch {
	case sc.Type.Is("integer"), sc.Type.Is("number"):
		return 1
	case sc.Type.Is("boolean"):
		return true
	case strings.EqualFold(sc.Format, "uuid"):
		return zeroUUID
	}
	return "1"
}

// getGlobalParamsForSecurityRequirement extracts parameters from security requirements.
func getGlobalParamsForSecurityRequirement(schema *openapi3.T, requirement *openapi3.SecurityRequirements, variables map[string]string) ([]*openapi3.ParameterRef, error) {
	if schema.Components == nil || len(schema.Components.SecuritySchemes) == 0 {
		return nil, nil
	}

	var globalParams []*openapi3.ParameterRef

	for _, security := range *requirement {
		for name := range security {
			scheme, ok := schema.Components.SecuritySchemes[name]
			if !ok {
				continue
			}

			param, err := generateParameterFromSecurityScheme(name, scheme, variables)
			if err != nil {
				zap.L().Debug("Failed to generate security param", zap.String("scheme", name), zap.Error(err))
				continue
			}
			if param != nil {
				globalParams = append(globalParams, &openapi3.ParameterRef{Value: param})
			}
		}
	}

	return globalParams, nil
}

// securityParamExt marks a parameter built from a security scheme. Its example
// is the finished credential ("Bearer <token>"), so the variable lookup in
// generateRequestsFromOp must not swap the raw --spec-var value back in.
const securityParamExt = "x-vigolium-security-param"

// securityParamValue returns the finished value of a security-scheme parameter.
func securityParamValue(p *openapi3.Parameter) (any, bool) {
	if p.Extensions[securityParamExt] != true || p.Schema == nil || p.Schema.Value == nil {
		return nil, false
	}
	return p.Schema.Value.Example, true
}

// lookupVar returns the first non-empty variable among keys.
func lookupVar(variables map[string]string, keys ...string) string {
	for _, k := range keys {
		if k == "" {
			continue
		}
		if v := variables[k]; v != "" {
			return v
		}
	}
	return ""
}

// withAuthScheme prefixes value with "<scheme> " unless it already carries it,
// so both --spec-var bearer=<token> and --spec-var Authorization="Bearer
// <token>" produce one prefix.
func withAuthScheme(scheme, value string) string {
	if len(value) > len(scheme) && strings.EqualFold(value[:len(scheme)+1], scheme+" ") {
		return value
	}
	return scheme + " " + value
}

// basicAuthValue builds a Basic credential: "user:pass" is base64-encoded, an
// already-encoded token or a full "Basic …" value is kept.
func basicAuthValue(value string) string {
	if len(value) > 6 && strings.EqualFold(value[:6], "basic ") {
		return value
	}
	if strings.Contains(value, ":") {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(value))
	}
	return "Basic " + value
}

// generateParameterFromSecurityScheme creates a parameter from a security
// scheme. name is the scheme's key under components.securitySchemes, which a
// --spec-var may use as well as the generic keys:
//
//	http bearer, oauth2, openIdConnect: bearer=<token> | <name>=<token> | Authorization=<token>
//	http basic:                         basic=user:pass | <name>=user:pass | Authorization=…
//	apiKey:                             <param name>=<key> | <name>=<key>
//
// A value that already starts with its scheme ("Bearer …", "Basic …") is used
// as-is, so nothing is double-prefixed. A scheme with no value adds nothing.
func generateParameterFromSecurityScheme(name string, scheme *openapi3.SecuritySchemeRef, variables map[string]string) (*openapi3.Parameter, error) {
	if scheme == nil || scheme.Value == nil {
		return nil, nil
	}

	authHeader := func(value string) *openapi3.Parameter {
		headerName := scheme.Value.Name
		if headerName == "" || scheme.Value.Type != "http" {
			headerName = "Authorization"
		}
		param := openapi3.NewHeaderParameter(headerName)
		param.Required = true
		param.Schema = openapi3.NewStringSchema().NewRef()
		param.Schema.Value.Example = value
		param.Extensions = map[string]any{securityParamExt: true}
		return param
	}

	switch scheme.Value.Type {
	case "http":
		switch strings.ToLower(scheme.Value.Scheme) {
		case "bearer":
			if v := lookupVar(variables, "bearer", name, "Authorization"); v != "" {
				return authHeader(withAuthScheme("Bearer", v)), nil
			}
		case "basic":
			if v := lookupVar(variables, "basic", name, "Authorization"); v != "" {
				return authHeader(basicAuthValue(v)), nil
			}
		default:
			// digest and other schemes: the value is the full credential.
			if v := lookupVar(variables, scheme.Value.Name, name, "Authorization"); v != "" {
				return authHeader(v), nil
			}
		}
		zap.L().Debug("Missing auth value for HTTP security scheme",
			zap.String("name", name), zap.String("scheme", scheme.Value.Scheme))
		return nil, nil

	case "oauth2", "openIdConnect":
		// Both end in a bearer access token on the wire.
		if v := lookupVar(variables, "bearer", name, "Authorization"); v != "" {
			return authHeader(withAuthScheme("Bearer", v)), nil
		}
		zap.L().Debug("Missing token for security scheme", zap.String("name", name), zap.String("type", scheme.Value.Type))
		return nil, nil

	case "apiKey":
		if scheme.Value.Name == "" {
			return nil, nil
		}

		authValue := lookupVar(variables, scheme.Value.Name, name)
		if authValue == "" {
			zap.L().Debug("Missing value for apiKey", zap.String("name", scheme.Value.Name))
			return nil, nil
		}

		var param *openapi3.Parameter
		switch scheme.Value.In {
		case "query":
			param = openapi3.NewQueryParameter(scheme.Value.Name)
		case "header":
			param = openapi3.NewHeaderParameter(scheme.Value.Name)
		case "cookie":
			param = openapi3.NewCookieParameter(scheme.Value.Name)
		default:
			return nil, nil
		}

		param.Required = true
		param.Schema = openapi3.NewStringSchema().NewRef()
		param.Schema.Value.Example = authValue
		param.Extensions = map[string]any{securityParamExt: true}
		return param, nil
	}

	return nil, nil
}

// Example generation

var (
	errRecursive = fmt.Errorf("recursive schema")
	errNoExample = fmt.Errorf("no example found")
)

type cachedSchema struct {
	pending bool
	out     any
}

// generateExampleFromSchema creates an example value from an OpenAPI schema.
// fieldTypeDefaults provides configurable default values per field type (may be nil).
func generateExampleFromSchema(schema *openapi3.Schema, fieldTypeDefaults map[string][]string) (any, error) {
	return generateExampleFromSchemaOpts(schema, fieldTypeDefaults, false)
}

// generateExampleFromSchemaOpts is generateExampleFromSchema honouring
// Options.RequiredOnly: when set, optional object properties are omitted.
func generateExampleFromSchemaOpts(schema *openapi3.Schema, fieldTypeDefaults map[string][]string, requiredOnly bool) (any, error) {
	return openAPIExample(schema, make(map[*openapi3.Schema]*cachedSchema), fieldTypeDefaults, requiredOnly)
}

// effectiveType returns the schema's first non-null declared type (OpenAPI
// 3.1 allows `type: [string, "null"]`, and Types.Is is false for any
// multi-type list, so such a property used to drop its whole operation), or
// "" when untyped.
func effectiveType(schema *openapi3.Schema) string {
	for _, t := range schema.Type.Slice() {
		if t != openapi3.TypeNull {
			return t
		}
	}
	return ""
}

func openAPIExample(schema *openapi3.Schema, cache map[*openapi3.Schema]*cachedSchema, fieldTypeDefaults map[string][]string, requiredOnly bool) (out any, err error) {
	if ex, ok := getSchemaExample(schema); ok {
		return ex, nil
	}

	cached, ok := cache[schema]
	if !ok {
		cached = &cachedSchema{pending: true}
		cache[schema] = cached
	} else if cached.pending {
		return nil, errRecursive
	} else {
		return cached.out, nil
	}

	defer func() {
		cached.pending = false
		cached.out = out
	}()

	// Handle combining keywords
	if len(schema.OneOf) > 0 {
		for _, candidate := range schema.OneOf {
			if candidate.Value != nil {
				ex, err := openAPIExample(candidate.Value, cache, fieldTypeDefaults, requiredOnly)
				if err == nil {
					return ex, nil
				}
			}
		}
		return nil, errNoExample
	}

	if len(schema.AnyOf) > 0 {
		for _, candidate := range schema.AnyOf {
			if candidate.Value != nil {
				ex, err := openAPIExample(candidate.Value, cache, fieldTypeDefaults, requiredOnly)
				if err == nil {
					return ex, nil
				}
			}
		}
		return nil, errNoExample
	}

	if len(schema.AllOf) > 0 {
		example := map[string]any{}
		for _, allOf := range schema.AllOf {
			if allOf.Value == nil {
				continue
			}
			candidate, err := openAPIExample(allOf.Value, cache, fieldTypeDefaults, requiredOnly)
			if err != nil {
				return nil, err
			}
			if value, ok := candidate.(map[string]any); ok {
				maps.Copy(example, value)
			}
		}
		return example, nil
	}

	typ := effectiveType(schema)
	switch {
	case typ == "boolean":
		return true, nil

	case typ == "number", typ == "integer":
		value := 0.0
		if schema.Min != nil && *schema.Min > value {
			value = *schema.Min
			if schema.ExclusiveMin.IsTrue() {
				value++
			}
		}
		// OpenAPI 3.1 spells the exclusive bound as the number itself rather than
		// as a boolean modifier on "minimum", so it raises the floor on its own -
		// without this an example for `exclusiveMinimum: 5` would generate 0 and
		// the target would reject the body we built to probe it.
		if eb := schema.ExclusiveMin; eb.Value != nil && *eb.Value >= value {
			value = *eb.Value + 1
		}
		if schema.Max != nil && *schema.Max < value {
			value = *schema.Max
		}
		if typ == "integer" {
			return int(value), nil
		}
		return value, nil

	case typ == "string":
		if ex := stringFormatExample(schema.Format, fieldTypeDefaults); ex != "" {
			return ex, nil
		}
		example := "string"
		for schema.MinLength > uint64(len(example)) {
			example += example
		}
		if schema.MaxLength != nil && *schema.MaxLength < uint64(len(example)) {
			example = example[:*schema.MaxLength]
		}
		return example, nil

	case typ == "array", typ == "" && schema.Items != nil:
		example := []any{}
		if schema.Items != nil && schema.Items.Value != nil {
			ex, err := openAPIExample(schema.Items.Value, cache, fieldTypeDefaults, requiredOnly)
			if err != nil {
				return nil, fmt.Errorf("can't get example for array item: %w", err)
			}
			example = append(example, ex)
			for uint64(len(example)) < schema.MinItems {
				example = append(example, ex)
			}
		}
		return example, nil

	case typ == "object", typ == "" && len(schema.Properties) > 0:
		example := map[string]any{}
		for k, v := range schema.Properties {
			if v.Value == nil || v.Value.ReadOnly {
				continue
			}
			if requiredOnly && !slices.Contains(schema.Required, k) {
				continue
			}
			ex, err := openAPIExample(v.Value, cache, fieldTypeDefaults, requiredOnly)
			if errors.Is(err, errRecursive) {
				if slices.Contains(schema.Required, k) {
					return nil, fmt.Errorf("can't get example for '%s': %w", k, err)
				}
			} else if err != nil {
				return nil, fmt.Errorf("can't get example for '%s': %w", k, err)
			} else {
				example[k] = ex
			}
		}

		if schema.AdditionalProperties.Has != nil && schema.AdditionalProperties.Schema != nil {
			addl := schema.AdditionalProperties.Schema.Value
			if addl != nil && !addl.ReadOnly {
				ex, err := openAPIExample(addl, cache, fieldTypeDefaults, requiredOnly)
				if err == nil {
					example["additionalPropertyName"] = ex
				}
			}
		}
		return example, nil

	case typ == "":
		// Untyped with nothing to infer from: any JSON value is allowed, and a
		// short scalar is what most handlers accept. Dropping the operation
		// (the old errNoExample) lost the endpoint entirely. A declared
		// format still shapes it (format: uuid → a UUID).
		if ex := stringFormatExample(schema.Format, fieldTypeDefaults); ex != "" {
			return ex, nil
		}
		return "1", nil
	}

	return nil, errNoExample
}

func getSchemaExample(schema *openapi3.Schema) (any, bool) {
	if schema.Example != nil {
		return schema.Example, true
	}
	if schema.Default != nil {
		return schema.Default, true
	}
	if len(schema.Enum) > 0 {
		return schema.Enum[0], true
	}
	return nil, false
}

// CountOperations counts the number of operations in an OpenAPI spec.
// If UseSpecServers is true, multiplies by the number of servers.
func CountOperations(data []byte, opts Options) (int64, error) {
	data = unwrapSpec(data)

	loader := openapi3.NewLoader()
	schema, err := loader.LoadFromData(data)
	if err != nil {
		return 0, fmt.Errorf("failed to parse OpenAPI spec: %w", err)
	}

	if schema.Paths == nil {
		return 0, nil
	}

	var count int64
	for _, pathItem := range schema.Paths.Map() {
		count += int64(len(pathItem.Operations()))
	}

	// If using spec servers and no BaseURL, multiply by server count
	if opts.UseSpecServers && opts.BaseURL == "" && len(schema.Servers) > 0 {
		count *= int64(len(schema.Servers))
	}

	return count, nil
}

// canonicalMediaType maps a declared request media type onto the body
// encoding it implies: parameters are stripped and case folded
// (mime.ParseMediaType), and structured-syntax suffixes resolve to their base
// (application/vnd.api+json -> application/json, application/soap+xml ->
// application/xml). Before this, anything but an exact "application/json"
// fell through to Go's %v rendering of a map.
func canonicalMediaType(declared string) string {
	mt, _, err := mime.ParseMediaType(declared)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(declared))
		if i := strings.IndexByte(mt, ';'); i >= 0 {
			mt = strings.TrimSpace(mt[:i])
		}
	}
	switch {
	case mt == "application/json", mt == "text/json", strings.HasSuffix(mt, "+json"),
		strings.HasSuffix(mt, "/x-json"):
		return "application/json"
	case mt == "application/xml", mt == "text/xml", strings.HasSuffix(mt, "+xml"):
		return "application/xml"
	}
	return mt
}

// declaredOr keeps the spec's declared media type on the wire (a server that
// routes on application/vnd.api+json must receive exactly that) unless it is
// a wildcard or empty.
func declaredOr(declared, fallback string) string {
	d := strings.TrimSpace(declared)
	if d == "" || strings.Contains(d, "*") {
		return fallback
	}
	return d
}

// idLikeParamValue returns a usable identifier for a path or query parameter
// with no explicit example: integer path parameters (and integer query
// parameters named like IDs) become max(1, minimum) because 0 is almost never
// a valid row, and string parameters named "*id" with no format or pattern
// become "1" rather than the literal "string". Values shaped like this let
// by-ID operations reach the handler instead of a 404.
func idLikeParamValue(param *openapi3.Parameter) (any, bool) {
	if param.In != "path" && param.In != "query" {
		return nil, false
	}
	if param.Schema == nil || param.Schema.Value == nil {
		return nil, false
	}
	sc := param.Schema.Value
	switch effectiveType(sc) {
	case "integer", "number":
		if param.In != "path" && !isIDName(param.Name) {
			return nil, false
		}
		v := 1.0
		if sc.Min != nil && *sc.Min > v {
			v = *sc.Min
			if sc.ExclusiveMin.IsTrue() {
				v++
			}
		}
		if eb := sc.ExclusiveMin; eb.Value != nil && *eb.Value >= v {
			v = *eb.Value + 1
		}
		if sc.Max != nil && *sc.Max < v {
			v = *sc.Max
		}
		return int(v), true
	case "string":
		if sc.Format != "" || sc.Pattern != "" || !isIDName(param.Name) {
			return nil, false
		}
		return "1", true
	}
	return nil, false
}

// isIDName reports whether a parameter name names an identifier: "id", or a
// name ending in "id" (userId, user_id, orderid).
func isIDName(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), "id")
}
