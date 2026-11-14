package openapi

import "net/http"

// Options contains options for parsing OpenAPI specs.
type Options struct {
	// BaseURL overrides servers in spec (e.g., https://api.example.com)
	BaseURL string

	// UseSpecServers allows using servers defined in spec when BaseURL is not provided
	UseSpecServers bool
	// HTTPClient fetches a spec given as a URL (nil = proxy-environment
	// client). Callers pass one built from the scan's --proxy (SAFE-11).
	HTTPClient *http.Client

	// PreserveSpecServerPath, when BaseURL is set, keeps the scheme/host from BaseURL
	// (so the in-scope target host is enforced) but uses the path prefix declared by
	// the spec's own servers / Swagger basePath instead of discarding it. Without this,
	// a spec served at host/openapi.json that declares servers:[{url:"https://x/api/v3"}]
	// would generate requests to host/<op> (404 noise) instead of host/api/v3/<op>.
	// Used by spec auto-ingestion (discovery + api-spec-ingest); the explicit
	// `import`/`scan -i` paths keep the full-override behaviour.
	PreserveSpecServerPath bool

	// Headers are custom headers to add to all requests
	Headers map[string]string

	// Variables are parameter values (e.g., api_key=abc123)
	Variables map[string]string

	// DefaultFallbackValue is used for required params without examples
	DefaultFallbackValue string

	// RequiredOnly only uses required fields when generating requests
	RequiredOnly bool

	// SkipFormatValidation is used to skip format validation
	SkipFormatValidation bool

	// FieldTypeDefaults provides configurable default values per field type.
	// Used when OpenAPI specs lack examples. Keys are type names (e.g. "email", "uuid").
	FieldTypeDefaults map[string][]string

	// Stats, when set, receives what the parse produced and what it could not
	// (never-silent: operations dropped are counted, not just debug-logged).
	Stats *ParseStats
}

// ParseStats counts the outcome of one spec parse.
type ParseStats struct {
	// Emitted is the number of requests handed to the callback.
	Emitted int
	// SynthesizedParams counts required parameters with no example, default or
	// usable schema that were filled with a type-based placeholder instead of
	// dropping their operation.
	SynthesizedParams int
	// SkippedOperations counts operations (or body variants) that produced no
	// request at all.
	SkippedOperations int
}

// ServerOptions extends Options with server-mode specific fields.
type ServerOptions struct {
	Options

	// EnableModules is the list of modules to enable for scan requests
	EnableModules []string

	// WebhookURL is the webhook URL for results
	WebhookURL string
}
