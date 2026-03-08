package openapi

// Options contains options for parsing OpenAPI specs.
type Options struct {
	// BaseURL overrides servers in spec (e.g., https://api.example.com)
	BaseURL string

	// UseSpecServers allows using servers defined in spec when BaseURL is not provided
	UseSpecServers bool

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
}

// ServerOptions extends Options with server-mode specific fields.
type ServerOptions struct {
	Options

	// EnableModules is the list of modules to enable for scan requests
	EnableModules []string

	// WebhookURL is the webhook URL for results
	WebhookURL string
}
