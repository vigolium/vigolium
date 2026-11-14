package source

import (
	"net/http"

	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/postman"
	"github.com/vigolium/vigolium/pkg/input/formats/wsdl"
)

// SpecOptions carries the options a spec-shaped input format (OpenAPI, WSDL,
// Postman) takes from the command line: the -t target and the shared
// --spec-header / --spec-var / --spec-default flags. ApplySpecOptions maps
// them onto whichever parser the file resolved to, so `scan -i`, the runner
// and `ingest` configure every spec format the same way instead of each
// keeping its own switch (which is how the Postman case went missing from
// all three).
type SpecOptions struct {
	// BaseURL is the -t target: the OpenAPI base URL, the WSDL endpoint host
	// override and the Postman {{baseUrl}} / {{url}} value.
	BaseURL string
	// UseSpecServers makes OpenAPI use the spec's own servers (--spec-url).
	UseSpecServers bool
	// Headers are added to every generated OpenAPI / WSDL request.
	Headers map[string]string
	// Variables fill OpenAPI parameters, WSDL element values and Postman
	// {{name}} variables (--spec-var name=value).
	Variables map[string]string
	// DefaultFallbackValue fills an OpenAPI parameter nothing else does.
	DefaultFallbackValue string
	// FieldTypeDefaults are OpenAPI per-type defaults from the config.
	FieldTypeDefaults map[string][]string
	// HTTPClient fetches an OpenAPI spec given as a URL; build it from the
	// scan's --proxy (SAFE-11). nil = proxy-environment client.
	HTTPClient *http.Client
}

// ApplySpecOptions configures the spec parser behind src, if any. It unwraps a
// MultiSource (FirstFileSource), so the options land when targets are
// combined with a file, and keys on the resolved parser, so a content-sniffed
// spec is configured too. Any other format is left untouched.
func ApplySpecOptions(src InputSource, o SpecOptions) {
	fs := FirstFileSource(src)
	if fs == nil {
		return
	}
	switch parser := fs.Format().(type) {
	case *openapi.Format:
		parser.SetOpenAPIOptions(openapi.Options{
			BaseURL:              o.BaseURL,
			UseSpecServers:       o.UseSpecServers,
			Headers:              o.Headers,
			Variables:            o.Variables,
			DefaultFallbackValue: o.DefaultFallbackValue,
			FieldTypeDefaults:    o.FieldTypeDefaults,
			HTTPClient:           o.HTTPClient,
		})
	case *wsdl.Format:
		parser.SetWSDLOptions(wsdl.Options{
			EndpointURL: o.BaseURL,
			Headers:     o.Headers,
			Variables:   o.Variables,
		})
	case *postman.Format:
		parser.SetPostmanOptions(postman.Options{
			BaseURL:   o.BaseURL,
			Variables: o.Variables,
		})
	}
}
