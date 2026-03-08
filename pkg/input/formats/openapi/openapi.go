package openapi

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
)

// Format implements formats.Format interface for OpenAPI/Swagger specs.
type Format struct {
	formatOpts  formats.InputFormatOptions
	openapiOpts Options
}

// New creates a new OpenAPI Format.
func New() *Format {
	return &Format{}
}

// Name returns the name of the format.
func (f *Format) Name() string {
	return "openapi"
}

// SetOptions sets the generic format options.
func (f *Format) SetOptions(options formats.InputFormatOptions) {
	f.formatOpts = options
}

// SetOpenAPIOptions sets OpenAPI-specific options.
func (f *Format) SetOpenAPIOptions(opts Options) {
	f.openapiOpts = opts
}

// Parse parses an OpenAPI/Swagger spec file and calls callback for each request.
func (f *Format) Parse(input string, callback formats.ParseReqRespCallback) error {
	// Load spec from file or URL
	data, ext, err := LoadSpec(input)
	if err != nil {
		return fmt.Errorf("failed to load spec: %w", err)
	}

	// Merge format options into OpenAPI options
	opts := f.openapiOpts
	opts.RequiredOnly = f.formatOpts.RequiredOnly
	opts.SkipFormatValidation = f.formatOpts.SkipFormatValidation

	// Wrap callback to match ResultCallback signature
	wrappedCallback := func(rr *httpmsg.HttpRequestResponse) bool {
		return callback(rr)
	}

	// Parse based on detected version - ParseSwagger auto-detects
	return ParseSwagger(data, ext, opts, wrappedCallback)
}

// Count returns the number of operations in the OpenAPI spec.
// If UseSpecServers is true, multiplies by number of servers.
func (f *Format) Count(input string) (int64, error) {
	data, _, err := LoadSpec(input)
	if err != nil {
		return 0, err
	}

	return CountOperations(data, f.openapiOpts)
}
