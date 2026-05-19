package openapi

import (
	"encoding/json"
	"fmt"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/invopop/yaml"
	"go.uber.org/zap"
)

// ParseSwagger parses a Swagger 2.0 spec, converts it to OpenAPI 3.0, and generates HttpRequestResponse.
// It auto-detects wrapper structures (swaggerDoc) and spec version (OpenAPI 3.x vs Swagger 2.x).
func ParseSwagger(data []byte, ext string, opts Options, callback ResultCallback) error {
	// Unwrap spec from wrapper structures (e.g., {"swaggerDoc": {...}})
	data = unwrapSpec(data)

	// Auto-detect spec version
	specVersion := detectSpecVersion(data)
	zap.L().Debug("Detected spec version", zap.String("version", specVersion))

	// If it's OpenAPI 3.x, use OpenAPI parser directly
	if specVersion == "openapi3" {
		return ParseOpenAPI(data, opts, callback)
	}

	// Parse Swagger 2.0 spec
	var doc2 openapi2.T

	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &doc2); err != nil {
			return fmt.Errorf("failed to parse Swagger 2.0 JSON: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &doc2); err != nil {
			return fmt.Errorf("failed to parse Swagger 2.0 YAML: %w", err)
		}
	default:
		// Try JSON first, then YAML (invopop/yaml handles YAML→JSON internally)
		if err := json.Unmarshal(data, &doc2); err != nil {
			if err := yaml.Unmarshal(data, &doc2); err != nil {
				return fmt.Errorf("failed to parse Swagger 2.0 spec: %w", err)
			}
		}
	}

	// Convert Swagger 2.0 to OpenAPI 3.0
	doc3, err := openapi2conv.ToV3(&doc2)
	if err != nil {
		return fmt.Errorf("failed to convert Swagger 2.0 to OpenAPI 3.0: %w", err)
	}

	// Resolve references (like nuclei does)
	loader := openapi3.NewLoader()
	if err := loader.ResolveRefsIn(doc3, nil); err != nil {
		return fmt.Errorf("failed to resolve OpenAPI references: %w", err)
	}

	return generateRequestsFromSchema(doc3, opts, callback)
}
