package openapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/invopop/yaml"
)

// SpecServerURLs returns the absolute server URLs a spec declares, in spec
// order, with server variables replaced by their defaults. Relative
// server URLs are skipped: they name no host. Swagger 2.0 host/basePath/schemes
// are converted the way ParseSwagger converts them.
func SpecServerURLs(input string) ([]string, error) {
	data, _, err := LoadSpec(input)
	if err != nil {
		return nil, err
	}
	data = unwrapSpec(data)
	var doc *openapi3.T
	if detectSpecVersion(data) == "openapi3" {
		doc, err = openapi3.NewLoader().LoadFromData(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse OpenAPI spec: %w", err)
		}
	} else {
		var doc2 openapi2.T
		if err := json.Unmarshal(data, &doc2); err != nil {
			if err := yaml.Unmarshal(data, &doc2); err != nil {
				return nil, fmt.Errorf("failed to parse Swagger 2.0 spec: %w", err)
			}
		}
		doc, err = openapi2conv.ToV3(&doc2)
		if err != nil {
			return nil, fmt.Errorf("failed to convert Swagger 2.0 spec: %w", err)
		}
	}
	var out []string
	for _, server := range doc.Servers {
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
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		out = append(out, raw)
	}
	return out, nil
}
