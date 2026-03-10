package specutil

import (
	"bytes"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/postman"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

const (
	// MinSpecBodySize is the minimum body size to consider for spec detection.
	MinSpecBodySize = 50
	// MaxSpecBodySize is the maximum body size to consider for spec detection (10 MB).
	MaxSpecBodySize = 10 * 1024 * 1024
)

// SpecType represents the type of API specification.
type SpecType int

const (
	Unknown SpecType = iota
	OpenAPI
	Postman
)

// DetectSpecType determines whether data is an OpenAPI/Swagger or Postman spec.
func DetectSpecType(data []byte) SpecType {
	if openapi.IsOpenAPISpec(data) {
		return OpenAPI
	}
	// Postman markers: "_postman_id" or schema.getpostman.com
	if bytes.Contains(data, []byte(`"_postman_id"`)) ||
		bytes.Contains(data, []byte(`schema.getpostman.com`)) {
		return Postman
	}
	return Unknown
}

// ParseSpec parses a spec of the given type and returns all extracted endpoints.
// If specType is Unknown, it auto-detects. Each endpoint is optionally stamped with the given service.
func ParseSpec(data []byte, baseURL string, service *httpmsg.Service) ([]*httpmsg.HttpRequestResponse, error) {
	return ParseSpecTyped(DetectSpecType(data), data, baseURL, service)
}

// ParseSpecTyped parses a spec of a known type, skipping detection.
func ParseSpecTyped(specType SpecType, data []byte, baseURL string, service *httpmsg.Service) ([]*httpmsg.HttpRequestResponse, error) {
	if specType == Unknown {
		return nil, nil
	}

	var results []*httpmsg.HttpRequestResponse

	collect := func(rr *httpmsg.HttpRequestResponse) bool {
		if service != nil {
			rr = rr.WithService(service)
		}
		results = append(results, rr)
		return true
	}

	switch specType {
	case OpenAPI:
		opts := openapi.Options{BaseURL: baseURL}
		ext := openapi.DetectFormatFromContent(data)
		if err := openapi.ParseSwagger(data, ext, opts, collect); err != nil {
			return results, err
		}

	case Postman:
		f := &postman.Format{}
		if baseURL != "" {
			f.SetPostmanOptions(postman.Options{BaseURL: baseURL})
		}
		if err := f.ParseFromData(data, collect); err != nil {
			return results, err
		}
	}

	return results, nil
}

// ParseAndFeed detects spec type, parses endpoints, and feeds them via the feeder.
// Returns the count of endpoints fed and any error.
func ParseAndFeed(data []byte, baseURL string, service *httpmsg.Service, feeder modkit.RequestFeeder) (int, error) {
	if feeder == nil {
		return 0, nil
	}

	specType := DetectSpecType(data)
	if specType == Unknown {
		return 0, nil
	}

	var count int
	collect := func(rr *httpmsg.HttpRequestResponse) bool {
		if service != nil {
			rr = rr.WithService(service)
		}
		if feeder.Feed(rr) {
			count++
		}
		return true
	}

	switch specType {
	case OpenAPI:
		opts := openapi.Options{BaseURL: baseURL}
		ext := openapi.DetectFormatFromContent(data)
		if err := openapi.ParseSwagger(data, ext, opts, collect); err != nil {
			return count, err
		}
	case Postman:
		f := &postman.Format{}
		if baseURL != "" {
			f.SetPostmanOptions(postman.Options{BaseURL: baseURL})
		}
		if err := f.ParseFromData(data, collect); err != nil {
			return count, err
		}
	}

	return count, nil
}

// IsSpecContentType returns true if the content-type header suggests API spec content.
func IsSpecContentType(ct string) bool {
	ct = strings.ToLower(ct)
	for _, allowed := range []string{
		"application/json",
		"application/yaml",
		"text/yaml",
		"application/x-yaml",
		"text/json",
	} {
		if strings.HasPrefix(ct, allowed) {
			return true
		}
	}
	return false
}

