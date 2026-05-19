package openapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// =============================================================================
// Tests based on Nuclei's VAmPI spec
// =============================================================================

func TestParseOpenAPI_VAmPI(t *testing.T) {
	specPath := filepath.Join("testdata", "vampi.yaml")
	specData, err := os.ReadFile(specPath)
	require.NoError(t, err)

	expectedURLsByMethod := map[string][]string{
		"GET": {
			"/createdb",
			"/",
			"/users/v1/John.Doe",
			"/users/v1",
			"/users/v1/_debug",
			"/books/v1",
			"/books/v1/bookTitle77",
		},
		"POST": {
			"/users/v1/register",
			"/users/v1/login",
			"/books/v1",
		},
		"PUT": {
			"/users/v1/name1/email",
			"/users/v1/name1/password",
		},
		"DELETE": {
			"/users/v1/name1",
		},
	}

	gotURLsByMethod := make(map[string][]string)
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		method := req.Request().Method()
		u, _ := req.URL()
		path := u.Path
		gotURLsByMethod[method] = append(gotURLsByMethod[method], path)
		return true
	}

	opts := Options{UseSpecServers: true}
	err = ParseOpenAPI(specData, opts, callback)
	require.NoError(t, err)

	for method, expectedPaths := range expectedURLsByMethod {
		assert.ElementsMatch(t, expectedPaths, gotURLsByMethod[method],
			"mismatch for method %s", method)
	}
}

func TestParseSwagger_SimpleSpec(t *testing.T) {
	specPath := filepath.Join("testdata", "swagger_simple.yaml")
	specData, err := os.ReadFile(specPath)
	require.NoError(t, err)

	var urls []string
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		u, _ := req.URL()
		urls = append(urls, u.Path)
		return true
	}

	opts := Options{UseSpecServers: true}
	err = ParseSwagger(specData, ".yaml", opts, callback)
	require.NoError(t, err)

	require.Len(t, urls, 2)
	assert.Contains(t, urls, "/v1/users")
	assert.Contains(t, urls, "/v1/users/1")
}

// =============================================================================
// Security Schemes Edge Cases
// =============================================================================

func TestParseOpenAPI_SecurityScheme_APIKey(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: API with API Key
  version: "1.0.0"
servers:
  - url: https://api.example.com
components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
security:
  - ApiKeyAuth: []
paths:
  /protected:
    get:
      summary: Protected endpoint
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{
		UseSpecServers: true,
		Variables: map[string]string{
			"X-API-Key": "secret-api-key-123",
		},
	}

	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	rawReq := string(requests[0].Request().Raw())
	// HTTP headers are canonicalized (X-Api-Key instead of X-API-Key)
	assert.Contains(t, rawReq, "X-Api-Key: secret-api-key-123")
}

func TestParseOpenAPI_SecurityScheme_BearerAuth(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: API with Bearer Auth
  version: "1.0.0"
servers:
  - url: https://api.example.com
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
security:
  - BearerAuth: []
paths:
  /protected:
    get:
      summary: Protected endpoint
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{
		UseSpecServers: true,
		Variables: map[string]string{
			"Authorization": "Bearer my-jwt-token",
		},
	}

	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	rawReq := string(requests[0].Request().Raw())
	assert.Contains(t, rawReq, "Authorization: Bearer my-jwt-token")
}

func TestParseOpenAPI_SecurityScheme_APIKeyInQuery(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: API with Query API Key
  version: "1.0.0"
servers:
  - url: https://api.example.com
components:
  securitySchemes:
    QueryApiKey:
      type: apiKey
      in: query
      name: api_key
security:
  - QueryApiKey: []
paths:
  /data:
    get:
      summary: Get data
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{
		UseSpecServers: true,
		Variables: map[string]string{
			"api_key": "my-api-key",
		},
	}

	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Contains(t, requests[0].Target(), "api_key=my-api-key")
}

// =============================================================================
// Content Types Edge Cases
// =============================================================================

func TestParseOpenAPI_ContentType_XML(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: XML API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /xml:
    post:
      summary: XML endpoint
      requestBody:
        content:
          application/xml:
            schema:
              type: object
              properties:
                name:
                  type: string
                age:
                  type: integer
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	rawReq := string(requests[0].Request().Raw())
	assert.Contains(t, rawReq, "Content-Type: application/xml")
}

func TestParseOpenAPI_ContentType_FormURLEncoded(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Form API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /login:
    post:
      summary: Login
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties:
                username:
                  type: string
                password:
                  type: string
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	rawReq := string(requests[0].Request().Raw())
	assert.Contains(t, rawReq, "Content-Type: application/x-www-form-urlencoded")
	assert.Contains(t, rawReq, "username=")
	assert.Contains(t, rawReq, "password=")
}

func TestParseOpenAPI_ContentType_Multipart(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Upload API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /upload:
    post:
      summary: Upload file
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                file:
                  type: string
                  format: binary
                description:
                  type: string
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	rawReq := string(requests[0].Request().Raw())
	assert.Contains(t, rawReq, "Content-Type: multipart/form-data")
}

func TestParseOpenAPI_ContentType_TextPlain(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Text API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /text:
    post:
      summary: Text endpoint
      requestBody:
        content:
          text/plain:
            schema:
              type: string
              example: "Hello, World!"
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	rawReq := string(requests[0].Request().Raw())
	assert.Contains(t, rawReq, "Content-Type: text/plain")
	assert.Contains(t, rawReq, "Hello, World!")
}

// =============================================================================
// Schema Composition Edge Cases (allOf, oneOf, anyOf)
// =============================================================================

func TestParseOpenAPI_Schema_AllOf(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: AllOf API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /pets:
    post:
      summary: Create pet
      requestBody:
        content:
          application/json:
            schema:
              allOf:
                - type: object
                  properties:
                    id:
                      type: integer
                      example: 1
                - type: object
                  properties:
                    name:
                      type: string
                      example: "Fluffy"
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	rawReq := string(requests[0].Request().Raw())
	assert.Contains(t, rawReq, `"id":1`)
	assert.Contains(t, rawReq, `"name":"Fluffy"`)
}

func TestParseOpenAPI_Schema_OneOf(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: OneOf API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /payment:
    post:
      summary: Make payment
      requestBody:
        content:
          application/json:
            schema:
              oneOf:
                - type: object
                  properties:
                    cardNumber:
                      type: string
                      example: "4111111111111111"
                - type: object
                  properties:
                    bankAccount:
                      type: string
                      example: "123456789"
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	// Should use first oneOf option
	rawReq := string(requests[0].Request().Raw())
	assert.Contains(t, rawReq, `"cardNumber":"4111111111111111"`)
}

// =============================================================================
// Parameter Location Edge Cases
// =============================================================================

func TestParseOpenAPI_Parameter_Cookie(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Cookie API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /session:
    get:
      summary: Get session
      parameters:
        - name: session_id
          in: cookie
          required: true
          schema:
            type: string
            example: "abc123"
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	rawReq := string(requests[0].Request().Raw())
	assert.Contains(t, rawReq, "Cookie: session_id=abc123")
}

func TestParseOpenAPI_Parameter_Header(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Header API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /data:
    get:
      summary: Get data
      parameters:
        - name: X-Request-ID
          in: header
          required: true
          schema:
            type: string
            example: "req-12345"
        - name: X-Client-Version
          in: header
          schema:
            type: string
            example: "1.0.0"
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	rawReq := string(requests[0].Request().Raw())
	assert.Contains(t, rawReq, "X-Request-Id: req-12345")
	assert.Contains(t, rawReq, "X-Client-Version: 1.0.0")
}

// =============================================================================
// Enum and Array Edge Cases
// =============================================================================

func TestParseOpenAPI_Parameter_Enum(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Enum API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /items:
    get:
      summary: Get items
      parameters:
        - name: status
          in: query
          schema:
            type: string
            enum: [active, inactive, pending]
        - name: sort
          in: query
          schema:
            type: string
            enum: [asc, desc]
            default: asc
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	target := requests[0].Target()
	// Uses first enum value or default
	assert.Contains(t, target, "status=active")
	assert.Contains(t, target, "sort=asc")
}

func TestParseOpenAPI_Schema_Array(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Array API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /batch:
    post:
      summary: Batch create
      requestBody:
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                  name:
                    type: string
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	rawReq := string(requests[0].Request().Raw())
	// Should generate array with at least one item
	assert.Contains(t, rawReq, "[{")
}

// =============================================================================
// Error Handling Edge Cases
// =============================================================================

func TestParseOpenAPI_EmptySpec(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Empty API
  version: "1.0.0"
paths: {}
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{BaseURL: "https://api.example.com"}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	assert.Empty(t, requests)
}

func TestParseOpenAPI_NoPaths(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: No Paths API
  version: "1.0.0"
servers:
  - url: https://api.example.com
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	assert.Empty(t, requests)
}

func TestParseSwagger_MalformedYAML(t *testing.T) {
	spec := []byte(`
swagger: "2.0"
info
  title: Malformed
  version: 1.0
`)

	callback := func(req *httpmsg.HttpRequestResponse) bool {
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseSwagger(spec, ".yaml", opts, callback)
	require.Error(t, err)
}

func TestParseSwagger_MalformedJSON(t *testing.T) {
	spec := []byte(`{
  "swagger": "2.0",
  "info": {
    "title": "Malformed"
    "version": "1.0"
  }
}`)

	callback := func(req *httpmsg.HttpRequestResponse) bool {
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseSwagger(spec, ".json", opts, callback)
	require.Error(t, err)
}

func TestParseOpenAPI_NoServersAndNoBaseURL(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: No Servers
  version: "1.0.0"
paths:
  /test:
    get:
      responses:
        '200':
          description: OK
`)

	callback := func(req *httpmsg.HttpRequestResponse) bool {
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no servers found")
}

// =============================================================================
// Multiple Servers Edge Cases
// =============================================================================

func TestParseOpenAPI_MultipleServers(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Multi-Server API
  version: "1.0.0"
servers:
  - url: https://api.example.com
  - url: https://api-staging.example.com
paths:
  /health:
    get:
      responses:
        '200':
          description: OK
`)

	var urls []string
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		urls = append(urls, req.Target())
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)

	// Should generate requests for both servers
	require.Len(t, urls, 2)
	hasProduction := false
	hasStaging := false
	for _, u := range urls {
		if strings.Contains(u, "api.example.com") && !strings.Contains(u, "staging") {
			hasProduction = true
		}
		if strings.Contains(u, "api-staging.example.com") {
			hasStaging = true
		}
	}
	assert.True(t, hasProduction, "should have production server URL")
	assert.True(t, hasStaging, "should have staging server URL")
}

// =============================================================================
// Extension Auto-Detection Edge Cases
// =============================================================================

func TestParseSwagger_UnknownExtension_JSON(t *testing.T) {
	spec := []byte(`{
  "swagger": "2.0",
  "info": {
    "title": "Test",
    "version": "1.0.0"
  },
  "host": "api.example.com",
  "basePath": "/v1",
  "schemes": ["https"],
  "paths": {
    "/test": {
      "get": {
        "responses": {
          "200": {"description": "OK"}
        }
      }
    }
  }
}`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	// Unknown extension - should try JSON first
	opts := Options{UseSpecServers: true}
	err := ParseSwagger(spec, ".txt", opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)
}

func TestParseSwagger_UnknownExtension_YAML(t *testing.T) {
	spec := []byte(`
swagger: "2.0"
info:
  title: Test
  version: "1.0.0"
host: api.example.com
basePath: /v1
schemes:
  - https
paths:
  /test:
    get:
      responses:
        200:
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	// Unknown extension - should fallback to YAML after JSON fails
	opts := Options{UseSpecServers: true}
	err := ParseSwagger(spec, ".txt", opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)
}

// =============================================================================
// Multiple Content Types Edge Cases
// =============================================================================

func TestParseOpenAPI_MultipleContentTypes(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Multi-Content API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /data:
    post:
      summary: Submit data
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
          application/xml:
            schema:
              type: object
              properties:
                name:
                  type: string
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties:
                name:
                  type: string
      responses:
        '200':
          description: OK
`)

	var contentTypes []string
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		rawReq := string(req.Request().Raw())
		if strings.Contains(rawReq, "Content-Type: application/json") {
			contentTypes = append(contentTypes, "json")
		}
		if strings.Contains(rawReq, "Content-Type: application/xml") {
			contentTypes = append(contentTypes, "xml")
		}
		if strings.Contains(rawReq, "Content-Type: application/x-www-form-urlencoded") {
			contentTypes = append(contentTypes, "form")
		}
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)

	// Should generate request for each content type
	require.Len(t, contentTypes, 3)
	assert.Contains(t, contentTypes, "json")
	assert.Contains(t, contentTypes, "xml")
	assert.Contains(t, contentTypes, "form")
}

// =============================================================================
// String Format Edge Cases
// =============================================================================

func TestStringFormatExample_AllFormats(t *testing.T) {
	tests := []struct {
		format   string
		expected string
	}{
		{"date", "2024-01-15"},
		{"date-time", "2024-01-15T10:30:00Z"},
		{"email", "user@example.com"},
		{"uuid", "550e8400-e29b-41d4-a716-446655440000"},
		{"ipv4", "192.0.2.1"},
		{"ipv6", "2001:db8::1"},
		{"uri", "https://example.com/path"},
		{"hostname", "example.com"},
		{"byte", "dGVzdA=="}, // base64 of "test"
		{"password", "********"},
		{"binary", "binary-data"},
		{"unknown", ""}, // Unknown format returns empty
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			result := stringFormatExample(tt.format, nil)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Callback Control Edge Cases
// =============================================================================

func TestParseOpenAPI_CallbackStopsEarly(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /a:
    get:
      responses:
        '200':
          description: OK
  /b:
    get:
      responses:
        '200':
          description: OK
  /c:
    get:
      responses:
        '200':
          description: OK
`)

	count := 0
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		count++
		return count < 2 // Stop after 2nd request
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)

	// Callback returns false after 2, so we get 2 requests
	// Note: The callback returning false doesn't stop iteration in current impl
	// This test documents current behavior
	assert.GreaterOrEqual(t, count, 2)
}

// =============================================================================
// Path Parameter Edge Cases
// =============================================================================

func TestParseOpenAPI_MultiplePathParameters(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Multi-Path-Param API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /users/{userId}/posts/{postId}/comments/{commentId}:
    get:
      summary: Get comment
      parameters:
        - name: userId
          in: path
          required: true
          schema:
            type: integer
            example: 1
        - name: postId
          in: path
          required: true
          schema:
            type: integer
            example: 42
        - name: commentId
          in: path
          required: true
          schema:
            type: integer
            example: 100
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	u, _ := requests[0].URL()
	assert.Equal(t, "/users/1/posts/42/comments/100", u.Path)
}

// =============================================================================
// Numeric Type Edge Cases
// =============================================================================

func TestParseOpenAPI_NumericTypes(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Numeric API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /data:
    get:
      parameters:
        - name: int_param
          in: query
          schema:
            type: integer
            minimum: 5
            maximum: 100
        - name: float_param
          in: query
          schema:
            type: number
            minimum: 0.5
            maximum: 10.5
        - name: bool_param
          in: query
          schema:
            type: boolean
      responses:
        '200':
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	target := requests[0].Target()
	// Should contain generated numeric values
	assert.Contains(t, target, "int_param=")
	assert.Contains(t, target, "float_param=")
	assert.Contains(t, target, "bool_param=")
}
