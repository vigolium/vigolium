package openapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestParseOpenAPI_RequiresBaseURLByDefault(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /users:
    get:
      summary: List users
      responses:
        '200':
          description: Success
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	// Without BaseURL and without UseSpecServers, should error
	opts := Options{}

	err := ParseOpenAPI(spec, opts, callback)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base URL required")
	assert.Empty(t, requests)
}

func TestParseOpenAPI_WithUseSpecServers(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /users:
    get:
      summary: List users
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
            default: 10
      responses:
        '200':
          description: Success
    post:
      summary: Create user
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                email:
                  type: string
                  format: email
      responses:
        '201':
          description: Created
  /users/{id}:
    get:
      summary: Get user by ID
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
            example: 42
      responses:
        '200':
          description: Success
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{
		UseSpecServers: true,
	}

	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)

	// Should generate 3 requests: GET /users, POST /users, GET /users/{id}
	assert.Len(t, requests, 3)

	// Verify URLs
	var urls []string
	for _, req := range requests {
		urls = append(urls, req.Target())
	}

	assert.Contains(t, urls, "https://api.example.com/users?limit=10")
	assert.Contains(t, urls, "https://api.example.com/users")
	assert.Contains(t, urls, "https://api.example.com/users/42")
}

func TestParseOpenAPI_WithBaseURLOverride(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /health:
    get:
      summary: Health check
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
		BaseURL: "https://staging.example.com/api/v2",
	}

	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)

	require.Len(t, requests, 1)
	assert.Contains(t, requests[0].Target(), "staging.example.com")
	assert.Contains(t, requests[0].Target(), "/api/v2/health")
}

func TestParseOpenAPI_PreserveSpecServerPath(t *testing.T) {
	// Absolute server with a path prefix; host pinned via BaseURL, basePath kept.
	specAbs := []byte(`
openapi: "3.0.0"
info: {title: T, version: "1.0.0"}
servers:
  - url: https://api.internal.example.com/api/v3
paths:
  /users:
    get:
      responses:
        '200': {description: OK}
`)
	// Relative server path.
	specRel := []byte(`
openapi: "3.0.0"
info: {title: T, version: "1.0.0"}
servers:
  - url: /v2
paths:
  /ping:
    get:
      responses:
        '200': {description: OK}
`)
	// Templated server variables.
	specVar := []byte(`
openapi: "3.0.0"
info: {title: T, version: "1.0.0"}
servers:
  - url: "https://{host}/{basePath}"
    variables:
      host: {default: api.example.com}
      basePath: {default: api/v4}
paths:
  /items:
    get:
      responses:
        '200': {description: OK}
`)

	parseOA := func(t *testing.T, data []byte, opts Options) []*httpmsg.HttpRequestResponse {
		var reqs []*httpmsg.HttpRequestResponse
		require.NoError(t, ParseOpenAPI(data, opts, func(r *httpmsg.HttpRequestResponse) bool {
			reqs = append(reqs, r)
			return true
		}))
		return reqs
	}

	t.Run("absolute server path preserved, host pinned", func(t *testing.T) {
		reqs := parseOA(t, specAbs, Options{BaseURL: "https://target.example.com", PreserveSpecServerPath: true})
		require.Len(t, reqs, 1)
		assert.Equal(t, "https://target.example.com/api/v3/users", reqs[0].Target())
	})

	t.Run("relative server path preserved", func(t *testing.T) {
		reqs := parseOA(t, specRel, Options{BaseURL: "https://target.example.com", PreserveSpecServerPath: true})
		require.Len(t, reqs, 1)
		assert.Equal(t, "https://target.example.com/v2/ping", reqs[0].Target())
	})

	t.Run("server variables substituted with defaults", func(t *testing.T) {
		reqs := parseOA(t, specVar, Options{BaseURL: "https://target.example.com", PreserveSpecServerPath: true})
		require.Len(t, reqs, 1)
		assert.Equal(t, "https://target.example.com/api/v4/items", reqs[0].Target())
	})

	t.Run("option off keeps legacy full-override behaviour", func(t *testing.T) {
		reqs := parseOA(t, specAbs, Options{BaseURL: "https://target.example.com"})
		require.Len(t, reqs, 1)
		assert.Equal(t, "https://target.example.com/users", reqs[0].Target())
	})

	t.Run("swagger 2 basePath preserved", func(t *testing.T) {
		swagger2 := []byte(`{
  "swagger": "2.0",
  "info": {"title": "T", "version": "1.0.0"},
  "schemes": ["https"],
  "host": "api.internal.example.com",
  "basePath": "/api/v1",
  "paths": {"/users": {"get": {"responses": {"200": {"description": "OK"}}}}}
}`)
		var reqs []*httpmsg.HttpRequestResponse
		require.NoError(t, ParseSwagger(swagger2, ".json", Options{BaseURL: "https://target.example.com", PreserveSpecServerPath: true}, func(r *httpmsg.HttpRequestResponse) bool {
			reqs = append(reqs, r)
			return true
		}))
		require.Len(t, reqs, 1)
		assert.Equal(t, "https://target.example.com/api/v1/users", reqs[0].Target())
	})
}

func TestParseOpenAPI_WithCustomHeaders(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: https://api.example.com
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
		Headers: map[string]string{
			"Authorization": "Bearer token123",
			"X-Custom":      "value",
		},
	}

	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)

	require.Len(t, requests, 1)
	rawReq := string(requests[0].Request().Raw())
	assert.Contains(t, rawReq, "Authorization: Bearer token123")
	assert.Contains(t, rawReq, "X-Custom: value")
}

func TestParseOpenAPI_WithVariables(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /search:
    get:
      summary: Search
      parameters:
        - name: query
          in: query
          required: true
          schema:
            type: string
        - name: api_key
          in: query
          required: true
          schema:
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

	opts := Options{
		UseSpecServers: true,
		Variables: map[string]string{
			"query":   "test search",
			"api_key": "secret123",
		},
	}

	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)

	require.Len(t, requests, 1)
	target := requests[0].Target()
	assert.Contains(t, target, "query=test+search")
	assert.Contains(t, target, "api_key=secret123")
}

func TestGenerateExampleFromSchema(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		expected string
	}{
		{"date", "date", "2024-01-15"},
		{"date-time", "date-time", "2024-01-15T10:30:00Z"},
		{"email", "email", "user@example.com"},
		{"uuid", "uuid", "550e8400-e29b-41d4-a716-446655440000"},
		{"ipv4", "ipv4", "192.0.2.1"},
		{"ipv6", "ipv6", "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stringFormatExample(tt.format, nil)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseOpenAPI_ParameterExamples(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /users/{userId}:
    get:
      parameters:
        - name: userId
          in: path
          required: true
          example: "user-123"
          schema:
            type: string
        - name: filter
          in: query
          examples:
            active:
              value: "status=active"
            all:
              value: "status=all"
          schema:
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
	// Parameter.Example has higher priority than Schema
	assert.Contains(t, requests[0].Target(), "/users/user-123")
	// First example from Examples map
	assert.Contains(t, requests[0].Target(), "filter=")
}

func TestParseOpenAPI_RequestBodyExample(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            example:
              name: "John Doe"
              email: "john@example.com"
            schema:
              type: object
              properties:
                name:
                  type: string
                email:
                  type: string
      responses:
        '201':
          description: Created
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
	// MediaType.Example should be used instead of generating from schema
	rawReq := string(requests[0].Request().Raw())
	assert.Contains(t, rawReq, `"name":"John Doe"`)
	assert.Contains(t, rawReq, `"email":"john@example.com"`)
}

func TestParseOpenAPI_XExampleExtension(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /items:
    get:
      parameters:
        - name: category
          in: query
          x-example: "electronics"
          schema:
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
	assert.Contains(t, requests[0].Target(), "category=electronics")
}

func TestParseOpenAPI_DefaultFallbackValue_NoSchema(t *testing.T) {
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /items:
    get:
      parameters:
        - name: token
          in: query
          required: true
      responses:
        '200':
          description: OK
`)

	t.Run("without fallback - skips request", func(t *testing.T) {
		var requests []*httpmsg.HttpRequestResponse
		callback := func(req *httpmsg.HttpRequestResponse) bool {
			requests = append(requests, req)
			return true
		}

		opts := Options{UseSpecServers: true}
		err := ParseOpenAPI(spec, opts, callback)
		require.NoError(t, err)
		// Request skipped because required param has no schema/example
		assert.Empty(t, requests)
	})

	t.Run("with fallback - uses fallback value", func(t *testing.T) {
		var requests []*httpmsg.HttpRequestResponse
		callback := func(req *httpmsg.HttpRequestResponse) bool {
			requests = append(requests, req)
			return true
		}

		opts := Options{
			UseSpecServers:       true,
			DefaultFallbackValue: "1",
		}
		err := ParseOpenAPI(spec, opts, callback)
		require.NoError(t, err)

		require.Len(t, requests, 1)
		assert.Contains(t, requests[0].Target(), "token=1")
	})
}

func TestParseOpenAPI_DefaultFallbackValue_WithSchema(t *testing.T) {
	// Spec with required param that has schema type
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /items/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: OK
`)

	t.Run("without fallback - uses schema generated value", func(t *testing.T) {
		var requests []*httpmsg.HttpRequestResponse
		callback := func(req *httpmsg.HttpRequestResponse) bool {
			requests = append(requests, req)
			return true
		}

		opts := Options{UseSpecServers: true}
		err := ParseOpenAPI(spec, opts, callback)
		require.NoError(t, err)
		// Schema generates "string" for type: string
		require.Len(t, requests, 1)
		assert.Contains(t, requests[0].Target(), "/items/string")
	})

	t.Run("with fallback - fallback takes precedence over schema generated", func(t *testing.T) {
		var requests []*httpmsg.HttpRequestResponse
		callback := func(req *httpmsg.HttpRequestResponse) bool {
			requests = append(requests, req)
			return true
		}

		opts := Options{
			UseSpecServers:       true,
			DefaultFallbackValue: "test-id",
		}
		err := ParseOpenAPI(spec, opts, callback)
		require.NoError(t, err)

		require.Len(t, requests, 1)
		// Fallback takes precedence for required params without explicit example
		assert.Contains(t, requests[0].Target(), "/items/test-id")
	})
}

func TestParseOpenAPI_MethodPrioritySorting(t *testing.T) {
	// Spec with multiple methods and paths to verify sorting order
	spec := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: https://api.example.com
paths:
  /users:
    delete:
      summary: Delete all users
      responses:
        '204':
          description: Deleted
    post:
      summary: Create user
      responses:
        '201':
          description: Created
    get:
      summary: List users
      responses:
        '200':
          description: Success
  /books:
    patch:
      summary: Patch book
      responses:
        '200':
          description: Success
    put:
      summary: Update book
      responses:
        '200':
          description: Success
    get:
      summary: List books
      responses:
        '200':
          description: Success
  /admin:
    options:
      summary: Options for admin
      responses:
        '200':
          description: Success
    head:
      summary: Head for admin
      responses:
        '200':
          description: Success
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseOpenAPI(spec, opts, callback)
	require.NoError(t, err)

	require.Len(t, requests, 8)

	// Extract method and path for each request
	type reqInfo struct {
		method string
		path   string
	}
	var order []reqInfo
	for _, req := range requests {
		u, err := req.Request().URL()
		require.NoError(t, err)
		order = append(order, reqInfo{
			method: req.Request().Method(),
			path:   u.Path,
		})
	}

	// Expected order: GET (0) > POST (1) > PUT (2) > PATCH (3) > OPTIONS (4) > HEAD (5) > DELETE (6)
	// Within same method, alphabetical by path
	expected := []reqInfo{
		{method: "GET", path: "/books"},
		{method: "GET", path: "/users"},
		{method: "POST", path: "/users"},
		{method: "PUT", path: "/books"},
		{method: "PATCH", path: "/books"},
		{method: "OPTIONS", path: "/admin"},
		{method: "HEAD", path: "/admin"},
		{method: "DELETE", path: "/users"},
	}

	assert.Equal(t, expected, order, "Requests should be sorted by method priority (GET>POST>PUT>PATCH>OPTIONS>HEAD>DELETE), then alphabetically by path")
}
