package openapi

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSwagger_WithUseSpecServers(t *testing.T) {
	spec := []byte(`{
  "swagger": "2.0",
  "info": {
    "title": "Test API",
    "version": "1.0.0"
  },
  "host": "api.example.com",
  "basePath": "/v1",
  "schemes": ["https"],
  "paths": {
    "/users": {
      "get": {
        "summary": "List users",
        "parameters": [
          {
            "name": "limit",
            "in": "query",
            "type": "integer",
            "default": 10
          }
        ],
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      },
      "post": {
        "summary": "Create user",
        "consumes": ["application/json"],
        "parameters": [
          {
            "name": "body",
            "in": "body",
            "schema": {
              "type": "object",
              "properties": {
                "name": {"type": "string"},
                "email": {"type": "string", "format": "email"}
              }
            }
          }
        ],
        "responses": {
          "201": {
            "description": "Created"
          }
        }
      }
    },
    "/users/{id}": {
      "get": {
        "summary": "Get user by ID",
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "type": "integer",
            "x-example": 42
          }
        ],
        "responses": {
          "200": {
            "description": "Success"
          }
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

	opts := Options{
		UseSpecServers: true,
	}

	err := ParseSwagger(spec, ".json", opts, callback)
	require.NoError(t, err)

	// Should generate 3 requests: GET /users, POST /users, GET /users/{id}
	assert.Len(t, requests, 3)

	// Verify URLs
	var urls []string
	for _, req := range requests {
		urls = append(urls, req.Target())
	}

	assert.Contains(t, urls, "https://api.example.com/v1/users?limit=10")
	assert.Contains(t, urls, "https://api.example.com/v1/users")
	assert.Contains(t, urls, "https://api.example.com/v1/users/42")
}

func TestParseSwagger_YAML(t *testing.T) {
	spec := []byte(`
swagger: "2.0"
info:
  title: Test API
  version: "1.0.0"
host: api.example.com
basePath: /api
schemes:
  - https
paths:
  /status:
    get:
      summary: Get status
      responses:
        200:
          description: OK
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{UseSpecServers: true}
	err := ParseSwagger(spec, ".yaml", opts, callback)
	require.NoError(t, err)

	require.Len(t, requests, 1)
	assert.Contains(t, requests[0].Target(), "api.example.com")
	assert.Contains(t, requests[0].Target(), "/api/status")
}

func TestParseSwagger_WithBaseURLOverride(t *testing.T) {
	spec := []byte(`{
  "swagger": "2.0",
  "info": {
    "title": "Test API",
    "version": "1.0.0"
  },
  "host": "api.example.com",
  "basePath": "/v1",
  "schemes": ["https"],
  "paths": {
    "/health": {
      "get": {
        "responses": {
          "200": {
            "description": "OK"
          }
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

	opts := Options{
		BaseURL: "https://staging.example.com/api/v2",
	}

	err := ParseSwagger(spec, ".json", opts, callback)
	require.NoError(t, err)

	require.Len(t, requests, 1)
	assert.Contains(t, requests[0].Target(), "staging.example.com")
	assert.Contains(t, requests[0].Target(), "/api/v2/health")
}

func TestParseSwagger_WithCustomHeaders(t *testing.T) {
	spec := []byte(`{
  "swagger": "2.0",
  "info": {
    "title": "Test API",
    "version": "1.0.0"
  },
  "host": "api.example.com",
  "basePath": "/v1",
  "schemes": ["https"],
  "paths": {
    "/protected": {
      "get": {
        "summary": "Protected endpoint",
        "responses": {
          "200": {
            "description": "OK"
          }
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

	opts := Options{
		UseSpecServers: true,
		Headers: map[string]string{
			"Authorization": "Bearer token123",
			"X-Custom":      "value",
		},
	}

	err := ParseSwagger(spec, ".json", opts, callback)
	require.NoError(t, err)

	require.Len(t, requests, 1)
	rawReq := string(requests[0].Request().Raw())
	assert.Contains(t, rawReq, "Authorization: Bearer token123")
	assert.Contains(t, rawReq, "X-Custom: value")
}

func TestParseSwagger_WithVariables(t *testing.T) {
	spec := []byte(`{
  "swagger": "2.0",
  "info": {
    "title": "Test API",
    "version": "1.0.0"
  },
  "host": "api.example.com",
  "basePath": "/v1",
  "schemes": ["https"],
  "paths": {
    "/search": {
      "get": {
        "summary": "Search",
        "parameters": [
          {
            "name": "query",
            "in": "query",
            "required": true,
            "type": "string"
          },
          {
            "name": "api_key",
            "in": "query",
            "required": true,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "OK"
          }
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

	opts := Options{
		UseSpecServers: true,
		Variables: map[string]string{
			"query":   "test search",
			"api_key": "secret123",
		},
	}

	err := ParseSwagger(spec, ".json", opts, callback)
	require.NoError(t, err)

	require.Len(t, requests, 1)
	target := requests[0].Target()
	assert.Contains(t, target, "query=test+search")
	assert.Contains(t, target, "api_key=secret123")
}

func TestParseSwagger_ParameterDefault(t *testing.T) {
	spec := []byte(`{
  "swagger": "2.0",
  "info": {
    "title": "Test API",
    "version": "1.0.0"
  },
  "host": "api.example.com",
  "basePath": "/v1",
  "schemes": ["https"],
  "paths": {
    "/items": {
      "get": {
        "parameters": [
          {
            "name": "page",
            "in": "query",
            "type": "integer",
            "default": 1
          },
          {
            "name": "limit",
            "in": "query",
            "type": "integer",
            "default": 20
          }
        ],
        "responses": {
          "200": {
            "description": "OK"
          }
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

	opts := Options{UseSpecServers: true}
	err := ParseSwagger(spec, ".json", opts, callback)
	require.NoError(t, err)

	require.Len(t, requests, 1)
	target := requests[0].Target()
	assert.Contains(t, target, "page=1")
	assert.Contains(t, target, "limit=20")
}

func TestParseSwagger_XExampleExtension(t *testing.T) {
	spec := []byte(`{
  "swagger": "2.0",
  "info": {
    "title": "Test API",
    "version": "1.0.0"
  },
  "host": "api.example.com",
  "basePath": "/v1",
  "schemes": ["https"],
  "paths": {
    "/items": {
      "get": {
        "parameters": [
          {
            "name": "category",
            "in": "query",
            "type": "string",
            "x-example": "electronics"
          }
        ],
        "responses": {
          "200": {
            "description": "OK"
          }
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

	opts := Options{UseSpecServers: true}
	err := ParseSwagger(spec, ".json", opts, callback)
	require.NoError(t, err)

	require.Len(t, requests, 1)
	assert.Contains(t, requests[0].Target(), "category=electronics")
}

// TestParseSwagger_UnwrapSwaggerDocWrapper tests that swagger specs wrapped in
// {"swaggerDoc": {...}} structure are correctly unwrapped and parsed.
func TestParseSwagger_UnwrapSwaggerDocWrapper(t *testing.T) {
	// Spec wrapped in swaggerDoc structure (common in swagger-ui-express)
	wrappedSpec := []byte(`{
  "swaggerDoc": {
    "openapi": "3.0.0",
    "info": {
      "title": "Wrapped API",
      "version": "1.0.0"
    },
    "paths": {
      "/api/users": {
        "get": {
          "summary": "Get users",
          "responses": {
            "200": {
              "description": "Success"
            }
          }
        }
      },
      "/api/items": {
        "post": {
          "summary": "Create item",
          "responses": {
            "201": {
              "description": "Created"
            }
          }
        }
      }
    }
  },
  "customOptions": {
    "explorer": true
  }
}`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{
		BaseURL: "https://api.example.com",
	}

	err := ParseSwagger(wrappedSpec, ".json", opts, callback)
	require.NoError(t, err)

	// Should generate 2 requests from the unwrapped spec
	require.Len(t, requests, 2)

	// Verify URLs
	var urls []string
	for _, req := range requests {
		urls = append(urls, req.Target())
	}
	assert.Contains(t, urls, "https://api.example.com/api/users")
	assert.Contains(t, urls, "https://api.example.com/api/items")
}

// TestParseSwagger_UnwrapSwaggerDocWrapperYAML tests that YAML swagger specs wrapped in
// swaggerDoc structure are correctly unwrapped and parsed.
func TestParseSwagger_UnwrapSwaggerDocWrapperYAML(t *testing.T) {
	wrappedSpec := []byte(`swaggerDoc:
  openapi: "3.0.0"
  info:
    title: Wrapped YAML API
    version: "1.0.0"
  paths:
    /yaml/users:
      get:
        summary: Get users
        responses:
          "200":
            description: Success
    /yaml/items:
      post:
        summary: Create item
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  name:
                    type: string
                    example: "test-item"
        responses:
          "201":
            description: Created
customOptions:
  explorer: true
`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{
		BaseURL: "https://api.example.com",
	}

	err := ParseSwagger(wrappedSpec, ".yaml", opts, callback)
	require.NoError(t, err)

	// Should generate 2 requests from the unwrapped spec
	require.Len(t, requests, 2)

	// Verify URLs
	var urls []string
	for _, req := range requests {
		urls = append(urls, req.Target())
	}
	assert.Contains(t, urls, "https://api.example.com/yaml/users")
	assert.Contains(t, urls, "https://api.example.com/yaml/items")

	// Verify POST request has body
	for _, req := range requests {
		if req.Request().Method() == "POST" {
			body := req.Request().BodyToString()
			assert.Contains(t, body, "test-item", "POST request should have body from requestBody schema")
		}
	}
}

// TestParseSwagger_AutoDetectOpenAPI3 tests that OpenAPI 3.x specs are detected
// and parsed correctly even when using ParseSwagger.
func TestParseSwagger_AutoDetectOpenAPI3(t *testing.T) {
	// OpenAPI 3.0 spec (not Swagger 2.0)
	openapi3Spec := []byte(`{
  "openapi": "3.0.0",
  "info": {
    "title": "OpenAPI 3 API",
    "version": "1.0.0"
  },
  "paths": {
    "/v3/resource": {
      "get": {
        "summary": "Get resource",
        "parameters": [
          {
            "name": "filter",
            "in": "query",
            "schema": {
              "type": "string",
              "example": "active"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Success"
          }
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

	opts := Options{
		BaseURL: "https://api.example.com",
	}

	// Using ParseSwagger with OpenAPI 3.0 spec should auto-detect and work
	err := ParseSwagger(openapi3Spec, ".json", opts, callback)
	require.NoError(t, err)

	require.Len(t, requests, 1)
	assert.Contains(t, requests[0].Target(), "/v3/resource")
	assert.Contains(t, requests[0].Target(), "filter=active")
}

// TestParseSwagger_BaseURLNormalization tests that trailing slashes in BaseURL
// are normalized to prevent double slashes in generated URLs.
func TestParseSwagger_BaseURLNormalization(t *testing.T) {
	spec := []byte(`{
  "swagger": "2.0",
  "info": {
    "title": "Test API",
    "version": "1.0.0"
  },
  "host": "api.example.com",
  "basePath": "/v1",
  "schemes": ["https"],
  "paths": {
    "/users": {
      "get": {
        "responses": {
          "200": {
            "description": "OK"
          }
        }
      }
    }
  }
}`)

	t.Run("BaseURL with trailing slash", func(t *testing.T) {
		var requests []*httpmsg.HttpRequestResponse
		callback := func(req *httpmsg.HttpRequestResponse) bool {
			requests = append(requests, req)
			return true
		}

		opts := Options{
			BaseURL: "https://staging.example.com/api/", // trailing slash
		}

		err := ParseSwagger(spec, ".json", opts, callback)
		require.NoError(t, err)

		require.Len(t, requests, 1)
		// Should NOT have double slash
		assert.NotContains(t, requests[0].Target(), "//users")
		assert.Contains(t, requests[0].Target(), "/api/users")
	})

	t.Run("BaseURL without trailing slash", func(t *testing.T) {
		var requests []*httpmsg.HttpRequestResponse
		callback := func(req *httpmsg.HttpRequestResponse) bool {
			requests = append(requests, req)
			return true
		}

		opts := Options{
			BaseURL: "https://staging.example.com/api", // no trailing slash
		}

		err := ParseSwagger(spec, ".json", opts, callback)
		require.NoError(t, err)

		require.Len(t, requests, 1)
		assert.Contains(t, requests[0].Target(), "/api/users")
	})
}

// TestParseSwagger_WrappedOpenAPI3Spec tests the combined case of a wrapped
// OpenAPI 3.0 spec (the original bug scenario).
func TestParseSwagger_WrappedOpenAPI3Spec(t *testing.T) {
	// This simulates the actual swagger.json format from swagger-ui-express
	// where OpenAPI 3.0 spec is wrapped in swaggerDoc
	wrappedSpec := []byte(`{
  "swaggerDoc": {
    "openapi": "3.0.0",
    "info": {
      "title": "Real API",
      "version": "1.0.0"
    },
    "paths": {
      "/api/request/employee-info-change-request/search": {
        "get": {
          "operationId": "RequestController_search",
          "parameters": [
            {
              "name": "page",
              "required": true,
              "in": "query",
              "schema": {
                "type": "number"
              }
            },
            {
              "name": "pageSize",
              "required": true,
              "in": "query",
              "schema": {
                "type": "number"
              }
            }
          ],
          "responses": {
            "200": {
              "description": "Success"
            }
          }
        }
      },
      "/api/auth/login": {
        "post": {
          "operationId": "AuthController_login",
          "requestBody": {
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "email": {"type": "string"},
                    "password": {"type": "string"}
                  }
                }
              }
            }
          },
          "responses": {
            "201": {
              "description": "Success"
            }
          }
        }
      }
    }
  },
  "customOptions": {}
}`)

	var requests []*httpmsg.HttpRequestResponse
	callback := func(req *httpmsg.HttpRequestResponse) bool {
		requests = append(requests, req)
		return true
	}

	opts := Options{
		BaseURL:              "https://125.212.198.16:3000/", // trailing slash
		DefaultFallbackValue: "1",
	}

	err := ParseSwagger(wrappedSpec, ".json", opts, callback)
	require.NoError(t, err)

	// Should generate 2 requests
	require.Len(t, requests, 2)

	// Verify URLs don't have double slashes
	for _, req := range requests {
		assert.NotContains(t, req.Target(), "//api", "URL should not have double slashes")
	}

	// Verify endpoints are correct
	var urls []string
	for _, req := range requests {
		urls = append(urls, req.Target())
	}
	assert.True(t, strings.Contains(urls[0], "/api/") || strings.Contains(urls[1], "/api/"))
}
