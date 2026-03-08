package openapi

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// normalizeRawRequest normalizes a raw HTTP request for comparison.
// It sorts headers alphabetically and normalizes JSON body key order.
func normalizeRawRequest(raw string) string {
	// Split into headers and body
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	if len(parts) == 0 {
		return raw
	}

	headerSection := parts[0]
	var body string
	if len(parts) > 1 {
		body = parts[1]
	}

	// Parse header lines
	lines := strings.Split(headerSection, "\r\n")
	if len(lines) == 0 {
		return raw
	}

	// First line is request line
	requestLine := lines[0]
	headers := lines[1:]

	// Sort headers
	sort.Strings(headers)

	// Rebuild
	var sb strings.Builder
	sb.WriteString(requestLine)
	sb.WriteString("\r\n")
	for _, h := range headers {
		sb.WriteString(h)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")

	// Normalize JSON body if present
	if body != "" {
		body = normalizeJSONBody(body)
		sb.WriteString(body)
	}

	return sb.String()
}

// normalizeJSONBody normalizes JSON by re-marshaling with sorted keys.
func normalizeJSONBody(body string) string {
	var data any
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return body // Not JSON, return as-is
	}
	normalized, err := json.Marshal(data)
	if err != nil {
		return body
	}
	return string(normalized)
}

func TestParseOpenAPI_VAmPI_RawRequests(t *testing.T) {
	// Inline VAmPI spec for test reproducibility
	spec := []byte(`
openapi: 3.0.1
info:
  title: VAmPI
  version: '0.1'
servers:
  - url: http://localhost:5000
paths:
  /createdb:
    get:
      summary: Creates and populates the database
      responses:
        '200':
          description: Success
  /:
    get:
      summary: VAmPI home
      responses:
        '200':
          description: Home
  /users/v1:
    get:
      summary: Retrieves all users
      responses:
        '200':
          description: Success
  /users/v1/_debug:
    get:
      summary: Debug endpoint
      responses:
        '200':
          description: Success
  /users/v1/register:
    post:
      summary: Register new user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                  example: 'name1'
                password:
                  type: string
                  example: 'pass1'
                email:
                  type: string
                  example: 'user@tempmail.com'
      responses:
        '200':
          description: Success
  /users/v1/login:
    post:
      summary: Login
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                  example: 'name1'
                password:
                  type: string
                  example: 'pass1'
      responses:
        '200':
          description: Success
  /me:
    get:
      summary: Get current user
      responses:
        '200':
          description: Success
  /users/v1/{username}:
    get:
      summary: Get user by username
      parameters:
        - name: username
          in: path
          required: true
          schema:
            type: string
            example: 'name1'
      responses:
        '200':
          description: Success
    delete:
      summary: Delete user
      parameters:
        - name: username
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Success
  /users/v1/{username}/email:
    put:
      summary: Update email
      parameters:
        - name: username
          in: path
          required: true
          schema:
            type: string
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
                  example: 'mail3@mail.com'
      responses:
        '204':
          description: Success
  /users/v1/{username}/password:
    put:
      summary: Update password
      parameters:
        - name: username
          in: path
          required: true
          schema:
            type: string
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                password:
                  type: string
                  example: 'pass4'
      responses:
        '204':
          description: Success
  /books/v1:
    get:
      summary: Get all books
      responses:
        '200':
          description: Success
    post:
      summary: Add new book
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                book_title:
                  type: string
                  example: 'book99'
                secret:
                  type: string
                  example: 'pass1secret'
      responses:
        '200':
          description: Success
  /books/v1/{book_title}:
    get:
      summary: Get book by title
      parameters:
        - name: book_title
          in: path
          required: true
          schema:
            type: string
            example: 'bookTitle77'
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
	require.Len(t, requests, 14, "Expected 14 operations")

	// Build lookup map: "METHOD /path" -> request
	byKey := make(map[string]*httpmsg.HttpRequestResponse)
	for _, req := range requests {
		u, _ := req.URL()
		key := req.Request().Method() + " " + u.Path
		byKey[key] = req
	}

	tests := []struct {
		name        string
		key         string
		expectedRaw string
	}{
		{
			name: "GET /createdb",
			key:  "GET /createdb",
			expectedRaw: "GET /createdb HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n",
		},
		{
			name: "GET /",
			key:  "GET /",
			expectedRaw: "GET / HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n",
		},
		{
			name: "GET /users/v1",
			key:  "GET /users/v1",
			expectedRaw: "GET /users/v1 HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n",
		},
		{
			name: "GET /users/v1/_debug",
			key:  "GET /users/v1/_debug",
			expectedRaw: "GET /users/v1/_debug HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n",
		},
		{
			name: "POST /users/v1/register",
			key:  "POST /users/v1/register",
			expectedRaw: "POST /users/v1/register HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Content-Length: 67\r\n" +
				"Content-Type: application/json\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n" +
				`{"email":"user@tempmail.com","password":"pass1","username":"name1"}`,
		},
		{
			name: "POST /users/v1/login",
			key:  "POST /users/v1/login",
			expectedRaw: "POST /users/v1/login HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Content-Length: 39\r\n" +
				"Content-Type: application/json\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n" +
				`{"password":"pass1","username":"name1"}`,
		},
		{
			name: "GET /me",
			key:  "GET /me",
			expectedRaw: "GET /me HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n",
		},
		{
			name: "GET /users/v1/{username} with example",
			key:  "GET /users/v1/name1",
			expectedRaw: "GET /users/v1/name1 HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n",
		},
		{
			name: "DELETE /users/v1/{username} no example",
			key:  "DELETE /users/v1/string",
			expectedRaw: "DELETE /users/v1/string HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n",
		},
		{
			name: "PUT /users/v1/{username}/email",
			key:  "PUT /users/v1/string/email",
			expectedRaw: "PUT /users/v1/string/email HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Content-Length: 26\r\n" +
				"Content-Type: application/json\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n" +
				`{"email":"mail3@mail.com"}`,
		},
		{
			name: "PUT /users/v1/{username}/password",
			key:  "PUT /users/v1/string/password",
			expectedRaw: "PUT /users/v1/string/password HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Content-Length: 20\r\n" +
				"Content-Type: application/json\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n" +
				`{"password":"pass4"}`,
		},
		{
			name: "GET /books/v1",
			key:  "GET /books/v1",
			expectedRaw: "GET /books/v1 HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n",
		},
		{
			name: "POST /books/v1",
			key:  "POST /books/v1",
			expectedRaw: "POST /books/v1 HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Content-Length: 46\r\n" +
				"Content-Type: application/json\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n" +
				`{"book_title":"book99","secret":"pass1secret"}`,
		},
		{
			name: "GET /books/v1/{book_title}",
			key:  "GET /books/v1/bookTitle77",
			expectedRaw: "GET /books/v1/bookTitle77 HTTP/1.1\r\n" +
				"Host: localhost:5000\r\n" +
				"Accept-Encoding: gzip\r\n" +
				"\r\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, ok := byKey[tc.key]
			require.True(t, ok, "Request not found for key: %s", tc.key)

			actualRaw := string(req.Request().Raw())
			expected := normalizeRawRequest(tc.expectedRaw)
			actual := normalizeRawRequest(actualRaw)

			assert.Equal(t, expected, actual,
				"Raw request mismatch.\nExpected:\n%s\n\nActual:\n%s",
				tc.expectedRaw, actualRaw)
		})
	}
}
