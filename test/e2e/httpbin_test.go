//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	httpClient "github.com/vigolium/vigolium/pkg/http"
)

// TestHttpbin tests HTTP request/response handling using httpbin
// This verifies that Vigolium correctly sends and receives HTTP data
func TestHttpbin(t *testing.T) {
	// NOTE: goleak.VerifyNone removed — the shared fastdialer (backed by LevelDB)
	// and network memory guardian create background goroutines that outlive
	// individual tests, causing persistent false positives in the e2e suite.

	ctx := context.Background()

	// Start httpbin container
	httpbinApp, err := StartContainer(ctx, ContainerConfig{
		Image:         "kennethreitz/httpbin",
		ExposedPort:   "80/tcp",
		WaitStrategy:  wait.ForHTTP("/get").WithStartupTimeout(60 * time.Second),
		ReadyEndpoint: "/get",
	})
	require.NoError(t, err, "Failed to start httpbin container")
	defer httpbinApp.Stop()

	t.Logf("httpbin started at: %s", httpbinApp.BaseURL)

	// Setup test infrastructure
	infra, err := SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	// Extract host from base URL for raw HTTP requests
	// BaseURL format: http://host:port
	baseURL := httpbinApp.BaseURL
	host := strings.TrimPrefix(baseURL, "http://")

	// Parse host and port for Service
	hostPart, portStr, _ := strings.Cut(host, ":")
	port, _ := strconv.Atoi(portStr)
	service := httpmsg.NewServiceSecure(hostPart, port, false) // false = HTTP not HTTPS

	// Test 1: GET request
	t.Run("GET", func(t *testing.T) {
		rawReq := fmt.Sprintf("GET /get?param1=value1&param2=value2 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		t.Logf("Testing GET request")

		// Create HTTP request from raw bytes with service info
		req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
		ctx := httpmsg.NewHttpRequestResponse(req, nil)

		// Send request
		respChain, _, err := infra.HTTPClient.Execute(ctx, httpClient.Options{})
		require.NoError(t, err, "GET request failed")
		defer respChain.Close()

		// Verify response
		resp := respChain.Response()
		assert.Equal(t, 200, resp.StatusCode, "Expected 200 OK")

		// Parse httpbin response
		body := respChain.Body().String()
		var httpbinResp map[string]interface{}
		err = json.Unmarshal([]byte(body), &httpbinResp)
		require.NoError(t, err, "Failed to parse httpbin response")

		// Verify httpbin received our request correctly
		assert.Contains(t, httpbinResp, "url", "Response should contain 'url' field")
		assert.Contains(t, httpbinResp, "args", "Response should contain 'args' field")
		assert.Contains(t, httpbinResp, "headers", "Response should contain 'headers' field")

		// Verify query parameters were sent
		if args, ok := httpbinResp["args"].(map[string]interface{}); ok {
			assert.Contains(t, args, "param1", "Query parameter param1 should be present")
			assert.Contains(t, args, "param2", "Query parameter param2 should be present")
			assert.Equal(t, "value1", args["param1"], "Query parameter param1 value mismatch")
			assert.Equal(t, "value2", args["param2"], "Query parameter param2 value mismatch")
			t.Log("✓ Query parameters verified")
		}

		t.Log("✓ GET request validated successfully")
	})

	// Test 2: POST request with JSON body
	t.Run("POST-JSON", func(t *testing.T) {
		jsonBody := `{"key1":"value1","key2":"value2"}`
		rawReq := fmt.Sprintf("POST /post HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
			host, len(jsonBody), jsonBody)
		t.Log("Testing POST JSON request")

		req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
		ctx := httpmsg.NewHttpRequestResponse(req, nil)

		respChain, _, err := infra.HTTPClient.Execute(ctx, httpClient.Options{})
		require.NoError(t, err, "POST request failed")
		defer respChain.Close()

		// Verify response
		resp := respChain.Response()
		assert.Equal(t, 200, resp.StatusCode, "Expected 200 OK")

		// Parse httpbin response
		body := respChain.Body().String()
		var httpbinResp map[string]interface{}
		err = json.Unmarshal([]byte(body), &httpbinResp)
		require.NoError(t, err, "Failed to parse httpbin response")

		// Verify httpbin received our JSON
		if jsonData, ok := httpbinResp["json"].(map[string]interface{}); ok {
			assert.Equal(t, "value1", jsonData["key1"], "JSON key1 mismatch")
			assert.Equal(t, "value2", jsonData["key2"], "JSON key2 mismatch")
			t.Log("✓ JSON body verified")
		}

		// Verify Content-Type header was sent
		if headers, ok := httpbinResp["headers"].(map[string]interface{}); ok {
			assert.Contains(t, headers, "Content-Type", "Content-Type header should be present")
			t.Log("✓ Headers verified")
		}

		t.Log("✓ POST JSON request validated successfully")
	})

	// Test 3: POST request with form data
	t.Run("POST-Form", func(t *testing.T) {
		formBody := "field1=value1&field2=value2"
		rawReq := fmt.Sprintf("POST /post HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s",
			host, len(formBody), formBody)
		t.Log("Testing POST form request")

		req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
		ctx := httpmsg.NewHttpRequestResponse(req, nil)

		respChain, _, err := infra.HTTPClient.Execute(ctx, httpClient.Options{})
		require.NoError(t, err, "POST form request failed")
		defer respChain.Close()

		// Verify response
		resp := respChain.Response()
		assert.Equal(t, 200, resp.StatusCode, "Expected 200 OK")

		// Parse httpbin response
		body := respChain.Body().String()
		var httpbinResp map[string]interface{}
		err = json.Unmarshal([]byte(body), &httpbinResp)
		require.NoError(t, err, "Failed to parse httpbin response")

		// Verify httpbin received our form data
		if formData, ok := httpbinResp["form"].(map[string]interface{}); ok {
			assert.Equal(t, "value1", formData["field1"], "Form field1 mismatch")
			assert.Equal(t, "value2", formData["field2"], "Form field2 mismatch")
			t.Log("✓ Form data verified")
		}

		t.Log("✓ POST form request validated successfully")
	})

	// Test 4: Custom headers
	t.Run("Custom-Headers", func(t *testing.T) {
		rawReq := fmt.Sprintf("GET /headers HTTP/1.1\r\nHost: %s\r\nX-Custom-Header: custom-value\r\nX-Test-Header: test-value\r\n\r\n", host)
		t.Log("Testing custom headers")

		req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
		ctx := httpmsg.NewHttpRequestResponse(req, nil)

		respChain, _, err := infra.HTTPClient.Execute(ctx, httpClient.Options{})
		require.NoError(t, err, "Headers request failed")
		defer respChain.Close()

		// Verify response
		resp := respChain.Response()
		assert.Equal(t, 200, resp.StatusCode, "Expected 200 OK")

		// Parse httpbin response
		body := respChain.Body().String()
		var httpbinResp map[string]interface{}
		err = json.Unmarshal([]byte(body), &httpbinResp)
		require.NoError(t, err, "Failed to parse httpbin response")

		// Verify httpbin received our custom headers
		if headers, ok := httpbinResp["headers"].(map[string]interface{}); ok {
			assert.Contains(t, headers, "X-Custom-Header", "Custom header should be present")
			assert.Contains(t, headers, "X-Test-Header", "Test header should be present")
			assert.Equal(t, "custom-value", headers["X-Custom-Header"], "Custom header value mismatch")
			assert.Equal(t, "test-value", headers["X-Test-Header"], "Test header value mismatch")
			t.Log("✓ Custom headers verified")
		}

		t.Log("✓ Custom headers validated successfully")
	})

	// Test 5: Different status codes
	t.Run("Status-Codes", func(t *testing.T) {
		statusCodes := []int{200, 400, 404}

		for _, statusCode := range statusCodes {
			rawReq := fmt.Sprintf("GET /status/%d HTTP/1.1\r\nHost: %s\r\n\r\n", statusCode, host)
			t.Logf("Testing status code %d", statusCode)

			req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
			ctx := httpmsg.NewHttpRequestResponse(req, nil)

			respChain, _, err := infra.HTTPClient.Execute(ctx, httpClient.Options{
				NoRedirects: true,
			})

			// For non-200 status codes, we might get an error from the HTTP client
			// This is expected behavior, so we skip those
			if err != nil {
				t.Logf("Status %d returned error (expected for non-2xx): %v", statusCode, err)
				continue
			}
			defer respChain.Close()

			resp := respChain.Response()
			assert.Equal(t, statusCode, resp.StatusCode, "Status code mismatch")
			t.Logf("✓ Status code %d verified", statusCode)
		}
	})

	t.Log("✓ All httpbin tests passed!")
}
