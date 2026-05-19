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

	"github.com/vigolium/vigolium/internal/config"
	httpClient "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TestMutationStrategy_InsertionPointModes verifies that insertion points correctly
// replace parameter values in HTTP requests and that the server receives the
// mutated payloads as expected. This covers the core mutation mechanics that
// the append/replace/prepend modes build upon.
func TestMutationStrategy_InsertionPointModes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

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

	infra, err := SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	baseURL := httpbinApp.BaseURL
	host := strings.TrimPrefix(baseURL, "http://")
	hostPart, portStr, _ := strings.Cut(host, ":")
	port, _ := strconv.Atoi(portStr)
	service := httpmsg.NewServiceSecure(hostPart, port, false)

	// Test 1: URL parameter replacement via insertion point
	t.Run("URLParam_Replace", func(t *testing.T) {
		rawReq := fmt.Sprintf("GET /get?search=original HTTP/1.1\r\nHost: %s\r\n\r\n", host)

		// Create insertion points from the request
		ips, err := httpmsg.CreateAllInsertionPoints([]byte(rawReq), false)
		require.NoError(t, err)
		require.NotEmpty(t, ips, "Expected at least one insertion point")

		// Find the "search" insertion point
		var searchIP httpmsg.InsertionPoint
		for _, ip := range ips {
			if ip.Name() == "search" {
				searchIP = ip
				break
			}
		}
		require.NotNil(t, searchIP, "Expected 'search' insertion point")
		assert.Equal(t, "original", searchIP.BaseValue())

		// Replace mode: completely replace the original value
		payload := "REPLACED_VALUE"
		fuzzedRaw := searchIP.BuildRequest([]byte(payload))
		assert.Contains(t, string(fuzzedRaw), "search=REPLACED_VALUE")
		assert.NotContains(t, string(fuzzedRaw), "original")

		// Send the fuzzed request and verify httpbin received it
		req := httpmsg.NewHttpRequestWithService(service, fuzzedRaw)
		rr := httpmsg.NewHttpRequestResponse(req, nil)
		respChain, _, err := infra.HTTPClient.Execute(rr, httpClient.Options{})
		require.NoError(t, err)
		defer respChain.Close()

		body := respChain.Body().String()
		var httpbinResp map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(body), &httpbinResp))

		args := httpbinResp["args"].(map[string]interface{})
		assert.Equal(t, payload, args["search"], "httpbin should receive replaced value")
		t.Logf("Replace mode verified: search=%s", args["search"])
	})

	// Test 2: Append mode (module manually appends to base value)
	t.Run("URLParam_Append", func(t *testing.T) {
		rawReq := fmt.Sprintf("GET /get?id=42 HTTP/1.1\r\nHost: %s\r\n\r\n", host)

		ips, err := httpmsg.CreateAllInsertionPoints([]byte(rawReq), false)
		require.NoError(t, err)

		var idIP httpmsg.InsertionPoint
		for _, ip := range ips {
			if ip.Name() == "id" {
				idIP = ip
				break
			}
		}
		require.NotNil(t, idIP)

		// Append mode: original value + payload
		payload := idIP.BaseValue() + "' OR 1=1--"
		fuzzedRaw := idIP.BuildRequest([]byte(payload))

		req := httpmsg.NewHttpRequestWithService(service, fuzzedRaw)
		rr := httpmsg.NewHttpRequestResponse(req, nil)
		respChain, _, err := infra.HTTPClient.Execute(rr, httpClient.Options{})
		require.NoError(t, err)
		defer respChain.Close()

		body := respChain.Body().String()
		var httpbinResp map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(body), &httpbinResp))

		args := httpbinResp["args"].(map[string]interface{})
		receivedVal := args["id"].(string)
		assert.True(t, strings.HasPrefix(receivedVal, "42"), "Append: value should start with original")
		assert.Contains(t, receivedVal, "OR 1=1", "Append: value should contain payload")
		t.Logf("Append mode verified: id=%s", receivedVal)
	})

	// Test 3: Prepend mode (payload + original value)
	t.Run("URLParam_Prepend", func(t *testing.T) {
		rawReq := fmt.Sprintf("GET /get?name=alice HTTP/1.1\r\nHost: %s\r\n\r\n", host)

		ips, err := httpmsg.CreateAllInsertionPoints([]byte(rawReq), false)
		require.NoError(t, err)

		var nameIP httpmsg.InsertionPoint
		for _, ip := range ips {
			if ip.Name() == "name" {
				nameIP = ip
				break
			}
		}
		require.NotNil(t, nameIP)

		// Prepend mode: payload + original value
		payload := "<script>" + nameIP.BaseValue()
		fuzzedRaw := nameIP.BuildRequest([]byte(payload))

		req := httpmsg.NewHttpRequestWithService(service, fuzzedRaw)
		rr := httpmsg.NewHttpRequestResponse(req, nil)
		respChain, _, err := infra.HTTPClient.Execute(rr, httpClient.Options{})
		require.NoError(t, err)
		defer respChain.Close()

		body := respChain.Body().String()
		var httpbinResp map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(body), &httpbinResp))

		args := httpbinResp["args"].(map[string]interface{})
		receivedVal := args["name"].(string)
		assert.True(t, strings.HasSuffix(receivedVal, "alice"), "Prepend: value should end with original")
		assert.True(t, strings.HasPrefix(receivedVal, "<script>"), "Prepend: value should start with payload")
		t.Logf("Prepend mode verified: name=%s", receivedVal)
	})

	// Test 4: Body parameter mutation
	t.Run("BodyParam_Replace", func(t *testing.T) {
		formBody := "username=admin&password=secret"
		rawReq := fmt.Sprintf("POST /post HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s",
			host, len(formBody), formBody)

		ips, err := httpmsg.CreateAllInsertionPoints([]byte(rawReq), false)
		require.NoError(t, err)
		require.NotEmpty(t, ips, "Expected insertion points for form body")

		var pwIP httpmsg.InsertionPoint
		for _, ip := range ips {
			if ip.Name() == "password" {
				pwIP = ip
				break
			}
		}
		require.NotNil(t, pwIP, "Expected 'password' insertion point")
		assert.Equal(t, "secret", pwIP.BaseValue())

		// Replace password with payload
		fuzzedRaw := pwIP.BuildRequest([]byte("' OR '1'='1"))

		req := httpmsg.NewHttpRequestWithService(service, fuzzedRaw)
		rr := httpmsg.NewHttpRequestResponse(req, nil)
		respChain, _, err := infra.HTTPClient.Execute(rr, httpClient.Options{})
		require.NoError(t, err)
		defer respChain.Close()

		body := respChain.Body().String()
		var httpbinResp map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(body), &httpbinResp))

		formData := httpbinResp["form"].(map[string]interface{})
		assert.Equal(t, "admin", formData["username"], "Username should remain unchanged")
		assert.Contains(t, formData["password"], "OR", "Password should be replaced with payload")
		t.Logf("Body param replace verified: password=%s", formData["password"])
	})

	// Test 5: JSON body mutation
	t.Run("JSONParam_Replace", func(t *testing.T) {
		jsonBody := `{"user":"admin","token":"abc123"}`
		rawReq := fmt.Sprintf("POST /post HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
			host, len(jsonBody), jsonBody)

		ips, err := httpmsg.CreateAllInsertionPoints([]byte(rawReq), false)
		require.NoError(t, err)

		var tokenIP httpmsg.InsertionPoint
		for _, ip := range ips {
			if ip.Name() == "token" {
				tokenIP = ip
				break
			}
		}
		require.NotNil(t, tokenIP, "Expected 'token' insertion point")

		fuzzedRaw := tokenIP.BuildRequest([]byte("INJECTED"))

		req := httpmsg.NewHttpRequestWithService(service, fuzzedRaw)
		rr := httpmsg.NewHttpRequestResponse(req, nil)
		respChain, _, err := infra.HTTPClient.Execute(rr, httpClient.Options{})
		require.NoError(t, err)
		defer respChain.Close()

		body := respChain.Body().String()
		var httpbinResp map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(body), &httpbinResp))

		jsonData := httpbinResp["json"].(map[string]interface{})
		assert.Equal(t, "admin", jsonData["user"], "User should remain unchanged")
		assert.Equal(t, "INJECTED", jsonData["token"], "Token should be replaced with payload")
		t.Logf("JSON param replace verified: token=%s", jsonData["token"])
	})

	// Test 6: Multiple insertion points on same request
	t.Run("MultipleParams_IndependentMutation", func(t *testing.T) {
		rawReq := fmt.Sprintf("GET /get?a=1&b=2&c=3 HTTP/1.1\r\nHost: %s\r\n\r\n", host)

		allIPs, err := httpmsg.CreateAllInsertionPoints([]byte(rawReq), false)
		require.NoError(t, err)

		// Filter to URL query params only — CreateAllInsertionPoints also
		// produces header insertion points (e.g., True-Client-IP, X-Real-IP)
		// which are not relevant for this URL parameter mutation test.
		var ips []httpmsg.InsertionPoint
		for _, ip := range allIPs {
			if ip.Type() == httpmsg.INS_PARAM_URL {
				ips = append(ips, ip)
			}
		}
		require.GreaterOrEqual(t, len(ips), 3, "Expected at least 3 URL param insertion points")

		// Mutate each param independently and verify others stay intact
		for _, ip := range ips {
			payload := "FUZZ_" + ip.Name()
			fuzzedRaw := ip.BuildRequest([]byte(payload))

			req := httpmsg.NewHttpRequestWithService(service, fuzzedRaw)
			rr := httpmsg.NewHttpRequestResponse(req, nil)
			respChain, _, err := infra.HTTPClient.Execute(rr, httpClient.Options{})
			require.NoError(t, err)
			defer respChain.Close()

			body := respChain.Body().String()
			var httpbinResp map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(body), &httpbinResp))

			args := httpbinResp["args"].(map[string]interface{})
			assert.Equal(t, payload, args[ip.Name()],
				"Mutated param %s should contain payload", ip.Name())

			// Other params should keep their original values
			for _, otherIP := range ips {
				if otherIP.Name() != ip.Name() {
					assert.Equal(t, otherIP.BaseValue(), args[otherIP.Name()],
						"Non-mutated param %s should keep original value", otherIP.Name())
				}
			}
		}
		t.Log("Independent mutation verified for all params")
	})
}

// TestMutationStrategy_ConfigLoading verifies the MutationStrategyConfig loads
// correctly with single and multiple default modes.
func TestMutationStrategy_ConfigLoading(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	t.Run("DefaultConfig", func(t *testing.T) {
		settings := config.DefaultSettings()
		assert.Equal(t, []string{"append"}, settings.MutationStrategy.DefaultModes)
		assert.NotEmpty(t, settings.MutationStrategy.FieldTypeDefaults.String)
		assert.NotEmpty(t, settings.MutationStrategy.FieldTypeDefaults.Email)
		assert.NotEmpty(t, settings.MutationStrategy.FieldTypeDefaults.Integer)
	})

	t.Run("MultipleModesConfig", func(t *testing.T) {
		// Verify the struct accepts multiple modes
		cfg := config.MutationStrategyConfig{
			DefaultModes: []string{"append", "replace", "prepend"},
		}
		assert.Len(t, cfg.DefaultModes, 3)
		assert.Contains(t, cfg.DefaultModes, "append")
		assert.Contains(t, cfg.DefaultModes, "replace")
		assert.Contains(t, cfg.DefaultModes, "prepend")
	})

	t.Run("FieldTypeDefaultsToMap", func(t *testing.T) {
		settings := config.DefaultSettings()
		m := settings.MutationStrategy.FieldTypeDefaults.ToMap()
		assert.NotEmpty(t, m["string"])
		assert.NotEmpty(t, m["email"])
		assert.NotEmpty(t, m["integer"])
		assert.NotEmpty(t, m["uuid"])
		assert.Contains(t, m["boolean"], "true")
	})
}
