package mcp_batch_abuse

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// isBatch reports whether the JSON-RPC body is an array (a batch request).
func isBatch(body []byte) bool {
	var arr []json.RawMessage
	return json.Unmarshal(body, &arr) == nil
}

// vulnBatchHandler emulates a server that happily processes a batched array of
// initialize + tools/list without enforcing a per-request session gate.
func vulnBatchHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isBatch(raw) {
			// initialize result + tools/list result, both successful.
			_, _ = io.WriteString(w, `[`+
				`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}},`+
				`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo"}]}}`+
				`]`)
			return
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}
}

// strictBatchHandler emulates a safe server that rejects batched arrays with
// the JSON-RPC invalid-request error.
func strictBatchHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isBatch(raw) {
			_, _ = io.WriteString(w, `[{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"batch not allowed"}}]`)
			return
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}
}

// TestScanPerHost_DetectsBatchBypass flags a server that processes a smuggled
// tools/list inside an initialize batch without a session.
func TestScanPerHost_DetectsBatchBypass(t *testing.T) {
	srv := httptest.NewServer(vulnBatchHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "batched tools/list returning a result must be flagged")
	assert.Equal(t, "MCP JSON-RPC Batch Auth Bypass", res[0].Info.Name)
}

// TestScanPerHost_StrictServerNoFinding ensures a server that rejects batches
// produces no finding.
func TestScanPerHost_StrictServerNoFinding(t *testing.T) {
	srv := httptest.NewServer(strictBatchHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a batch-rejecting server must not be flagged")
}

// TestCanProcess_RequiresResponse verifies the detection gate needs a captured
// response.
func TestCanProcess_RequiresResponse(t *testing.T) {
	rr := modtest.Request(t, "http://example.com/mcp")
	assert.False(t, New().CanProcess(rr), "no response => not processable")
	assert.False(t, New().CanProcess(nil))
}
