package mcp_dos_amplification

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// batchLen returns the element count when body is a JSON-RPC array (batch), or
// -1 when it is not an array (a single request).
func batchLen(body []byte) int {
	var arr []json.RawMessage
	if json.Unmarshal(body, &arr) != nil {
		return -1
	}
	return len(arr)
}

// writeResultArray writes a JSON-RPC array of n successful (empty-result)
// responses — as a server that fully processes a batch would.
func writeResultArray(w http.ResponseWriter, n int) {
	w.Header().Set("Content-Type", "application/json")
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"jsonrpc":"2.0","id":%d,"result":{}}`, i+1)
	}
	b.WriteByte(']')
	_, _ = io.WriteString(w, b.String())
}

// vulnHandler emulates a server with no batch-size cap or rate limiting: it
// fully processes ANY batch it receives, echoing back one result per element.
func vulnHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if n := batchLen(raw); n >= 0 {
			writeResultArray(w, n)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}
}

// cappedHandler emulates a hardened server: it honours small batches but caps
// how many entries of an oversized batch it will process.
func cappedHandler(cap int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if n := batchLen(raw); n >= 0 {
			if n > cap {
				n = cap
			}
			writeResultArray(w, n)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}
}

// noBatchHandler emulates a server that rejects batching entirely, returning a
// single JSON-RPC invalid-request error for any array.
func noBatchHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if batchLen(raw) >= 0 {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"batch not supported"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}
}

// TestScanPerHost_DetectsUnboundedBatch flags a server that fully processes the
// oversized 200-ping batch with no size/rate limit.
func TestScanPerHost_DetectsUnboundedBatch(t *testing.T) {
	srv := httptest.NewServer(vulnHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a server that processes an unbounded oversized batch must be flagged")
	assert.Equal(t, "MCP Large JSON-RPC Batch Processing Candidate", res[0].Info.Name)
	assert.Equal(t, severity.Medium, res[0].Info.Severity)
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeDifferential, res[0].EvidenceGrade)
	assert.Equal(t, false, res[0].Metadata["service_degradation_observed"])
}

// TestScanPerHost_CappedServerNoFinding ensures a server that caps the oversized
// batch (processing far fewer than requested) is not flagged.
func TestScanPerHost_CappedServerNoFinding(t *testing.T) {
	srv := httptest.NewServer(cappedHandler(10))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that caps oversized batches must not be flagged")
}

// TestScanPerHost_NoBatchingNoFinding ensures a server that rejects batching
// entirely (single -32600 error) is not flagged.
func TestScanPerHost_NoBatchingNoFinding(t *testing.T) {
	srv := httptest.NewServer(noBatchHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a batch-rejecting server has nothing to amplify")
}

// TestCanProcess_RequiresResponse verifies the detection gate needs a captured
// response.
func TestCanProcess_RequiresResponse(t *testing.T) {
	rr := modtest.Request(t, "http://example.com/mcp")
	assert.False(t, New().CanProcess(rr), "no response => not processable")
	assert.False(t, New().CanProcess(nil))
}
