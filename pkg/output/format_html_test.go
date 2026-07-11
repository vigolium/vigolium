package output

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// httpRecordEnvelope marshals an http_record envelope the way queryExportData
// emits one (a []byte body field is base64-encoded, matching
// HTTPRecord.MarshalJSON).
func httpRecordEnvelope(t *testing.T, data map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": "http_record", "data": data})
	require.NoError(t, err)
	return b
}

// decodeEnvelopeData unwraps the trimmed envelope back to its data map.
func decodeEnvelopeData(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var env map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &env))
	var data map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(env["data"], &data))
	return data
}

func decodeBodyField(t *testing.T, data map[string]json.RawMessage, key string) []byte {
	t.Helper()
	var body []byte
	require.NoError(t, json.Unmarshal(data[key], &body))
	return body
}

func TestTrimReportItemDropsRawDuplicates(t *testing.T) {
	budget := int64(htmlReportBodyBudgetBytes)
	raw := httpRecordEnvelope(t, map[string]any{
		"url":                   "https://x/a",
		"status_code":           200,
		"response_content_type": "text/html",
		"raw_request":           []byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"),
		"raw_response":          []byte("HTTP/1.1 200 OK\r\n\r\n<html>hi</html>"),
		"response_body":         []byte("<html>hi</html>"),
	})

	data := decodeEnvelopeData(t, trimReportItemJSON(raw, &budget, &reportTrimStats{}))

	_, hasRawReq := data["raw_request"]
	_, hasRawResp := data["raw_response"]
	assert.False(t, hasRawReq, "raw_request should be dropped")
	assert.False(t, hasRawResp, "raw_response should be dropped")
	// Small textual body is kept verbatim with no trim flag.
	assert.Equal(t, "<html>hi</html>", string(decodeBodyField(t, data, "response_body")))
	_, trimmedFlag := data["response_body_trimmed"]
	assert.False(t, trimmedFlag)
}

func TestTrimReportItemBinaryBodyLabeled(t *testing.T) {
	budget := int64(htmlReportBodyBudgetBytes)
	raw := httpRecordEnvelope(t, map[string]any{
		"response_content_type": "application/pdf",
		"response_body":         append([]byte("%PDF-1.7\x00\x01"), []byte("binarymarker")...),
	})

	data := decodeEnvelopeData(t, trimReportItemJSON(raw, &budget, &reportTrimStats{}))

	assert.Empty(t, decodeBodyField(t, data, "response_body"), "binary body should be dropped")
	var trimmed bool
	require.NoError(t, json.Unmarshal(data["response_body_trimmed"], &trimmed))
	assert.True(t, trimmed)
	var note string
	require.NoError(t, json.Unmarshal(data["response_body_note"], &note))
	assert.Contains(t, note, "binary")
	assert.Contains(t, note, "pdf")
	assert.Contains(t, note, "JSONL")
}

func TestTrimReportItemSniffsBinaryWithoutContentType(t *testing.T) {
	budget := int64(htmlReportBodyBudgetBytes)
	raw := httpRecordEnvelope(t, map[string]any{
		"response_body": []byte{0x89, 0x50, 0x4e, 0x47, 0x00, 0x01, 0x02, 0x03}, // PNG-ish, NUL byte
	})

	data := decodeEnvelopeData(t, trimReportItemJSON(raw, &budget, &reportTrimStats{}))
	assert.Empty(t, decodeBodyField(t, data, "response_body"))
	var trimmed bool
	require.NoError(t, json.Unmarshal(data["response_body_trimmed"], &trimmed))
	assert.True(t, trimmed)
}

func TestTrimReportItemTruncatesLargeText(t *testing.T) {
	budget := int64(htmlReportBodyBudgetBytes)
	big := strings.Repeat("A", 100*1024)
	raw := httpRecordEnvelope(t, map[string]any{
		"response_content_type": "text/html",
		"response_body":         []byte(big),
	})

	data := decodeEnvelopeData(t, trimReportItemJSON(raw, &budget, &reportTrimStats{}))
	assert.Len(t, decodeBodyField(t, data, "response_body"), htmlReportMaxBodyBytes)
	var note string
	require.NoError(t, json.Unmarshal(data["response_body_note"], &note))
	assert.Contains(t, note, "truncated")
}

func TestTrimReportItemBudgetExhaustion(t *testing.T) {
	budget := int64(8) // smaller than the body below
	raw := httpRecordEnvelope(t, map[string]any{
		"response_content_type": "text/plain",
		"response_body":         []byte("this body is well over eight bytes"),
	})

	data := decodeEnvelopeData(t, trimReportItemJSON(raw, &budget, &reportTrimStats{}))
	assert.Empty(t, decodeBodyField(t, data, "response_body"))
	var note string
	require.NoError(t, json.Unmarshal(data["response_body_note"], &note))
	assert.Contains(t, note, "manageable")
}

func TestTrimReportItemNonHTTPRecordUnchanged(t *testing.T) {
	budget := int64(htmlReportBodyBudgetBytes)
	raw, err := json.Marshal(map[string]any{
		"type": "finding",
		"data": map[string]any{"id": 1, "severity": "high", "description": "keep me whole"},
	})
	require.NoError(t, err)

	out := trimReportItemJSON(raw, &budget, &reportTrimStats{})
	assert.JSONEq(t, string(raw), string(out))
}

// TestTrimReportItemFindingBudgeted is the Claim-D regression: a finding's inline
// response and additional-evidence text are capped against the shared body budget
// (previously they bypassed it entirely), while a small inline request is kept.
func TestTrimReportItemFindingBudgeted(t *testing.T) {
	budget := int64(htmlReportBodyBudgetBytes)
	big := strings.Repeat("A", 100*1024)
	raw, err := json.Marshal(map[string]any{
		"type": "finding",
		"data": map[string]any{
			"id":                  1,
			"severity":            "high",
			"request":             "GET /a HTTP/1.1\r\nHost: x\r\n\r\n",
			"response":            "HTTP/1.1 200 OK\r\n\r\n" + big,
			"additional_evidence": []string{"# [baseline]\n" + big},
		},
	})
	require.NoError(t, err)

	before := budget
	data := decodeEnvelopeData(t, trimReportItemJSON(raw, &budget, &reportTrimStats{}))

	var resp string
	require.NoError(t, json.Unmarshal(data["response"], &resp))
	assert.True(t, strings.HasPrefix(resp, "HTTP/1.1 200 OK"), "kept the head of the response")
	assert.Contains(t, resp, "truncated", "oversized finding response must be truncated with a marker")
	assert.Less(t, budget, before, "finding response must consume the shared body budget")

	// Small inline request fits and is preserved verbatim.
	var req string
	require.NoError(t, json.Unmarshal(data["request"], &req))
	assert.Equal(t, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n", req)

	var ev []string
	require.NoError(t, json.Unmarshal(data["additional_evidence"], &ev))
	assert.Contains(t, ev[0], "truncated", "oversized evidence entry must be truncated")
}

func TestTrimReportItemStatsAccounting(t *testing.T) {
	budget := int64(htmlReportBodyBudgetBytes)
	stats := &reportTrimStats{}

	// Binary body → dropped.
	trimReportItemJSON(httpRecordEnvelope(t, map[string]any{
		"response_content_type": "application/pdf",
		"response_body":         append([]byte("%PDF\x00"), make([]byte, 100)...),
	}), &budget, stats)
	// Large text body → truncated.
	trimReportItemJSON(httpRecordEnvelope(t, map[string]any{
		"response_content_type": "text/html",
		"response_body":         []byte(strings.Repeat("A", 100*1024)),
	}), &budget, stats)

	assert.Equal(t, 1, stats.bodiesDropped)
	assert.Equal(t, 1, stats.bodiesTruncated)
	assert.Greater(t, stats.bytesOmitted, int64(0))
}

// TestGenerateHTMLReportTrimsBinaryBodies exercises the full generator: a
// multi-byte binary body must not survive into the rendered HTML (neither as
// raw bytes nor as its base64 encoding).
func TestGenerateHTMLReportTrimsBinaryBodies(t *testing.T) {
	bodyBytes := append([]byte("%PDF\x00"), []byte("SHOULD_NOT_APPEAR_IN_REPORT")...)
	items := []any{
		map[string]any{"type": "http_record", "data": map[string]any{
			"uuid":                  "u1",
			"url":                   "https://x/a.pdf",
			"status_code":           200,
			"response_content_type": "application/pdf",
			"response_body":         bodyBytes,
			"raw_response":          append([]byte("HTTP/1.1 200 OK\r\n\r\n"), bodyBytes...),
		}},
	}

	out := filepath.Join(t.TempDir(), "report.html")
	require.NoError(t, GenerateHTMLReport(items, out, HTMLReportMeta{}))

	content, err := os.ReadFile(out)
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(bodyBytes)
	assert.NotContains(t, string(content), encoded, "binary body base64 must be trimmed out")
	assert.NotContains(t, string(content), "SHOULD_NOT_APPEAR_IN_REPORT")
}

// TestGenerateHTMLReportLogsTrim confirms the operator-facing note fires when
// bodies are trimmed (no silent caps).
func TestGenerateHTMLReportLogsTrim(t *testing.T) {
	items := []any{
		map[string]any{"type": "http_record", "data": map[string]any{
			"uuid":                  "u1",
			"response_content_type": "application/pdf",
			"response_body":         append([]byte("%PDF\x00"), make([]byte, 4096)...),
		}},
	}

	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	err := GenerateHTMLReport(items, filepath.Join(t.TempDir(), "report.html"), HTMLReportMeta{})
	_ = w.Close()
	os.Stderr = old
	captured, _ := io.ReadAll(r)

	require.NoError(t, err)
	assert.Contains(t, string(captured), "HTML report trimmed", "operator note must be emitted when bodies are trimmed")
}

// TestGenerateHTMLReportSetsDataExpectedSentinel verifies the generator wires up
// the data-expected sentinel so the viewer can distinguish a failed-to-load
// report from the standalone demo template.
func TestGenerateHTMLReportSetsDataExpectedSentinel(t *testing.T) {
	items := []any{
		map[string]any{"type": "finding", "data": map[string]any{"id": 1, "severity": "high"}},
	}
	out := filepath.Join(t.TempDir(), "report.html")
	require.NoError(t, GenerateHTMLReport(items, out, HTMLReportMeta{}))

	content, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.NotContains(t, string(content), "{{.DataExpected}}", "placeholder must be substituted")
	assert.Contains(t, string(content), `"true" === "true"`, "sentinel must resolve to true")
}
