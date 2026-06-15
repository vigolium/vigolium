package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
)

// seedRecordWithBodies inserts one http_record carrying raw request/response
// bytes, so the omit-response and report-trim behavior can be asserted.
func seedRecordWithBodies(t *testing.T, db *database.DB, suffix string) {
	t.Helper()
	ctx := context.Background()
	_, err := db.NewInsert().Model(&database.HTTPRecord{
		UUID:                "rec-" + suffix,
		Scheme:              "http",
		Hostname:            suffix + ".example",
		Port:                80,
		Method:              "GET",
		Path:                "/" + suffix,
		URL:                 "http://" + suffix + ".example/" + suffix,
		HTTPVersion:         "HTTP/1.1",
		RequestHash:         "rhash-" + suffix,
		StatusCode:          200,
		ResponseContentType: "text/html",
		RawRequest:          []byte("GET /" + suffix + " HTTP/1.1\r\nHost: " + suffix + ".example\r\n\r\n"),
		RawResponse:         []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>RAWBODYMARKER-" + suffix + "</html>"),
	}).Exec(ctx)
	require.NoError(t, err)
}

// streamJSONLExport must keep the raw request/response bytes when omitResponse is
// false (full JSONL fidelity) and drop them — while keeping the metadata — when
// omitResponse is true (the report path).
func TestStreamJSONLExportOmitResponse(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	seedRecordWithBodies(t, db, "alpha")

	t.Run("full fidelity keeps raw bytes", func(t *testing.T) {
		var buf bytes.Buffer
		n, err := streamJSONLExport(ctx, db, &buf, false, "")
		require.NoError(t, err)
		require.Positive(t, n)
		out := buf.String()
		assert.Contains(t, out, "\"raw_request\"")
		assert.Contains(t, out, "\"raw_response\"")
		// The record metadata is always present.
		assert.Contains(t, out, "http://alpha.example/alpha")
	})

	t.Run("omit-response drops raw bytes but keeps metadata", func(t *testing.T) {
		var buf bytes.Buffer
		n, err := streamJSONLExport(ctx, db, &buf, true, "")
		require.NoError(t, err)
		require.Positive(t, n)
		out := buf.String()
		assert.NotContains(t, out, "\"raw_request\"")
		assert.NotContains(t, out, "\"raw_response\"")
		assert.NotContains(t, out, "RAWBODYMARKER")
		assert.Contains(t, out, "http://alpha.example/alpha")
	})
}

// The streaming HTML generator must produce a byte-identical report to the
// legacy materialized generator over the same data (fixed GeneratedAt removes
// the only nondeterministic field), and must never embed the raw_request/
// raw_response bytes — which the report viewer discards.
func TestGenerateHTMLReportStreamingParity(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	seedRecordWithBodies(t, db, "alpha")
	seedRecordWithBodies(t, db, "bravo")
	seedFindingAndRecord(t, db, "", "charlie")

	meta := output.HTMLReportMeta{
		Title:       "Parity Report",
		Version:     "test",
		GeneratedAt: "2026-06-15T00:00:00.000Z", // fixed → deterministic output
	}

	for _, omit := range []bool{false, true} {
		omit := omit
		name := "keep-raw"
		if omit {
			name = "omit-raw"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()

			legacyItems, err := queryExportData(ctx, db, omit, "")
			require.NoError(t, err)
			legacyPath := filepath.Join(dir, "legacy.html")
			require.NoError(t, output.GenerateHTMLReport(legacyItems, legacyPath, meta))

			streamPath := filepath.Join(dir, "stream.html")
			produce := func(emit func(any) error) error {
				return streamExportData(ctx, db, omit, "", emit)
			}
			require.NoError(t, output.GenerateHTMLReportStreaming(produce, streamPath, meta))

			legacy, err := os.ReadFile(legacyPath)
			require.NoError(t, err)
			stream, err := os.ReadFile(streamPath)
			require.NoError(t, err)

			assert.Equal(t, string(legacy), string(stream),
				"streaming HTML report must be byte-identical to the legacy materialized report")
			// The report viewer renders from parsed fields, not the raw copies,
			// so the actual raw body bytes must never be embedded in the HTML
			// (the field-name identifiers themselves appear in the viewer JS, so
			// we assert on the body content, not the keys).
			assert.NotContains(t, string(stream), "RAWBODYMARKER")
		})
	}
}

// GenerateHTMLReportStreaming stages to a temp file and renames on success, so a
// successful run leaves exactly the report at the destination and no leftover
// temp siblings in the directory.
func TestGenerateHTMLReportStreamingAtomic(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	seedRecordWithBodies(t, db, "alpha")

	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.html")
	produce := func(emit func(any) error) error {
		return streamExportData(ctx, db, true, "", emit)
	}
	require.NoError(t, output.GenerateHTMLReportStreaming(produce, outPath, output.HTMLReportMeta{
		GeneratedAt: "2026-06-15T00:00:00.000Z",
	}))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.Equal(t, []string{"report.html"}, names,
		"only the final report should remain (no leftover temp file): got %v", names)
	for _, n := range names {
		assert.False(t, strings.HasSuffix(n, ".tmp"), "temp file leaked: %s", n)
	}
}
