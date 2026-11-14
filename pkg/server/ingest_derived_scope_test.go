package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
)

// SAFE-4 (REST): a HAR naming several hosts is scoped to its primary host;
// the third-party records are stored as context, which scan-on-receive never
// scans.
func TestIngestHTTP_DerivesScopeFromCapture(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{DisableFetchResponse: true}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/ingest-http", h.HandleIngestHTTP)

	var entries []string
	for i := 0; i < 3; i++ {
		entries = append(entries, fmt.Sprintf(`{"request":{"method":"GET","url":"https://app.test/p%d","headers":[]},"response":{"status":200,"headers":[],"content":{"text":"x"}}}`, i))
	}
	for i := 0; i < 2; i++ {
		entries = append(entries, fmt.Sprintf(`{"request":{"method":"GET","url":"https://cdn.other/s%d.js","headers":[]},"response":{"status":200,"headers":[],"content":{"text":"x"}}}`, i))
	}
	har := `{"log":{"version":"1.2","entries":[` + strings.Join(entries, ",") + `]}}`
	raw, err := json.Marshal(map[string]any{"input_mode": "har", "content": har})
	require.NoError(t, err)
	status, out := doReq(t, app, http.MethodPost, "/api/ingest-http", string(raw), nil)
	require.Equal(t, http.StatusOK, status, string(out))
	var resp IngestHTTPResponse
	require.NoError(t, json.Unmarshal(out, &resp))
	require.Equal(t, "app.test", resp.DerivedScope)
	require.Equal(t, 2, resp.ContextOnly)

	var rows []struct {
		Hostname string `bun:"hostname"`
		Source   string `bun:"source"`
	}
	require.NoError(t, db.NewSelect().TableExpr("http_records").Column("hostname", "source").Scan(context.Background(), &rows))
	for _, r := range rows {
		want := database.RecordSourceIngestServer
		if r.Hostname == "cdn.other" {
			want = database.RecordSourceIngestContext
		}
		if r.Source != want {
			t.Errorf("%s stored with source %q, want %q", r.Hostname, r.Source, want)
		}
	}
	require.Len(t, rows, 5)
}
