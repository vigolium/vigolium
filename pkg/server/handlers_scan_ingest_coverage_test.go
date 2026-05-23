package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
)

// -----------------------------------------------------------------------------
// validateScanAllRecordsRequest (pure)
// -----------------------------------------------------------------------------

func TestValidateScanAllRecordsRequest(t *testing.T) {
	cases := []struct {
		name    string
		req     ScanAllRecordsRequest
		wantErr bool
	}{
		{"empty ok", ScanAllRecordsRequest{}, false},
		{"valid durations + heuristics", ScanAllRecordsRequest{Timeout: "5s", ScanningMaxDuration: "1m", HeuristicsCheck: "basic"}, false},
		{"bad timeout", ScanAllRecordsRequest{Timeout: "notaduration"}, true},
		{"bad max duration", ScanAllRecordsRequest{ScanningMaxDuration: "xyz"}, true},
		{"bad heuristics", ScanAllRecordsRequest{HeuristicsCheck: "extreme"}, true},
		{"negative concurrency", ScanAllRecordsRequest{Concurrency: -1}, true},
		{"negative max per host", ScanAllRecordsRequest{MaxPerHost: -3}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateScanAllRecordsRequest(tc.req)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// HandleScanRecords — validation / early-return paths (no live runner)
// -----------------------------------------------------------------------------

func TestHandleScanRecords_ValidationPaths(t *testing.T) {
	t.Run("db unavailable → 503", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app := fiber.New()
		app.Post("/api/scan-records", h.HandleScanRecords)
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-records", `{"record_uuids":["x"]}`, nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})

	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/scan-records", h.HandleScanRecords)

	t.Run("malformed body → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-records", `{not json`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("empty record_uuids → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-records", `{"record_uuids":[]}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("no valid records → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-records", `{"record_uuids":["nonexistent-uuid"]}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})
}

// -----------------------------------------------------------------------------
// HandleScanAllRecords — validation + dry-run (no live runner)
// -----------------------------------------------------------------------------

func TestHandleScanAllRecords_ValidationAndDryRun(t *testing.T) {
	t.Run("db unavailable → 503", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app := fiber.New()
		app.Post("/api/scan-all-records", h.HandleScanAllRecords)
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-all-records", "", nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})

	db, repo := newPinnedTestDB(t)
	insertRecord(t, db, database.DefaultProjectUUID)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/scan-all-records", h.HandleScanAllRecords)

	t.Run("malformed body → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-all-records", `{not json`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("validation error → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-all-records", `{"timeout":"notaduration"}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("no matching records → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-all-records", `{"hostname":"no-such-host.invalid"}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("dry run returns scan record", func(t *testing.T) {
		status, body := doReq(t, app, http.MethodPost, "/api/scan-all-records", `{"dry_run":true}`, nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var resp ScanResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, body)
		}
		if resp.Status != "dry_run" {
			t.Errorf("status = %q, want dry_run", resp.Status)
		}
		if resp.RecordsToScan != 1 {
			t.Errorf("records_to_scan = %d, want 1", resp.RecordsToScan)
		}
	})
}

// -----------------------------------------------------------------------------
// HandleUpdateScan / HandleUpdateAgenticScan
// -----------------------------------------------------------------------------

func TestHandleUpdateScan(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	scanUUID := insertScan(t, db, repo, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/scans/:uuid/update", h.HandleUpdateScan)

	t.Run("update name", func(t *testing.T) {
		status, body := doReq(t, app, http.MethodPost, "/api/scans/"+scanUUID+"/update", `{"name":"renamed"}`, nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var s database.Scan
		_ = json.Unmarshal(body, &s)
		if s.Name != "renamed" {
			t.Errorf("name = %q, want renamed", s.Name)
		}
	})

	t.Run("malformed body → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scans/"+scanUUID+"/update", `{bad`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("missing scan → 404", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scans/no-such/update", `{"name":"x"}`, nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("cross-project → 404", func(t *testing.T) {
		// The scan belongs to the default project; request a different project
		// via the X-Project-UUID header path. Wire the project middleware so the
		// header is honoured.
		app2 := fiber.New()
		app2.Use(ProjectUUIDMiddleware(nil))
		app2.Post("/api/scans/:uuid/update", h.HandleUpdateScan)
		if status, _ := doReq(t, app2, http.MethodPost, "/api/scans/"+scanUUID+"/update", `{"name":"x"}`,
			map[string]string{"X-Project-UUID": "some-other-project"}); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("db unavailable → 503", func(t *testing.T) {
		hn := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app3 := fiber.New()
		app3.Post("/api/scans/:uuid/update", hn.HandleUpdateScan)
		if status, _ := doReq(t, app3, http.MethodPost, "/api/scans/x/update", `{}`, nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})
}

func TestHandleUpdateAgenticScan(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	uuid := insertAgenticScan(t, repo, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/agent/scans/:uuid/update", h.HandleUpdateAgenticScan)

	t.Run("update status field", func(t *testing.T) {
		status, body := doReq(t, app, http.MethodPost, "/api/agent/scans/"+uuid+"/update", `{"status":"cancelled"}`, nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var a database.AgenticScan
		_ = json.Unmarshal(body, &a)
		if a.Status != "cancelled" {
			t.Errorf("status = %q, want cancelled", a.Status)
		}
	})

	t.Run("missing → 404", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/agent/scans/no-such/update", `{}`, nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("malformed body → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/agent/scans/"+uuid+"/update", `{bad`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("db unavailable → 503", func(t *testing.T) {
		hn := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app2 := fiber.New()
		app2.Post("/api/agent/scans/:uuid/update", hn.HandleUpdateAgenticScan)
		if status, _ := doReq(t, app2, http.MethodPost, "/api/agent/scans/x/update", `{}`, nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})
}

// -----------------------------------------------------------------------------
// Ingest: HandleIngestHTTP routing + validation, resolveContent, scope helper
// -----------------------------------------------------------------------------

func TestResolveContent(t *testing.T) {
	t.Run("raw content preferred", func(t *testing.T) {
		got, err := resolveContent(&IngestHTTPRequest{Content: "plain"})
		if err != nil || got != "plain" {
			t.Errorf("got (%q,%v), want (plain,nil)", got, err)
		}
	})
	t.Run("base64 decoded", func(t *testing.T) {
		enc := base64.StdEncoding.EncodeToString([]byte("decoded"))
		got, err := resolveContent(&IngestHTTPRequest{ContentBase64: enc})
		if err != nil || got != "decoded" {
			t.Errorf("got (%q,%v), want (decoded,nil)", got, err)
		}
	})
	t.Run("invalid base64 → error", func(t *testing.T) {
		if _, err := resolveContent(&IngestHTTPRequest{ContentBase64: "!!!not-base64!!!"}); err == nil {
			t.Errorf("expected error for invalid base64")
		}
	})
	t.Run("missing content → error", func(t *testing.T) {
		if _, err := resolveContent(&IngestHTTPRequest{}); err == nil {
			t.Errorf("expected ErrMissingContent")
		}
	})
}

func TestHandleIngestHTTP_Validation(t *testing.T) {
	t.Run("repo unavailable → 503", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app := fiber.New()
		app.Post("/api/ingest-http", h.HandleIngestHTTP)
		if status, _ := doReq(t, app, http.MethodPost, "/api/ingest-http", `{"input_mode":"curl"}`, nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})

	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/ingest-http", h.HandleIngestHTTP)

	t.Run("malformed body → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/ingest-http", `{not json`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("missing mode → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/ingest-http", `{}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("invalid mode → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/ingest-http", `{"input_mode":"nonsense"}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("burp_base64 missing request → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/ingest-http", `{"input_mode":"burp_base64"}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("burp_base64 invalid base64 → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/ingest-http", `{"input_mode":"burp_base64","http_request_base64":"!!!"}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("curl missing content → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/ingest-http", `{"input_mode":"curl"}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("burp_base64 valid request+response ingested", func(t *testing.T) {
		rawReq := "GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n"
		rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nhi"
		body := `{"input_mode":"burp_base64","url":"https://example.test/index.html","http_request_base64":"` +
			base64.StdEncoding.EncodeToString([]byte(rawReq)) + `","http_response_base64":"` +
			base64.StdEncoding.EncodeToString([]byte(rawResp)) + `"}`
		status, respBody := doReq(t, app, http.MethodPost, "/api/ingest-http", body, nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, respBody)
		}
		var resp IngestHTTPResponse
		if err := json.Unmarshal(respBody, &resp); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, respBody)
		}
		if resp.Imported != 1 {
			t.Errorf("imported = %d, want 1", resp.Imported)
		}
		// Confirm the record was persisted.
		var cnt int
		if err := db.NewSelect().Table("http_records").ColumnExpr("count(*)").Scan(context.Background(), &cnt); err != nil {
			t.Fatalf("count: %v", err)
		}
		if cnt == 0 {
			t.Errorf("expected at least one persisted record")
		}
	})
}

// TestForceNativePersistLogs covers the small helper used by the scan handlers.
func TestForceNativePersistLogs(t *testing.T) {
	// nil settings → returns a non-nil settings value (defaults applied).
	if got := forceNativePersistLogs(nil); got == nil {
		t.Errorf("forceNativePersistLogs(nil) returned nil")
	}
	_ = time.Now
}
