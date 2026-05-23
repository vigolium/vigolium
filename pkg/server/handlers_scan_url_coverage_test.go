package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// -----------------------------------------------------------------------------
// resolveAPIOutputFormats + validateRunScanRequest (pure)
// -----------------------------------------------------------------------------

func TestResolveAPIOutputFormats(t *testing.T) {
	t.Run("empty returns nil", func(t *testing.T) {
		got, err := resolveAPIOutputFormats(nil)
		if err != nil || got != nil {
			t.Errorf("got (%v,%v), want (nil,nil)", got, err)
		}
	})
	t.Run("dedup + normalize", func(t *testing.T) {
		got, err := resolveAPIOutputFormats([]string{"JSONL", " html ", "jsonl", ""})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(got) != 2 || got[0] != "jsonl" || got[1] != "html" {
			t.Errorf("got %v, want [jsonl html]", got)
		}
	})
	t.Run("invalid format → error", func(t *testing.T) {
		if _, err := resolveAPIOutputFormats([]string{"csv"}); err == nil {
			t.Errorf("expected error for unsupported format")
		}
	})
}

func TestValidateRunScanRequest(t *testing.T) {
	cases := []struct {
		name    string
		req     RunScanRequest
		wantErr bool
	}{
		{"empty ok", RunScanRequest{}, false},
		{"valid strategy", RunScanRequest{Strategy: "deep"}, false},
		{"bad strategy", RunScanRequest{Strategy: "ultra"}, true},
		{"only+skip mutually exclusive", RunScanRequest{Only: "discovery", Skip: []string{"spidering"}}, true},
		{"bad only phase", RunScanRequest{Only: "not-a-phase"}, true},
		{"bad skip phase", RunScanRequest{Skip: []string{"not-a-phase"}}, true},
		{"valid skip", RunScanRequest{Skip: []string{"discovery", "spidering"}}, false},
		{"bad scope origin", RunScanRequest{ScopeOrigin: "weird"}, true},
		{"bad heuristics", RunScanRequest{HeuristicsCheck: "max"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateRunScanRequest(tc.req); (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// HandleRunScan — early validation paths (no live runner)
// -----------------------------------------------------------------------------

func TestHandleRunScan_Validation(t *testing.T) {
	t.Run("nil db → 400", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app := fiber.New()
		app.Post("/api/scans/run", h.HandleRunScan)
		if status, _ := doReq(t, app, http.MethodPost, "/api/scans/run", `{"targets":["https://x"]}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/scans/run", h.HandleRunScan)

	t.Run("malformed body → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scans/run", `{not json`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("no targets → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scans/run", `{}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("invalid strategy → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scans/run", `{"targets":["https://x"],"strategy":"ultra"}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("invalid timeout → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scans/run", `{"targets":["https://x"],"timeout":"notaduration"}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})
}

// -----------------------------------------------------------------------------
// HandleScanURL / HandleScanRequest — validation paths (no live runner)
// -----------------------------------------------------------------------------

func TestHandleScanURL_Validation(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Post("/api/scan-url", h.HandleScanURL)

	t.Run("malformed body → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-url", `{not json`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("missing url → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-url", `{}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("invalid url → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-url", `{"url":"::::not a url"}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})
}

func TestHandleScanRequest_Validation(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Post("/api/scan-request", h.HandleScanRequest)

	t.Run("malformed body → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-request", `{not json`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("missing raw request → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-request", `{}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("invalid base64 → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scan-request", `{"http_request_base64":"!!!"}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})
}

// -----------------------------------------------------------------------------
// buildRequestFromParams (pure)
// -----------------------------------------------------------------------------

func TestBuildRequestFromParams(t *testing.T) {
	t.Run("simple GET", func(t *testing.T) {
		rr, err := buildRequestFromParams("https://example.test/path", "GET", "", nil)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if rr == nil {
			t.Fatalf("nil request")
		}
	})

	t.Run("POST with body and headers", func(t *testing.T) {
		rr, err := buildRequestFromParams("https://example.test/api", "POST", `{"a":1}`, map[string]string{"X-Test": "yes"})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if rr == nil {
			t.Fatalf("nil request")
		}
	})

	t.Run("invalid URL → error", func(t *testing.T) {
		if _, err := buildRequestFromParams("://bad-url", "POST", "x", nil); err == nil {
			t.Errorf("expected error for invalid URL")
		}
	})
}

// -----------------------------------------------------------------------------
// scan_url pure display helpers
// -----------------------------------------------------------------------------

func TestScanURLDisplayHelpers(t *testing.T) {
	t.Run("colorModuleType", func(t *testing.T) {
		// Output is colored, but the type substring must survive.
		for _, ty := range []string{"active", "passive", "other"} {
			if got := colorModuleType(ty); !strings.Contains(got, ty) {
				t.Errorf("colorModuleType(%q) = %q, missing type", ty, got)
			}
		}
	})

	t.Run("scanShortID", func(t *testing.T) {
		if got := scanShortID("scan-abcdefgh1234"); got != "abcdefgh" {
			t.Errorf("got %q, want abcdefgh", got)
		}
		if got := scanShortID("short"); got != "short" {
			t.Errorf("got %q, want short", got)
		}
	})

	t.Run("severityBracket covers all severities", func(t *testing.T) {
		for _, sev := range []severity.Severity{
			severity.Critical, severity.High, severity.Medium,
			severity.Low, severity.Suspect, severity.Info,
		} {
			if got := severityBracket(sev); !strings.Contains(got, sev.String()) {
				t.Errorf("severityBracket(%v) = %q, missing severity text", sev, got)
			}
		}
	})

	t.Run("formatFindingLine", func(t *testing.T) {
		res := &output.ResultEvent{
			ModuleID:         "xss-reflected",
			ModuleType:       "active",
			URL:              "https://example.test/q",
			Matched:          "https://example.test/q?x=1",
			ExtractedResults: []string{"payload<script>"},
		}
		res.Info.Severity = severity.High
		line := formatFindingLine("scan-deadbeef00", res)
		if !strings.Contains(line, "xss-reflected") {
			t.Errorf("line missing module id: %q", line)
		}
		if !strings.HasSuffix(line, "\n") {
			t.Errorf("line should end with newline")
		}
	})
}

// -----------------------------------------------------------------------------
// Import + Storage handler early-return / validation paths
// -----------------------------------------------------------------------------

func TestHandleImport_Validation(t *testing.T) {
	t.Run("nil db → 503", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app := fiber.New()
		app.Post("/api/import", h.HandleImport)
		if status, _ := doReq(t, app, http.MethodPost, "/api/import", `{}`, nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})

	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/import", h.HandleImport)

	t.Run("unsupported content-type → 415", func(t *testing.T) {
		// doReq sets Content-Type only when a body is given; send a body so
		// the JSON branch is taken... here we want a non-json, non-multipart
		// type, so build the request manually via doReqRawCT.
		if status := postWithContentType(t, app, "/api/import", "x", "text/plain"); status != http.StatusUnsupportedMediaType {
			t.Errorf("status = %d, want 415", status)
		}
	})

	t.Run("json malformed → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/import", `{not json`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("json missing url → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/import", `{}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("json non-gcs url → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/import", `{"url":"https://example.test/x.tar.gz"}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("json gcs url but storage disabled → 503", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/import", `{"url":"gs://bucket/path/x.tar.gz"}`, nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})
}

func TestStorageHandlers_NotEnabled(t *testing.T) {
	// nil settings → storage disabled. Every storage handler must short-circuit
	// with 503 before touching locals.
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Post("/api/storage/upload-source", h.HandleStorageUploadSource)
	app.Get("/api/storage/source/:key", h.HandleStorageDownloadSource)
	app.Get("/api/storage/results/:scan_uuid", h.HandleStorageDownloadResults)
	app.Post("/api/storage/presign", h.HandleStoragePresign)

	t.Run("upload-source → 503", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/storage/upload-source", "", nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})
	t.Run("download-source → 503", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/storage/source/abc", nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})
	t.Run("download-results → 503", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/storage/results/scan-1", nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})
	t.Run("presign → 503", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/storage/presign", `{"key":"x"}`, nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})
}

// postWithContentType posts a body with an explicit Content-Type and returns the
// status code.
func postWithContentType(t *testing.T, app *fiber.App, path, body, contentType string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}
