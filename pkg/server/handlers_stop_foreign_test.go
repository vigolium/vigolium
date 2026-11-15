package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
)

// A scan the server does not run (a CLI scan on the same store) is stopped
// through a stop request on its row: 202, and the request is recorded.
func TestHandleStopScan_ForeignScanGetsStopRequest(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	ctx := context.Background()
	running := &database.Scan{UUID: "cli-scan-running", ProjectUUID: database.DefaultProjectUUID, Status: "running", StartedAt: time.Now()}
	if err := repo.CreateScan(ctx, running); err != nil {
		t.Fatal(err)
	}
	other := &database.Scan{UUID: "cli-scan-other-project", ProjectUUID: "another-project", Status: "running", StartedAt: time.Now()}
	if err := repo.CreateScan(ctx, other); err != nil {
		t.Fatal(err)
	}
	done := insertScan(t, db, repo, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/scans/:uuid/stop", h.HandleStopScan)

	if status, body := doReq(t, app, http.MethodPost, "/api/scans/cli-scan-running/stop", "", nil); status != http.StatusAccepted {
		t.Fatalf("running foreign scan: status %d, want 202\n%s", status, body)
	}
	if req, err := repo.ScanStopRequested(ctx, "cli-scan-running"); err != nil || req == nil || req.By != "rest api" {
		t.Fatalf("stop request = %+v, %v", req, err)
	}
	for _, id := range []string{done, "cli-scan-other-project", "no-such-scan"} {
		if status, _ := doReq(t, app, http.MethodPost, "/api/scans/"+id+"/stop", "", nil); status != http.StatusConflict {
			t.Errorf("%s: status %d, want 409", id, status)
		}
	}
	if req, _ := repo.ScanStopRequested(ctx, "cli-scan-other-project"); req != nil {
		t.Fatal("a scan of another project got a stop request")
	}
}

// An agent run the server does not run gets a cancel request on its row.
func TestHandleAgentCancel_ForeignRunGetsCancelRequest(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	ctx := context.Background()
	if err := repo.CreateAgenticScan(ctx, &database.AgenticScan{UUID: "cli-agent-run", ProjectUUID: database.DefaultProjectUUID,
		Mode: "autopilot", AgentName: "olium", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateAgenticScan(ctx, &database.AgenticScan{UUID: "cli-agent-done", ProjectUUID: database.DefaultProjectUUID,
		Mode: "autopilot", AgentName: "olium", Status: "completed"}); err != nil {
		t.Fatal(err)
	}
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/agent/scans/:uuid/cancel", h.HandleAgentCancel)

	if status, body := doReq(t, app, http.MethodPost, "/api/agent/scans/cli-agent-run/cancel", "", nil); status != http.StatusAccepted {
		t.Fatalf("status %d, want 202\n%s", status, body)
	}
	if ok, _ := repo.AgenticScanCancelRequested(ctx, "cli-agent-run"); !ok {
		t.Fatal("cancel request not recorded")
	}
	for _, id := range []string{"cli-agent-done", "nope"} {
		if status, _ := doReq(t, app, http.MethodPost, "/api/agent/scans/"+id+"/cancel", "", nil); status != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", id, status)
		}
	}
}

// With scan-on-receive on, an ingest response names the scan that will pick
// the records up and its cursor.
func TestIngestResponseNamesScanOnReceiveScan(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	ctx := context.Background()
	if err := repo.CreateScan(ctx, &database.Scan{UUID: "scan-sor-1", ProjectUUID: database.DefaultProjectUUID, Status: "running",
		ScanSource: database.ScanSourceScanOnReceive, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	h := newBasicHandlers(t, ServerConfig{ScanOnReceive: true, DisableFetchResponse: true}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/ingest-http", h.HandleIngestHTTP)
	status, body := doReq(t, app, http.MethodPost, "/api/ingest-http",
		`{"input_mode":"curl","content":"curl https://sor.example/a"}`, map[string]string{"Content-Type": "application/json"})
	if status != http.StatusOK || !strings.Contains(string(body), `"scan_on_receive":{"scan_uuid":"scan-sor-1"`) {
		t.Fatalf("status %d\n%s", status, body)
	}
}
