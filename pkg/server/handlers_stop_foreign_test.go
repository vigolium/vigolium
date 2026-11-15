package server

import (
	"context"
	"net/http"
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
