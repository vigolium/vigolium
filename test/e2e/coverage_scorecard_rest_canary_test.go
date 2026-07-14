//go:build canary

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/server"
)

// restScorecardServer is an in-process Vigolium REST API server used to drive a
// scorecard scan the way an operator / the workbench UI would — over HTTP (POST
// /api/scans/run) — instead of calling runner.New directly. It writes into the
// db/repo it is handed, so the scan's findings can be scored with the same
// machinery the direct-runner scorecards use.
type restScorecardServer struct {
	url string
}

func newRESTScorecardServer(t *testing.T, db *database.DB, repo *database.Repository) *restScorecardServer {
	t.Helper()

	taskQueue, err := queue.NewDiskQueue(queue.DiskQueueConfig{
		BaseDir:              t.TempDir(),
		MaxRecordsPerSegment: 100,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = taskQueue.Close() })

	addr := fmt.Sprintf("127.0.0.1:%d", getFreePort(t))
	srv := server.NewServer(server.ServerConfig{
		ServiceAddr: addr,
		NoAuth:      true,
		NoAgent:     true, // native-scan scorecard: no agent engine needed
		Version:     "canary",
	}, taskQueue, db, repo, config.DefaultSettings(), nil, nil)

	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	url := "http://" + addr
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url + "/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return &restScorecardServer{url: url}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("REST scorecard server did not become healthy at %s", url)
	return nil
}

func (s *restScorecardServer) postJSON(t *testing.T, path, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(s.url+path, "application/json", strings.NewReader(body))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func (s *restScorecardServer) getJSON(t *testing.T, path string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(s.url + path)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// TestCoverageScorecard_RESTNativeScan_DVWA is the REST-API twin of
// TestCoverageScorecard_DVWA: it boots the full API server and triggers a REAL
// dynamic-assessment scan of the live DVWA container over HTTP (POST
// /api/scans/run), polls it to completion through the API, then scores the
// findings the server persisted. This proves the operator/UI scan path
// (server boot → POST scan → run → queryable findings) actually detects real
// vulnerabilities against a real target, not just that endpoints return 2xx.
func TestCoverageScorecard_RESTNativeScan_DVWA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	app := startDVWA(t)
	cookie := setupDVWA(t, app.BaseURL)

	db, repo := setupStatelessTempDB(t)
	srv := newRESTScorecardServer(t, db, repo)

	catalog := dvwaCatalog()
	targets := catalogTargets(app.BaseURL, catalog)

	// Drive the scan through the REST API: dynamic-assessment only (the targets
	// provide the surface), with the DVWA session cookie + identity encoding riding
	// on every probe via the headers map — exactly like `vigolium scan -H`.
	reqBody, err := json.Marshal(map[string]any{
		"targets":          targets,
		"only":             "dynamic-assessment",
		"heuristics_check": "none",
		"headers": map[string]string{
			"Cookie":          cookie,
			"Accept-Encoding": "identity",
		},
	})
	require.NoError(t, err)

	logScanCommand(t, "rest-scorecard", "", targets, []string{"Cookie: " + cookie, "Accept-Encoding: identity"})

	code, body := srv.postJSON(t, "/api/scans/run", string(reqBody))
	require.Equalf(t, http.StatusAccepted, code, "POST /api/scans/run should be accepted, got %d: %s", code, body)
	var run server.ScanResponse
	require.NoError(t, json.Unmarshal(body, &run))
	require.NotEmpty(t, run.ScanUUID)

	final := waitForTerminalStatus(t, srv.getJSON, "/api/scans/"+run.ScanUUID, 500*time.Millisecond, 12*time.Minute)
	require.NotEmptyf(t, final, "REST scan %s did not reach a terminal state within 12m", run.ScanUUID)
	require.Equal(t, "completed", final, "REST-driven native scan should finish cleanly")

	// Score the findings the server persisted. Read straight from the shared DB so
	// the exact scorecard machinery (candidate/observation kinds included) applies.
	findings := scorecardFindings(t, db)
	res := reportScorecard(t, "dvwa-rest", catalog, findings)

	// The same reliable injection gate the direct-runner DVWA scorecard asserts —
	// proven here to hold when the scan is driven entirely through the REST API.
	mustCatch(t, "dvwa-rest", res, "dvwa-sqli", "dvwa-xss-reflected", "dvwa-lfi", "dvwa-open-redirect")
	assert.GreaterOrEqualf(t, res.reHit, 4,
		"expected the REST-driven scan to catch the SQLi/XSS/LFI/open-redirect DVWA vulns (reHit=%d)", res.reHit)
}
