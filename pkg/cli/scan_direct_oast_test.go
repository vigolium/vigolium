package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
)

// failingInteractsh is a local "interactsh server" that refuses registration.
func failingInteractsh(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeOASTConfig writes a config whose oast section is body and points
// --config at it.
func writeOASTConfig(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vigolium-configs.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	swapGlobal(t, &globalConfig, path)
}

func TestDirectOASTConfig(t *testing.T) {
	directRowFixture(t)
	swapGlobal(t, &scanOpts.OastURL, "")

	t.Run("--oast-url selects fixed-URL mode", func(t *testing.T) {
		writeOASTConfig(t, "oast:\n  enabled: true\n")
		scanOpts.OastURL = "https://{nonce}.cb.example"
		t.Cleanup(func() { scanOpts.OastURL = "" })
		cfg, err := (&directScanSession{}).oastConfig()
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, "https://{nonce}.cb.example", cfg.OastURL)
	})

	t.Run("--offline turns OAST off, --oast-url included", func(t *testing.T) {
		writeOASTConfig(t, "oast:\n  enabled: true\n")
		swapGlobal(t, &scanOpts.OastURL, "https://cb.example")
		swapGlobal(t, &globalOffline, true)
		cfg, err := (&directScanSession{}).oastConfig()
		require.NoError(t, err)
		assert.Nil(t, cfg, "an --offline direct scan must register and plant nothing out of band")
	})

	t.Run("settings key offline turns OAST off", func(t *testing.T) {
		writeOASTConfig(t, "offline: true\noast:\n  enabled: true\n")
		cfg, err := (&directScanSession{}).oastConfig()
		require.NoError(t, err)
		assert.Nil(t, cfg)
	})

	t.Run("oast.enabled false wins, as on scan", func(t *testing.T) {
		writeOASTConfig(t, "oast:\n  enabled: false\n")
		scanOpts.OastURL = "https://cb.example"
		t.Cleanup(func() { scanOpts.OastURL = "" })
		cfg, err := (&directScanSession{}).oastConfig()
		require.NoError(t, err)
		assert.Nil(t, cfg)
	})

	t.Run("interactsh when enabled", func(t *testing.T) {
		writeOASTConfig(t, "oast:\n  enabled: true\n  server_url: http://127.0.0.1:9\n")
		cfg, err := (&directScanSession{}).oastConfig()
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, "http://127.0.0.1:9", cfg.ServerURL)
	})
}

// A fixed URL is ready at once and is wired into the executor.
func TestAwaitDirectOASTFixedURL(t *testing.T) {
	swapGlobal(t, &globalSilent, true)
	sess := &directScanSession{}
	svc := startDirectOAST(&config.OASTConfig{Enabled: true, OastURL: "https://cb.example"}, nil, nil, "scan-1", "")
	require.NotNil(t, svc)
	var cfg core.ExecutorConfig
	start := time.Now()
	got := awaitDirectOAST(context.Background(), sess, "scan-1", svc, &cfg)
	require.NotNil(t, got)
	defer got.Close()
	assert.Less(t, time.Since(start), time.Second)
	assert.NotNil(t, cfg.OASTProvider)
	assert.NotNil(t, cfg.OASTService)
	assert.Empty(t, sess.phaseReasons)
}

// A registration that fails leaves the executor without OAST and the row's
// reason oast_unavailable.
func TestAwaitDirectOASTUnavailable(t *testing.T) {
	swapGlobal(t, &globalSilent, true)
	srv := failingInteractsh(t)
	sess := &directScanSession{}
	svc := startDirectOAST(&config.OASTConfig{Enabled: true, ServerURL: srv.URL}, nil, nil, "scan-1", "")
	require.NotNil(t, svc)
	var cfg core.ExecutorConfig
	assert.Nil(t, awaitDirectOAST(context.Background(), sess, "scan-1", svc, &cfg))
	assert.Nil(t, cfg.OASTProvider)
	assert.Nil(t, cfg.OASTService)
	assert.Equal(t, []string{database.ReasonOASTUnavailable}, sess.phaseReasons["scan-1"])
}

// End to end on the direct path: interactsh enabled but unreachable, the scan
// still runs and completes, and its row is partial with oast_unavailable.
func TestDirectScanOASTUnavailableMarksPartial(t *testing.T) {
	directRowFixture(t)
	swapGlobal(t, &scanOpts.OastURL, "")
	iact := failingInteractsh(t)
	// fallback_to_default off: the case under test is a run that reports
	// oast_unavailable, which the default would turn into a successful
	// registration against the public oast.pro - and a suite reaching a third
	// party to prove a local failure.
	writeOASTConfig(t, "oast:\n  enabled: true\n  fallback_to_default: false\n  server_url: "+iact.URL+"\n")

	srv := bareServer(t)
	in := directInput(t, srv.URL+"/")
	sess := newDirectScanSession(database.ScanNameScanURL, []scanInput{in})
	defer sess.close()

	result, err := executeDirectScan(context.Background(), sess, in.rr, in.target, in.method)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Reachable)

	row := scanRow(t, result.ScanUUID)
	assert.Equal(t, "completed", row.Status)
	assert.Equal(t, database.CompletenessPartial, row.Completeness)
	assert.Equal(t, database.ReasonOASTUnavailable, row.StopReason)
}

// --scanning-max-duration on the direct path: a run it ends is partial with
// scan_budget (the executor itself reports no error for its deadline).
func TestDirectScanMaxDuration(t *testing.T) {
	directRowFixture(t)
	swapGlobal(t, &globalScanningMaxDuration, 300*time.Millisecond)
	// Answers the baseline at once, then holds every later request: the
	// module's follow-ups outlive the budget.
	first := make(chan struct{}, 1)
	first <- struct{}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-first:
		default:
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	}))
	t.Cleanup(srv.Close)
	globalModules = []string{"security-headers-missing", "cors-misconfiguration"}

	in := directInput(t, srv.URL+"/?q=1")
	sess := newDirectScanSession(database.ScanNameScanURL, []scanInput{in})
	defer sess.close()

	start := time.Now()
	result, err := executeDirectScan(context.Background(), sess, in.rr, in.target, in.method)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Less(t, time.Since(start), 4*time.Second, "the budget ends the run")
	assert.Contains(t, sess.phaseReasons[result.ScanUUID], database.ReasonScanBudget)
}
