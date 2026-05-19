//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vigolium/vigolium/pkg/server"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// Smoke tests guarding the intensity → profile → strategy → phase chain
// against the regression where applying a profile silently zeroed
// Lite/Balanced/Deep phase tables (user-visible: "intensity:deep ran no
// phases"). Both entry points are exercised: the CLI binary via subprocess,
// and the REST API via in-process server. --only ingestion keeps the scan
// short — the banner is printed before the only-clamp, so it still reflects
// the resolved strategy/profile.

// repoRoot returns the absolute path of the vigolium repo root.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")
	// file lives at .../vigolium/test/e2e/scan_intensity_smoke_test.go
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

// installBundledProfiles copies public/presets/profiles/*.yaml into a fresh
// tempdir so the test resolves --intensity → profile without depending on the
// caller's ~/.vigolium/profiles state.
func installBundledProfiles(t *testing.T) string {
	t.Helper()
	src := filepath.Join(repoRoot(t), "public", "presets", "profiles")
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	require.NoError(t, err, "read bundled profiles dir %s", src)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dst, e.Name()), data, 0o644))
	}
	return dst
}

var (
	smokeBinaryOnce sync.Once
	smokeBinaryPath string
	smokeBinaryErr  error
)

// buildVigoliumBinary compiles ./cmd/vigolium into a tempdir once per test
// process so subprocess invocations exercise the source under test.
func buildVigoliumBinary(t *testing.T) string {
	t.Helper()
	smokeBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "vigolium-smoke-bin-")
		if err != nil {
			smokeBinaryErr = fmt.Errorf("mkdir tempdir: %w", err)
			return
		}
		bin := filepath.Join(dir, "vigolium")
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/vigolium")
		cmd.Dir = repoRoot(t)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			smokeBinaryErr = fmt.Errorf("go build: %w (stderr: %s)", err, stderr.String())
			return
		}
		smokeBinaryPath = bin
	})
	if smokeBinaryErr != nil {
		t.Fatalf("buildVigoliumBinary: %v", smokeBinaryErr)
	}
	return smokeBinaryPath
}

// startJuiceShopContainer launches juice-shop and returns the BaseURL.
func startJuiceShopContainer(t *testing.T) *VulnerableApp {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	app, err := StartContainer(ctx, ContainerConfig{
		Image:       "bkimminich/juice-shop:latest",
		ExposedPort: "3000/tcp",
		WaitStrategy: wait.ForHTTP("/").
			WithPort("3000").
			WithStartupTimeout(120 * time.Second),
		ReadyEndpoint: "/",
	})
	require.NoError(t, err, "Failed to start Juice Shop container")
	// app.Stop registered before cancel: t.Cleanup runs in LIFO order, so
	// Terminate fires while the context is still live.
	t.Cleanup(func() { _ = app.Stop() })
	t.Cleanup(cancel)
	return app
}

// TestSmoke_NativeScan_CLI_IntensityDeep runs `vigolium scan -t <juice>
// --intensity deep` and asserts the runner banner reports Strategy: deep
// and Profile: full — the user-facing signal that intensity flowed through
// the CLI without the profile-clobber regression.
func TestSmoke_NativeScan_CLI_IntensityDeep(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping smoke test in short mode")
	}

	juice := startJuiceShopContainer(t)
	profilesDir := installBundledProfiles(t)
	sessionsDir := t.TempDir()
	bin := buildVigoliumBinary(t)

	// Stand-alone config so the test doesn't read ~/.vigolium/.
	cfgPath := filepath.Join(t.TempDir(), "vigolium-configs.yaml")
	cfgYAML := fmt.Sprintf(`scanning_strategy:
  default_strategy: balanced
  profiles_dir: %s
  scan_logs:
    sessions_dir: %s
    persist_logs: true
database:
  enabled: false
`, profilesDir, sessionsDir)
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgYAML), 0o644))

	// Hard wall clock cap so a hung subprocess can't stall the test suite.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "scan",
		"-t", juice.BaseURL,
		"--intensity", "deep",
		"--config", cfgPath,
		"--only", "ingestion", // shortest phase — banner still reflects deep
		"--scanning-max-duration", "20s",
	)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr // merge so we don't lose anything
	_ = cmd.Run()        // exit code may be non-zero on time cap; banner is what we check
	output := terminal.StripANSI(stderr.String())

	if !strings.Contains(output, "Strategy: deep") || !strings.Contains(output, "Profile: full") {
		t.Logf("captured output (last 4KB):\n%s", lastN(output, 4096))
	}

	assert.Contains(t, output, "Strategy: deep",
		"expected banner to show Strategy: deep — regression of profile clobber bug")
	assert.Contains(t, output, "Profile: full",
		"expected banner to show Profile: full")
}

// TestSmoke_NativeScan_API_IntensityDeep mirrors the user's curl repro
// (POST /api/scans/run, intensity=deep) against juice-shop, then asserts
// the runtime.log written by the in-process runner shows the right
// strategy/profile banner.
func TestSmoke_NativeScan_API_IntensityDeep(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping smoke test in short mode")
	}

	juice := startJuiceShopContainer(t)
	profilesDir := installBundledProfiles(t)
	sessionsDir := t.TempDir()

	env := newSettingsTestEnv(t, "")
	// Wire profiles + sessions dir into the live settings; PersistLogs is
	// already forced true by forceNativePersistLogs in the handler.
	env.settings.ScanningStrategy.ProfilesDir = profilesDir
	env.settings.ScanningStrategy.ScanLogs.SessionsDir = sessionsDir

	body := fmt.Sprintf(`{
        "targets": ["%s"],
        "intensity": "deep",
        "only": "ingestion",
        "scanning_max_duration": "20s",
        "headers": {}
    }`, juice.BaseURL)
	resp := env.post(t, "/api/scans/run", body)
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"scan run should accept intensity=deep")
	var scanResp server.ScanResponse
	readJSON(t, resp, &scanResp)
	require.NotEmpty(t, scanResp.ScanUUID)

	waitForScanIdle(t, env)

	runtimeLog := filepath.Join(sessionsDir, scanResp.ScanUUID, "runtime.log")
	deadline := time.Now().Add(30 * time.Second)
	var contents string
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(runtimeLog); err == nil && len(data) > 0 {
			contents = terminal.StripANSI(string(data))
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	require.NotEmpty(t, contents, "runtime.log was never written at %s", runtimeLog)

	assert.Contains(t, contents, "Strategy: deep",
		"runtime.log should report Strategy: deep — regression of profile clobber")
	assert.Contains(t, contents, "Profile: full",
		"runtime.log should report Profile: full")
}

// lastN returns the last n characters of s, prefixed with "..." when
// truncation occurred. Used to keep test failure logs readable.
func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "...\n" + s[len(s)-n:]
}
