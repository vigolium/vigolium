package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// runChildWithin is newB5Env's run with a deadline, so a dry run that starts
// scanning fails the test instead of hanging it.
func (e *b5Env) runChildWithin(t *testing.T, d time.Duration, args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	argv := append([]string{"--db", e.db}, args...)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMachineMutationsChild$", "-test.v=false")
	env := []string{b5ChildEnv + "=" + strings.Join(argv, "\x1f"), "HOME=" + e.home, "VIGOLIUM_DISABLE_UPDATE_CHECK=1"}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if name == "HOME" || strings.HasPrefix(name, "VIGOLIUM_") || strings.Contains(strings.ToLower(name), "proxy") ||
			strings.Contains(name, "API_KEY") || strings.Contains(name, "ANTHROPIC") || strings.Contains(name, "OPENAI") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("%v did not finish within %s:\n%s", args, d, errb.String())
	}
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, out.String(), errb.String()
}

// agent autopilot / swarm --dry-run send nothing to the target and call no
// provider, on the flag path and the natural-language path alike.
func TestAgentDryRunSendsNothing(t *testing.T) {
	var targetHits, providerHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = w.Write([]byte("<html>hi</html>"))
	}))
	defer target.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerHits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer provider.Close()

	e := newB5Env(t)
	cfg := "agent:\n  olium:\n    provider: openai-compatible\n    custom_provider:\n      base_url: " + provider.URL + "/v1\n      model_id: m\n"
	require.NoError(t, os.WriteFile(filepath.Join(e.home, ".vigolium", "vigolium-configs.yaml"), []byte(cfg), 0o600))

	for _, args := range [][]string{
		{"agent", "autopilot", "-t", target.URL + "/", "--dry-run", "-j"},
		{"agent", "autopilot", "-t", target.URL + "/", "--dry-run"},
		{"agent", "swarm", "-t", target.URL + "/", "--dry-run", "-j"},
		{"agent", "autopilot", "scan " + target.URL + "/ for sqli", "--dry-run", "-j"},
		{"agent", "swarm", "scan " + target.URL + "/ for sqli", "--dry-run"},
	} {
		code, stdout, stderr := e.runChildWithin(t, 60*time.Second, args...)
		require.Equal(t, 0, code, "%v\nstdout:\n%s\nstderr:\n%s", args, stdout, stderr)
		require.Zero(t, targetHits.Load(), "%v sent %d request(s) to the target", args, targetHits.Load())
		require.Zero(t, providerHits.Load(), "%v called the provider", args)
	}
}
