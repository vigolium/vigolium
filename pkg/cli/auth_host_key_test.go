package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/authentication"
)

// A session loaded for a host:port is found by replay --auth-session on that
// host:port (writes and reads share one key); auth load never prints the
// credential; the scan banner names a stored session and --no-auth drops it.
func TestStoredSessionKeyBannerAndRedaction(t *testing.T) {
	var mu sync.Mutex
	var cookies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookies = append(cookies, r.Header.Get("Cookie"))
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	home := a3Home(t, "127.0.0.1")
	db := filepath.Join(t.TempDir(), "a.sqlite")
	hostport := strings.TrimPrefix(srv.URL, "http://")
	sessFile := filepath.Join(t.TempDir(), "s.yaml")
	require.NoError(t, os.WriteFile(sessFile, []byte("sessions:\n  - name: alice\n    role: primary\n    headers:\n      Cookie: session=s3cr3t-value\n"), 0o600))

	code, stdout, stderr := runA3(t, home, "auth", "load", sessFile, "--host", hostport, "--db", db)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.NotContains(t, stdout+stderr, "s3cr3t-value", "auth load never prints the credential")

	code, stdout, stderr = runA3(t, home, "replay", "-i", "curl "+srv.URL+"/x", "--auth-session", "alice", "--db", db, "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	mu.Lock()
	got := append([]string(nil), cookies...)
	mu.Unlock()
	require.NotEmpty(t, got)
	assert.Contains(t, got[len(got)-1], "session=s3cr3t-value", "the session stored for host:port is found")

	args := []string{"scan-url", srv.URL + "/x", "--db", db, "-m", "security-headers-missing", "--dry-run"}
	code, stdout, stderr = runA3(t, home, args...)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Contains(t, stdout, "alice", "the plan names the stored session")

	code, stdout, _ = runA3(t, home, append(args, "--no-auth")...)
	require.Equal(t, 0, code)
	assert.NotContains(t, stdout, "alice", "--no-auth drops it")

	code, _, _ = runA3(t, home, append(args, "--no-auth", "--auth", "x:Cookie:a=1")...)
	assert.Equal(t, ExitUsageError, code)
}

func TestSessionLintGate(t *testing.T) {
	swapGlobal(t, &sessionLoadForce, false)
	warn := []authentication.LintIssue{{Field: "sessions", Severity: "warning", Message: "w"}}
	assert.NoError(t, sessionLintGate("s.yaml", warn))
	bad := append(warn, authentication.LintIssue{Field: "sessions[0]", Severity: "error", Message: "specify only one"})
	err := sessionLintGate("s.yaml", bad)
	require.Error(t, err)
	assert.Equal(t, apicontract.CodeLintFailed, classifyErrorCode(err, classifyExitCode(err)))
	sessionLoadForce = true
	assert.NoError(t, sessionLintGate("s.yaml", bad))
	assert.Equal(t, "<redacted>", redactSessionValue("Authorization", "Bearer x"))
	assert.Equal(t, "json", redactSessionValue("Accept", "json"))
}
