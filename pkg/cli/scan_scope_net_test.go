package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
)

// scopeNetHome is a3Home with scopeYAML as the config's whole scope section.
func scopeNetHome(t *testing.T, scopeYAML string) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".vigolium")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, initMarkerFileName), []byte("ok"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "vigolium-configs.yaml"), []byte(noOASTConfig+"scope:\n"+scopeYAML), 0o600))
	return home
}

// A private (loopback) target the host rule does not name is admitted by a
// scope.cidr.include prefix and scanned.
func TestScanURLCIDRScopedPrivateTargetAdmitted(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	srv, hits := countingServer(t)
	home := scopeNetHome(t, "  host:\n    include: [\"nomatch.example\"]\n  cidr:\n    include: [\"127.0.0.0/8\"]\n")
	code, stdout, stderr := runA3(t, home, "scan-url", srv.URL+"/", "-j", "--db", filepath.Join(home, "a3.sqlite"), "-m", "security-headers-missing")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Positive(t, hits.Load(), "the CIDR-scoped target is scanned")
}

// The instance-metadata address is refused at entry under the default scope,
// and admitted once a scope entry names it. --dry-run sends nothing either way.
func TestScanURLMetadataAddressRefusedWithoutRule(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	const imds = "http://169.254.169.254/latest/meta-data/"
	home := scopeNetHome(t, "  host:\n    include: [\"*\"]\n")
	for _, cmd := range [][]string{{"scan-url", imds}, {"scan", "-t", imds}} {
		args := append(append([]string(nil), cmd...), "--dry-run", "-j", "--db", filepath.Join(home, "a3.sqlite"))
		code, stdout, stderr := runA3(t, home, args...)
		require.Equal(t, 2, code, "%v\nstdout:\n%s\nstderr:\n%s", cmd, stdout, stderr)
		assert.Equal(t, string(apicontract.CodeOutOfScope), errorCode(t, stdout))
		assert.Contains(t, stdout, config.ScopeRuleMetadataAddress)
	}

	named := scopeNetHome(t, "  host:\n    include: [\"*\"]\n  cidr:\n    include: [\"169.254.169.254/32\"]\n")
	code, stdout, stderr := runA3(t, named, "scan-url", imds, "--dry-run", "-j", "--db", filepath.Join(named, "a3.sqlite"))
	require.Equal(t, 0, code, "an explicit CIDR entry lifts the block\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
}

// scope.port refuses a target on another port at entry.
func TestScanPortRuleRefusesAtEntry(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	srv, hits := countingServer(t)
	home := scopeNetHome(t, "  port:\n    include: [\"1\"]\n")
	code, stdout, stderr := runA3(t, home, "scan", "-t", srv.URL+"/", "-j", "--db", filepath.Join(home, "a3.sqlite"))
	require.Equal(t, 2, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, string(apicontract.CodeOutOfScope), errorCode(t, stdout))
	assert.Contains(t, stdout, config.ScopeRulePortInclude)
	assert.Zero(t, hits.Load())
}

// VIGOLIUM_REQUIRE_SCOPE=1 refuses scan-url under a scope that names no hosts,
// as it refuses the senders.
func TestScanURLRequireScopeRefusesEmptyScope(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	srv, hits := countingServer(t)
	home := scopeNetHome(t, "  cli_origin_mode: all\n  host:\n    include: [\"*\"]\n")
	code, stdout, stderr := runA3Env(t, home, []string{"VIGOLIUM_REQUIRE_SCOPE=1"}, "scan-url", srv.URL+"/", "-j", "--db", filepath.Join(home, "a3.sqlite"), "-m", "security-headers-missing")
	require.Equal(t, 2, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, string(apicontract.CodeOutOfScope), errorCode(t, stdout))
	assert.Contains(t, stdout, "--require-scope")
	assert.Zero(t, hits.Load())
}

// fuzz --resolve: the pinned address is judged like a resolved one, so an
// in-scope name cannot be pointed at the metadata address or an excluded
// prefix, nor a name only a glob admits at a private address; an ordinary
// public pin passes, and so does a private pin for a host the scope names.
func TestSendScopeGateJudgesResolveOverrides(t *testing.T) {
	cfg := *config.DefaultScopeConfig()
	cfg.Host = config.ScopeRule{Include: []string{"app.example.com"}}
	cfg.CIDR = config.ScopeRule{Exclude: []string{"203.0.113.0/24"}}
	gate := scopeGateFor(cfg, false)
	src := &replaySource{Hostname: "app.example.com", Port: 8443}

	for _, pin := range []string{"app.example.com:8443:169.254.169.254", "app.example.com:8443:203.0.113.9"} {
		overrides, err := parseResolveOverrides([]string{pin})
		require.NoError(t, err)
		err = gate.checkResolved(src, overrides)
		require.Error(t, err, pin)
		assert.True(t, isOutOfScope(err), pin)
	}
	for _, pin := range []string{"app.example.com:8443:198.51.100.4", "app.example.com:8443:10.0.0.7"} {
		overrides, err := parseResolveOverrides([]string{pin})
		require.NoError(t, err)
		assert.NoError(t, gate.checkResolved(src, overrides), pin)
	}
	globCfg := *config.DefaultScopeConfig()
	globCfg.Host = config.ScopeRule{Include: []string{"*.example.com"}}
	overrides, err := parseResolveOverrides([]string{"app.example.com:8443:10.0.0.7"})
	require.NoError(t, err)
	assert.True(t, isOutOfScope(scopeGateFor(globCfg, false).checkResolved(src, overrides)), "a glob-admitted name pinned to a private address")
	// A pin for another host:port does not apply to this destination.
	overrides, err = parseResolveOverrides([]string{"app.example.com:443:169.254.169.254"})
	require.NoError(t, err)
	assert.NoError(t, gate.checkResolved(src, overrides))
}

// The sender gate applies the port and CIDR rules to a destination whose port
// it knows.
func TestSendScopeGatePortAndCIDR(t *testing.T) {
	cfg := *config.DefaultScopeConfig()
	cfg.Port = config.ScopeRule{Include: []string{"443"}}
	cfg.CIDR = config.ScopeRule{Include: []string{"10.9.0.0/16"}}
	gate := scopeGateFor(cfg, false)
	assert.NoError(t, gate.check("https://10.9.1.1/x"))
	assert.True(t, isOutOfScope(gate.check("http://10.9.1.1/x")), "port 80 is outside scope.port")
	assert.True(t, isOutOfScope(gate.check("https://10.8.1.1/x")), "an IP outside scope.cidr.include")
	assert.NoError(t, gate.check("www.example.org"), "a bare name with no port is judged on the host rule")
}
