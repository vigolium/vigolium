package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/diagnostics"
)

func doctorTestEnv(t *testing.T, report func() *diagnostics.Report) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "VIGOLIUM_PROXY"} {
		t.Setenv(k, "")
	}
	swapGlobal(t, &globalConfig, "")
	swapGlobal(t, &globalProxy, "")
	swapGlobal(t, &globalDB, filepath.Join(home, "doctor.sqlite"))
	swapGlobal(t, &doctorFix, false)
	swapGlobal(t, &doctorDryRun, false)
	swapGlobal(t, &doctorOnly, nil)
	swapGlobal(t, &doctorStrict, false)
	swapGlobal(t, &doctorFor, "")
	swapGlobal(t, &doctorRunDiagnostics, func(diagnostics.Deps) *diagnostics.Report { return report() })
	t.Cleanup(resetDBCacheForTest)
}

func degradedReport() *diagnostics.Report {
	return &diagnostics.Report{
		Status:          "degraded",
		Database:        &diagnostics.CheckResult{Status: diagnostics.StatusOK},
		NucleiTemplates: &diagnostics.CheckResult{Status: diagnostics.StatusWarning, Message: "missing"},
		OAST:            &diagnostics.CheckResult{Status: diagnostics.StatusError, Message: "oast.example does not resolve"},
		Agent:           &diagnostics.AgentCheck{Status: diagnostics.StatusOK, Name: "olium", Protocol: "openai-compatible", Unverified: true, Endpoint: "http://127.0.0.1:1/v1", Message: "endpoint not contacted"},
		Tools:           map[string]*diagnostics.ToolCheck{"chromium": {Status: diagnostics.StatusError, Message: "not found"}},
	}
}

func checkIDs(items []any) []string {
	var ids []string
	for _, it := range items {
		ids = append(ids, it.(map[string]any)["id"].(string))
	}
	return ids
}

// doctor -j: flat checks, capabilities, an unverified agent, the proxy row,
// and the source of a failing check's setting.
func TestDoctorFlatChecks(t *testing.T) {
	doctorTestEnv(t, degradedReport)
	t.Setenv("VIGOLIUM_OAST_DOMAIN", "oast.example")
	doc := emitCaptured(t, func() error { return runDoctorCmd(doctorCmd, nil) })
	items := doc["items"].([]any)
	ids := checkIDs(items)
	require.Contains(t, ids, "proxy")
	require.Contains(t, ids, "agent")
	caps := doc["capabilities"].(map[string]any)
	require.Equal(t, "unavailable", caps["spidering"])
	require.Equal(t, "unverified", caps["agent"])
	for _, it := range items {
		c := it.(map[string]any)
		switch c["id"] {
		case "agent":
			require.Equal(t, "unverified", c["status"])
		case "chromium":
			require.Equal(t, []any{"vigolium", "doctor", "--fix", "--only", "chrome"}, c["fix_argv"])
		case "oast":
			require.Contains(t, c["source"], "oast.server_url from ")
		case "proxy":
			require.Equal(t, "ok", c["status"])
		}
	}
}

// --only filters without --fix; an unknown name is a usage error.
func TestDoctorOnlyFiltersWithoutFix(t *testing.T) {
	doctorTestEnv(t, degradedReport)
	swapGlobal(t, &doctorOnly, []string{"chrome", "oast"})
	doc := emitCaptured(t, func() error { return runDoctorCmd(doctorCmd, nil) })
	require.ElementsMatch(t, []string{"chromium", "oast"}, checkIDs(doc["items"].([]any)))

	swapGlobal(t, &doctorOnly, []string{"chrmoe"})
	err := runDoctorCmd(doctorCmd, nil)
	var usage clicommon.UsageError
	require.True(t, errors.As(err, &usage), "%v", err)
}

// --fix --dry-run lists each install with method, destination and size, and
// installs nothing.
func TestDoctorFixDryRun(t *testing.T) {
	doctorTestEnv(t, degradedReport)
	swapGlobal(t, &doctorFix, true)
	swapGlobal(t, &doctorDryRun, true)
	swapGlobal(t, &doctorOnly, []string{"chrome", "nuclei"})
	doc := emitCaptured(t, func() error { return runDoctorCmd(doctorCmd, nil) })
	require.Equal(t, true, doc["dry_run"])
	fixes := doc["fixes"].([]any)
	require.Len(t, fixes, 2)
	for _, f := range fixes {
		row := f.(map[string]any)
		require.Equal(t, true, row["planned"])
		require.NotEmpty(t, row["method"])
		require.NotEmpty(t, row["destination"])
		require.True(t, strings.HasPrefix(row["size"].(string), "~"), "%v", row)
		require.NotEqual(t, true, row["success"], "nothing was installed")
	}
}

// A proxy taken from the environment is named with its variable, and a dead
// one is an error.
func TestDoctorProxyNamesItsSource(t *testing.T) {
	doctorTestEnv(t, degradedReport)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	swapGlobal(t, &doctorOnly, []string{"proxy"})
	doc := emitCaptured(t, func() error { return runDoctorCmd(doctorCmd, nil) })
	items := doc["items"].([]any)
	require.Len(t, items, 1)
	c := items[0].(map[string]any)
	require.Equal(t, "error", c["status"])
	require.Contains(t, c["message"], "from HTTPS_PROXY")
	require.Contains(t, c["message"], "loopback")
}

// The human report puts the verdict before the checks and keeps the detail
// lines for -v.
func TestDoctorHumanVerdictFirst(t *testing.T) {
	doctorTestEnv(t, func() *diagnostics.Report {
		r := degradedReport()
		r.Config = &diagnostics.CheckResult{Status: diagnostics.StatusOK, Message: "ok", Details: []string{"DETAIL-LINE"}}
		return r
	})
	swapGlobal(t, &globalJSON, false)
	swapGlobal(t, &globalVerbose, false)
	out := captureStdout(t, func() { _ = runDoctorCmd(doctorCmd, nil) })
	verdict := strings.Index(out, "Degraded")
	core := strings.Index(out, "Core")
	require.True(t, verdict >= 0 && core > verdict, "verdict must precede the checks:\n%s", out)
	require.NotContains(t, out, "DETAIL-LINE", "detail lines are for -v")
}
