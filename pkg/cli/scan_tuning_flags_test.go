package cli

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
)

// scanTuningFlags are the flags scan-url and scan-request share with
// `vigolium scan` through registerLightweightScanTuningFlags.
var scanTuningFlags = []string{"intensity", "max-time", "scanning-max-duration", "safe", "scope-origin", "oast-url", "auth", "auth-file"}

// resetScanTuningGlobals clears the globals the tuning flags bind.
func resetScanTuningGlobals(t *testing.T) {
	t.Helper()
	swapGlobal(t, &globalIntensity, "")
	swapGlobal(t, &globalScanningMaxDuration, time.Duration(0))
	swapGlobal(t, &globalScopeOrigin, "")
	swapGlobal(t, &scanOpts.OastURL, "")
	swapGlobal(t, &scanOpts.AuthFiles, nil)
	swapGlobal(t, &scanOpts.AuthInline, nil)
	swapGlobal(t, &scanURLHeaders, nil)
}

// The tuning flags are one definition each: scan, run, scan-url and
// scan-request register them with identical usage strings, bound to the same
// globals the shared resolver reads.
func TestScanTuningFlagParity(t *testing.T) {
	ref := scanCmd.Flags()
	assert.Same(t, ref.Lookup("auth"), ref.Lookup("session"), "scan --session")
	assert.Same(t, ref.Lookup("auth-file"), ref.Lookup("session-file"), "scan --session-file")
	for _, cmd := range []struct {
		name  string
		flags *pflag.FlagSet
	}{
		{"run", runCmd.Flags()},
		{"scan-url", scanURLCmd.Flags()},
		{"scan-request", scanRequestCmd.Flags()},
	} {
		for _, name := range scanTuningFlags {
			want := ref.Lookup(name)
			require.NotNilf(t, want, "scan must register --%s", name)
			got := cmd.flags.Lookup(name)
			require.NotNilf(t, got, "%s must register --%s", cmd.name, name)
			assert.Equalf(t, want.Usage, got.Usage, "%s --%s usage drifted from scan's", cmd.name, name)
			assert.Equalf(t, want.Value.Type(), got.Value.Type(), "%s --%s type", cmd.name, name)
		}
		// The --session / --session-file spellings normalize onto --auth /
		// --auth-file on every command that has them.
		assert.Samef(t, cmd.flags.Lookup("auth"), cmd.flags.Lookup("session"), "%s --session", cmd.name)
		assert.Samef(t, cmd.flags.Lookup("auth-file"), cmd.flags.Lookup("session-file"), "%s --session-file", cmd.name)
	}
	require.NotNil(t, scanRequestCmd.Flags().ShorthandLookup("H"), "scan-request -H")
}

// The flags bind the same globals `vigolium scan` reads.
func TestRegisterLightweightScanTuningFlagsBindsGlobals(t *testing.T) {
	resetScanTuningGlobals(t)
	fs := pflag.NewFlagSet("scan-url", pflag.ContinueOnError)
	registerLightweightScanTuningFlags(fs)
	require.NoError(t, fs.Parse([]string{
		"--intensity", "quick", "--scanning-max-duration", "90s", "--scope-origin", "strict",
		"--oast-url", "https://{nonce}.cb.example", "--auth", "a:Cookie:s=1", "--session-file", "admin.yaml",
	}))
	assert.Equal(t, "quick", globalIntensity)
	assert.Equal(t, 90*time.Second, globalScanningMaxDuration)
	assert.Equal(t, "strict", globalScopeOrigin)
	assert.Equal(t, "https://{nonce}.cb.example", scanOpts.OastURL)
	assert.Equal(t, []string{"a:Cookie:s=1"}, scanOpts.AuthInline)
	assert.Equal(t, []string{"admin.yaml"}, scanOpts.AuthFiles)
}

// Auth and intensity need the Runner (session hydration, profile + module
// tiers); the scan budget and a fixed OAST URL are honoured on the direct path.
func TestNeedsRunnerScanTuningFlags(t *testing.T) {
	cases := []struct {
		name string
		set  func()
		want bool
	}{
		{"--auth", func() { scanOpts.AuthInline = []string{"a:Cookie:s=1"} }, true},
		{"--auth-file", func() { scanOpts.AuthFiles = []string{"admin.yaml"} }, true},
		{"--intensity", func() { globalIntensity = "quick" }, true},
		{"--scanning-max-duration", func() { globalScanningMaxDuration = time.Minute }, false},
		{"--oast-url", func() { scanOpts.OastURL = "https://cb.example" }, false},
		{"--scope-origin", func() { globalScopeOrigin = "strict" }, false},
		{"-H", func() { scanURLHeaders = []string{"Cookie: a=1"} }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetLightweightIOGlobals()
			t.Cleanup(resetLightweightIOGlobals)
			resetScanTuningGlobals(t)
			tc.set()
			assert.Equal(t, tc.want, needsRunnerScan())
		})
	}
}

// scan-request -H replaces every same-named captured header, else appends.
func TestApplyRequestHeaderOverrides(t *testing.T) {
	raw := "POST /api HTTP/1.1\r\nHost: app.example\r\nCookie: a=0\r\ncookie: stale=1\r\nContent-Length: 2\r\n\r\n{}"
	rr, err := httpmsg.ParseRawRequestWithURL(raw, "http://app.example")
	require.NoError(t, err)

	got, err := applyRequestHeaderOverrides(rr, []string{"Cookie: a=1", "X-Trace: t1", "x-trace: t2"})
	require.NoError(t, err)
	req := got.Request()
	values := func(name string) []string {
		var out []string
		for _, h := range req.Headers() {
			if strings.EqualFold(h.Name, name) {
				out = append(out, h.Value)
			}
		}
		return out
	}
	assert.Equal(t, []string{"a=1"}, values("Cookie"), "-H replaces every captured Cookie")
	assert.Equal(t, []string{"t2"}, values("X-Trace"), "a header the capture lacks is appended; the last -H wins")
	assert.Equal(t, "app.example", req.Header("Host"))
	assert.Equal(t, "{}", string(req.Body()), "the body survives")
	assert.Equal(t, "POST", req.Method())
	assert.Equal(t, rr.Target(), got.Target())

	same, err := applyRequestHeaderOverrides(rr, nil)
	require.NoError(t, err)
	assert.Same(t, rr, same, "no -H leaves the capture untouched")

	_, err = applyRequestHeaderOverrides(rr, []string{"no-colon"})
	require.Error(t, err)
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
}

// buildPhaseOptions hands every tuning flag to the Runner path.
func TestBuildPhaseOptionsCopiesTuning(t *testing.T) {
	resetLightweightIOGlobals()
	t.Cleanup(resetLightweightIOGlobals)
	resetScanTuningGlobals(t)
	t.Setenv("HOME", t.TempDir())
	swapGlobal(t, &globalDB, filepath.Join(t.TempDir(), "a8.sqlite"))
	resetDBCacheForTest()
	t.Cleanup(resetDBCacheForTest)

	globalIntensity = " quick "
	globalScanningMaxDuration = 5 * time.Minute
	globalScopeOrigin = "strict"
	scanOpts.OastURL = "https://{nonce}.cb.example"
	scanOpts.AuthFiles = []string{"admin.yaml"}
	scanOpts.AuthInline = []string{"user:Cookie:s=1"}
	scanURLHeaders = []string{"X-Api-Key: k"}

	opts, err := buildPhaseOptions("http://app.example/")
	require.NoError(t, err)
	assert.Equal(t, "quick", opts.Intensity)
	assert.Equal(t, 5*time.Minute, opts.ScanMaxDuration)
	assert.Equal(t, "strict", opts.ScopeOriginMode)
	assert.Equal(t, "https://{nonce}.cb.example", opts.OastURL)
	assert.Equal(t, []string{"admin.yaml"}, opts.AuthFiles)
	assert.Equal(t, []string{"user:Cookie:s=1"}, opts.AuthInline)
	assert.Equal(t, []string{"X-Api-Key: k"}, opts.Headers)
}

// The Runner path resolves --intensity through the shared resolver: the
// profile applies, the quick intensity's module-tier ceiling narrows the
// selection, and the settings overrides land.
func TestResolveLightweightScanOptionsIntensity(t *testing.T) {
	resetLightweightIOGlobals()
	t.Cleanup(resetLightweightIOGlobals)
	resetScanTuningGlobals(t)
	t.Setenv("HOME", t.TempDir())
	swapGlobal(t, &globalDB, filepath.Join(t.TempDir(), "a8.sqlite"))
	resetDBCacheForTest()
	t.Cleanup(resetDBCacheForTest)
	profiles := writeIntensityProfiles(t)

	resolve := func(intensity string) (*runner.ModuleSelection, string, bool) {
		globalIntensity = intensity
		globalScanningMaxDuration = 2 * time.Minute
		scanOpts.OastURL = "https://cb.example"
		opts, err := buildPhaseOptions("http://app.example/")
		require.NoError(t, err)
		settings := resolveTestSettings(t, profiles)
		require.NoError(t, resolveLightweightScanOptions(settings, opts))
		assert.Equal(t, "https://cb.example", settings.OAST.OastURL)
		assert.Equal(t, (2 * time.Minute).String(), settings.ScanningPace.MaxDuration)
		sel := runner.FilterModulesForRun(opts, settings)
		return &sel, opts.ScanningProfile, opts.SkipPortSweep
	}

	quick, profile, skipSweep := resolve("quick")
	assert.Equal(t, "quick", profile, "the intensity's profile applied")
	assert.Equal(t, modules.TierRankModerate, quick.TierCeiling, "quick caps modules at the moderate tier")
	assert.True(t, skipSweep, "a single request is never port-swept")

	none, profile, skipSweep := resolve("")
	assert.Empty(t, profile, "no intensity, no profile")
	assert.False(t, skipSweep, "without an intensity the options are left as typed")
	assert.Less(t, len(quick.Active), len(none.Active), "quick runs fewer active modules than the default ceiling")

	deep, _, skipSweep := resolve("deep")
	assert.True(t, skipSweep, "deep does not port-sweep a single request")
	assert.GreaterOrEqual(t, len(deep.Active), len(quick.Active))
}

func TestValidateLightweightScanTuning(t *testing.T) {
	resetScanTuningGlobals(t)
	require.NoError(t, validateLightweightScanTuning())

	globalIntensity = "extreme"
	err := validateLightweightScanTuning()
	require.Error(t, err)
	assert.Equal(t, ExitUsageError, classifyExitCode(err))

	globalIntensity = "Deep"
	require.NoError(t, validateLightweightScanTuning())

	globalScanningMaxDuration = -time.Second
	err = validateLightweightScanTuning()
	require.Error(t, err)
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
}
