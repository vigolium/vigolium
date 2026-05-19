package piolium

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/archon"
)

// pioliumFixture is one captured piolium output tree under test/testdata/piolium-output/.
// Each entry pins the expected repo name, audit mode, and minimum finding
// count so per-fixture regressions are easy to spot. Add new fixtures by
// dropping a piolium output directory under test/testdata/piolium-output/
// and appending here.
type pioliumFixture struct {
	name        string // subdir name under test/testdata/piolium-output/
	wantRepo    string
	wantMode    string
	minFindings int
}

var pioliumFixtures = []pioliumFixture{
	{name: "vercel-skills", wantRepo: "vercel-labs/skills", wantMode: "deep", minFindings: 14},
	{name: "shopify-cli", wantRepo: "shopify/cli", wantMode: "deep", minFindings: 12},
}

// fixturePath resolves test/testdata/piolium-output/<name> by walking up
// from the package dir until it finds the repo root marker (go.mod).
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			fixture := filepath.Join(dir, "test", "testdata", "piolium-output", name)
			if _, err := os.Stat(fixture); err == nil {
				return fixture
			}
			t.Fatalf("fixture not found at %s", fixture)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("repo root not found from %s", dir)
		}
		dir = parent
	}
}

func TestPioliumFixture_ParsesViaSharedParser(t *testing.T) {
	for _, fx := range pioliumFixtures {
		t.Run(fx.name, func(t *testing.T) {
			result, err := archon.ParseAuditFolder(fixturePath(t, fx.name))
			if err != nil {
				t.Fatalf("ParseAuditFolder: %v", err)
			}
			if len(result.State.Audits) == 0 {
				t.Fatalf("expected at least one audit entry in state")
			}
			if got := len(result.RawFindings); got < fx.minFindings {
				t.Errorf("expected at least %d findings, got %d", fx.minFindings, got)
			}
			if result.RepoName != fx.wantRepo {
				t.Errorf("RepoName = %q, want %q", result.RepoName, fx.wantRepo)
			}
			if got := result.State.Audits[0].Mode; got != fx.wantMode {
				t.Errorf("audit mode = %q, want %q", got, fx.wantMode)
			}
		})
	}
}

func TestPioliumFixture_FindingsTagAsPiolium(t *testing.T) {
	src := piolium_src()
	for _, fx := range pioliumFixtures {
		t.Run(fx.name, func(t *testing.T) {
			result, err := archon.ParseAuditFolder(fixturePath(t, fx.name))
			if err != nil {
				t.Fatalf("ParseAuditFolder: %v", err)
			}
			findings := archon.BuildFindingsWithSource(result.RawFindings, "audit-1", "scan-uuid", "proj-uuid", result.RepoName, src)
			if len(findings) == 0 {
				t.Fatalf("expected non-zero db findings")
			}
			for i, f := range findings {
				if f.ModuleID == "" {
					t.Errorf("findings[%d]: empty module_id", i)
				}
				hasTag := false
				for _, tag := range f.Tags {
					if tag == "piolium" {
						hasTag = true
						break
					}
				}
				if !hasTag {
					t.Errorf("findings[%d] (%s): missing piolium tag, got %v", i, f.ModuleID, f.Tags)
				}
				if f.ModuleID[:8] != "piolium:" {
					t.Errorf("findings[%d]: expected module_id to start with piolium:, got %q", i, f.ModuleID)
				}
			}
		})
	}
}

// Piolium frontmatter is lowercase YAML (severity: high). The parser
// should populate severity for every parsed finding across all fixtures.
func TestPioliumFixture_SeverityPopulatedFromFrontmatter(t *testing.T) {
	for _, fx := range pioliumFixtures {
		t.Run(fx.name, func(t *testing.T) {
			result, err := archon.ParseAuditFolder(fixturePath(t, fx.name))
			if err != nil {
				t.Fatalf("ParseAuditFolder: %v", err)
			}
			missing := 0
			for _, f := range result.RawFindings {
				if f.Severity == "" {
					missing++
				}
			}
			if missing > 0 {
				t.Errorf("%d/%d findings have empty severity — lowercase frontmatter not picked up?",
					missing, len(result.RawFindings))
			}
		})
	}
}

// sandboxPi isolates a test from a developer's real Pi/piolium setup
// AND from the canonical system install at /opt/piolium — resets HOME,
// clears PIOLIUM_HOME and the user-home auto-probe opt-in, and
// redirects the auto-probe at a non-existent temp dir so detection
// runs against the per-user fallback layout unless the test explicitly
// opts into a system or user-home install.
func sandboxPi(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(HomeEnvVar, "")
	t.Setenv(UserHomeAutoprobeEnvVar, "")
	old := defaultHomeProbe
	defaultHomeProbe = filepath.Join(home, "no-such-piolium")
	t.Cleanup(func() { defaultHomeProbe = old })
	return home
}

// withDefaultHomeProbe redirects the canonical install probe to a
// caller-controlled path for the duration of the test. Production
// callers must never write to defaultHomeProbe directly.
func withDefaultHomeProbe(t *testing.T, dir string) {
	t.Helper()
	old := defaultHomeProbe
	defaultHomeProbe = dir
	t.Cleanup(func() { defaultHomeProbe = old })
}

func TestEnsurePiInstalled_MissingFile(t *testing.T) {
	sandboxPi(t)
	if err := EnsurePiInstalled(); err == nil {
		t.Fatalf("expected error when ~/.pi/agent/settings.json is missing")
	}
}

func TestEnsurePiInstalled_PackageNotRegistered(t *testing.T) {
	home := sandboxPi(t)

	piDir := filepath.Join(home, ".pi", "agent")
	if err := os.MkdirAll(piDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	settings := map[string]any{"packages": []string{"some-other-extension"}}
	data, _ := json.Marshal(settings)
	if err := os.WriteFile(filepath.Join(piDir, "settings.json"), data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := EnsurePiInstalled(); err == nil {
		t.Fatalf("expected error when piolium is not in packages list")
	}
}

func TestEnsurePiInstalled_PackageRegistered(t *testing.T) {
	home := sandboxPi(t)

	piDir := filepath.Join(home, ".pi", "agent")
	if err := os.MkdirAll(piDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Test both local-path and git URL forms.
	cases := []map[string]any{
		{"packages": []string{"/Users/somebody/Desktop/external/piolium"}},
		{"packages": []string{"git:git@github.com:vigolium/piolium.git"}},
		{"packages": []string{"@vigolium/piolium@1.2.3"}},
	}
	for _, settings := range cases {
		data, _ := json.Marshal(settings)
		if err := os.WriteFile(filepath.Join(piDir, "settings.json"), data, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := EnsurePiInstalled(); err != nil {
			t.Fatalf("expected success for packages=%v, got: %v", settings["packages"], err)
		}
	}
}

// When PIOLIUM_HOME points at a self-contained install, EnsurePiInstalled
// must read $PIOLIUM_HOME/agent/settings.json — never the per-user
// ~/.pi/agent/settings.json — even if the latter exists with a different
// package list.
func TestEnsurePiInstalled_PioliumHome_Preferred(t *testing.T) {
	home := sandboxPi(t)

	// Per-user dir is wired up but does NOT register piolium — proves
	// the detection path doesn't fall through to it.
	userPiDir := filepath.Join(home, ".pi", "agent")
	if err := os.MkdirAll(userPiDir, 0o755); err != nil {
		t.Fatalf("mkdir user: %v", err)
	}
	userSettings, _ := json.Marshal(map[string]any{"packages": []string{"unrelated-extension"}})
	if err := os.WriteFile(filepath.Join(userPiDir, "settings.json"), userSettings, 0o644); err != nil {
		t.Fatalf("write user settings: %v", err)
	}

	pioliumHome := t.TempDir()
	systemAgentDir := filepath.Join(pioliumHome, "agent")
	if err := os.MkdirAll(systemAgentDir, 0o755); err != nil {
		t.Fatalf("mkdir system: %v", err)
	}
	systemSettings, _ := json.Marshal(map[string]any{"packages": []string{"git:git@github.com:vigolium/piolium.git"}})
	if err := os.WriteFile(filepath.Join(systemAgentDir, "settings.json"), systemSettings, 0o644); err != nil {
		t.Fatalf("write system settings: %v", err)
	}
	t.Setenv(HomeEnvVar, pioliumHome)

	if got := AgentDir(); got != systemAgentDir {
		t.Errorf("AgentDir() = %q, want %q", got, systemAgentDir)
	}
	if err := EnsurePiInstalled(); err != nil {
		t.Fatalf("expected success when PIOLIUM_HOME registers piolium, got: %v", err)
	}
}

// When PIOLIUM_HOME is set but the system install is incomplete
// (no settings.json), the error must blame PIOLIUM_HOME rather than
// suggesting the per-user `pi install` recipe.
func TestEnsurePiInstalled_PioliumHome_MissingSettings(t *testing.T) {
	sandboxPi(t)

	pioliumHome := t.TempDir()
	t.Setenv(HomeEnvVar, pioliumHome)

	err := EnsurePiInstalled()
	if err == nil {
		t.Fatalf("expected error when $PIOLIUM_HOME/agent/settings.json is missing")
	}
	if !strings.Contains(err.Error(), HomeEnvVar) {
		t.Errorf("expected error to reference %s, got: %v", HomeEnvVar, err)
	}
}

// Audit-only modes are accepted; operator commands that don't produce
// findings vigolium ingests are deliberately rejected so the audit
// pipeline isn't entered for read-only or wiring-check slash commands.
func TestIsValidMode_AcceptsAuditModes(t *testing.T) {
	for _, m := range []string{"lite", "balanced", "deep", "revisit", "confirm", "merge", "diff", "longshot"} {
		if !IsValidMode(m) {
			t.Errorf("expected %q to be a valid audit mode", m)
		}
	}
}

func TestIsValidMode_RejectsOperatorCommands(t *testing.T) {
	// status / smoke / export / learn are reachable via raw `pi -p
	// /piolium-<cmd>` but must not be dispatched through vigolium agent
	// piolium because they don't emit findings the importer can pick up.
	for _, m := range []string{"status", "smoke", "export", "learn", ""} {
		if IsValidMode(m) {
			t.Errorf("expected %q to be rejected at the audit-mode boundary", m)
		}
	}
}

func TestRuntimeEnv_NilWhenHomeUnset(t *testing.T) {
	t.Setenv(HomeEnvVar, "")
	if env := RuntimeEnv(); env != nil {
		t.Errorf("RuntimeEnv() with unset $PIOLIUM_HOME = %v, want nil", env)
	}
}

func TestRuntimeEnv_InjectsPiAgentDir(t *testing.T) {
	pioliumHome := t.TempDir()
	t.Setenv(HomeEnvVar, pioliumHome)

	env := RuntimeEnv()
	wantAgentDir := filepath.Join(pioliumHome, "agent")
	wantEntry := PiAgentDirEnvVar + "=" + wantAgentDir
	found := false
	for _, e := range env {
		if e == wantEntry {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("RuntimeEnv() = %v, missing %q", env, wantEntry)
	}
}

func TestHome_TrimsAndCleans(t *testing.T) {
	sandboxPi(t)
	t.Setenv(HomeEnvVar, "  /opt/piolium/  ")
	if got, want := Home(), "/opt/piolium"; got != want {
		t.Errorf("Home() = %q, want %q", got, want)
	}
	t.Setenv(HomeEnvVar, "   ")
	if got := Home(); got != "" {
		t.Errorf("Home() with blank env (and no system install) = %q, want empty", got)
	}
}

// When $PIOLIUM_HOME is unset but the canonical install path has an
// agent/ subdir, Home() must surface that path so operators don't have
// to remember to export the env var. The agent/ check is what stops a
// vanilla machine (no /opt/piolium at all) from short-circuiting.
func TestHome_AutoProbesDefaultPath(t *testing.T) {
	sandboxPi(t)
	probe := t.TempDir()
	if err := os.MkdirAll(filepath.Join(probe, "agent"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	withDefaultHomeProbe(t, probe)

	if got := Home(); got != probe {
		t.Errorf("Home() with system install present = %q, want %q", got, probe)
	}
}

func TestHome_AutoProbeSkipsWhenAgentDirMissing(t *testing.T) {
	sandboxPi(t)
	// Probe path exists but lacks the agent/ subdir — must NOT be
	// treated as an install.
	withDefaultHomeProbe(t, t.TempDir())
	if got := Home(); got != "" {
		t.Errorf("Home() with no agent/ under probe = %q, want empty", got)
	}
}

func TestHome_EnvOverridesAutoProbe(t *testing.T) {
	sandboxPi(t)
	probe := t.TempDir()
	if err := os.MkdirAll(filepath.Join(probe, "agent"), 0o755); err != nil {
		t.Fatalf("mkdir probe: %v", err)
	}
	withDefaultHomeProbe(t, probe)

	override := t.TempDir()
	t.Setenv(HomeEnvVar, override)

	if got := Home(); got != override {
		t.Errorf("Home() with env override = %q, want %q (env must beat auto-probe)", got, override)
	}
}

// Piolium's standalone launcher (bin/piolium.mjs) defaults
// PIOLIUM_HOME to ~/.piolium/. Vigolium auto-probes that path only
// when $VIGOLIUM_PIOLIUM_USERHOME is truthy — silently sharing the
// standalone-piolium tree by default would mix audit state across
// contexts. This test pins the default-off rule.
func TestHome_DoesNotAutoProbeUserHomePioliumByDefault(t *testing.T) {
	home := sandboxPi(t)
	userPiolium := filepath.Join(home, ".piolium")
	if err := os.MkdirAll(filepath.Join(userPiolium, "agent"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	settings, _ := json.Marshal(map[string]any{"packages": []string{"git:git@github.com:vigolium/piolium.git"}})
	if err := os.WriteFile(filepath.Join(userPiolium, "agent", "settings.json"), settings, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := Home(); got != "" {
		t.Errorf("Home() = %q, want empty — ~/.piolium/ must require explicit $%s opt-in", got, UserHomeAutoprobeEnvVar)
	}
}

// When $VIGOLIUM_PIOLIUM_USERHOME is truthy and a fully-formed
// install lives at $HOME/.piolium/agent, Home() must surface that
// path so detection and runtime dispatch line up with piolium's
// standalone-launcher convention.
func TestHome_AutoProbesUserHomeWhenOptedIn(t *testing.T) {
	home := sandboxPi(t)
	userPiolium := filepath.Join(home, ".piolium")
	if err := os.MkdirAll(filepath.Join(userPiolium, "agent"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv(UserHomeAutoprobeEnvVar, "1")

	if got := Home(); got != userPiolium {
		t.Errorf("Home() with %s=1 = %q, want %q", UserHomeAutoprobeEnvVar, got, userPiolium)
	}
}

// The opt-in must accept the same truthy spellings other vigolium
// boolean knobs do; falsy values stay default-off.
func TestHome_UserHomeOptInTruthyVariants(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "yes", "On"} {
		t.Run("truthy="+v, func(t *testing.T) {
			home := sandboxPi(t)
			if err := os.MkdirAll(filepath.Join(home, ".piolium", "agent"), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			t.Setenv(UserHomeAutoprobeEnvVar, v)
			if got := Home(); got != filepath.Join(home, ".piolium") {
				t.Errorf("Home() with %s=%q = %q, want user-home install", UserHomeAutoprobeEnvVar, v, got)
			}
		})
	}
	for _, v := range []string{"0", "false", "no", "off", "", "maybe"} {
		t.Run("falsy="+v, func(t *testing.T) {
			home := sandboxPi(t)
			if err := os.MkdirAll(filepath.Join(home, ".piolium", "agent"), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			t.Setenv(UserHomeAutoprobeEnvVar, v)
			if got := Home(); got != "" {
				t.Errorf("Home() with %s=%q = %q, want empty (opt-in must be explicit)", UserHomeAutoprobeEnvVar, v, got)
			}
		})
	}
}

// When a standalone install lives at ~/.piolium/ but the operator
// hasn't opted in, the registration error must mention the opt-in
// path rather than telling them to run `pi install` they don't need.
func TestEnsurePiInstalled_HintsAtUserHomeOptIn(t *testing.T) {
	home := sandboxPi(t)
	if err := os.MkdirAll(filepath.Join(home, ".piolium", "agent"), 0o755); err != nil {
		t.Fatalf("mkdir user-home install: %v", err)
	}
	piDir := filepath.Join(home, ".pi", "agent")
	if err := os.MkdirAll(piDir, 0o755); err != nil {
		t.Fatalf("mkdir pi: %v", err)
	}
	settings, _ := json.Marshal(map[string]any{"packages": []string{"unrelated"}})
	if err := os.WriteFile(filepath.Join(piDir, "settings.json"), settings, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := EnsurePiInstalled()
	if err == nil {
		t.Fatal("expected error when opt-in is off")
	}
	if !strings.Contains(err.Error(), UserHomeAutoprobeEnvVar) {
		t.Errorf("error must hint at %s, got: %v", UserHomeAutoprobeEnvVar, err)
	}
}

// $PIOLIUM_HOME must beat the user-home auto-probe even when both
// resolve — explicit env always wins.
func TestHome_PioliumHomeBeatsUserHomeOptIn(t *testing.T) {
	home := sandboxPi(t)
	if err := os.MkdirAll(filepath.Join(home, ".piolium", "agent"), 0o755); err != nil {
		t.Fatalf("mkdir user-home install: %v", err)
	}
	override := t.TempDir()
	t.Setenv(HomeEnvVar, override)
	t.Setenv(UserHomeAutoprobeEnvVar, "1")

	if got := Home(); got != override {
		t.Errorf("Home() with both PIOLIUM_HOME and user-home opt-in = %q, want %q", got, override)
	}
}

// /opt/piolium must beat the user-home auto-probe — system installs
// take precedence over the per-user tree even when both exist.
func TestHome_DefaultProbeBeatsUserHomeOptIn(t *testing.T) {
	home := sandboxPi(t)
	if err := os.MkdirAll(filepath.Join(home, ".piolium", "agent"), 0o755); err != nil {
		t.Fatalf("mkdir user-home install: %v", err)
	}
	probe := t.TempDir()
	if err := os.MkdirAll(filepath.Join(probe, "agent"), 0o755); err != nil {
		t.Fatalf("mkdir system install: %v", err)
	}
	withDefaultHomeProbe(t, probe)
	t.Setenv(UserHomeAutoprobeEnvVar, "1")

	if got := Home(); got != probe {
		t.Errorf("Home() with both system install and user-home opt-in = %q, want system install %q", got, probe)
	}
}

// EnsurePiInstalled must drive its settings.json lookup off the
// user-home install when the opt-in is set, mirroring the existing
// auto-probe behavior for /opt/piolium.
func TestEnsurePiInstalled_UserHomeOptIn_PackageRegistered(t *testing.T) {
	home := sandboxPi(t)
	userAgentDir := filepath.Join(home, ".piolium", "agent")
	if err := os.MkdirAll(userAgentDir, 0o755); err != nil {
		t.Fatalf("mkdir agent: %v", err)
	}
	settings, _ := json.Marshal(map[string]any{"packages": []string{"../package"}})
	if err := os.WriteFile(filepath.Join(userAgentDir, "settings.json"), settings, 0o644); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	t.Setenv(UserHomeAutoprobeEnvVar, "1")

	if err := EnsurePiInstalled(); err != nil {
		t.Fatalf("expected success when $%s opts into a registered ~/.piolium install, got: %v", UserHomeAutoprobeEnvVar, err)
	}
}

// The /opt/piolium auto-probe must also accept the canonical
// "../package" relative entry that piolium's installer writes — the
// install layout doesn't include the substring "piolium" in that
// path, so this exercises the resolves-to-package-dir fallback.
func TestEnsurePiInstalled_AutoProbe_RelativePackagePath(t *testing.T) {
	sandboxPi(t)
	probe := t.TempDir()
	systemAgentDir := filepath.Join(probe, "agent")
	if err := os.MkdirAll(systemAgentDir, 0o755); err != nil {
		t.Fatalf("mkdir agent: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(probe, "package"), 0o755); err != nil {
		t.Fatalf("mkdir package: %v", err)
	}
	settings, _ := json.Marshal(map[string]any{"packages": []string{"../package"}})
	if err := os.WriteFile(filepath.Join(systemAgentDir, "settings.json"), settings, 0o644); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	withDefaultHomeProbe(t, probe)

	if err := EnsurePiInstalled(); err != nil {
		t.Fatalf("expected success for canonical \"../package\" entry under auto-probed install, got: %v", err)
	}
}

// resolvesToPackageDir must NOT be tricked by remote-looking strings
// (git:..., npm specifiers, URLs) — those aren't filesystem paths and
// callers should fall back to the substring check.
func TestEnsurePiInstalled_RemoteSpecifiersDoNotResolveAsPaths(t *testing.T) {
	sandboxPi(t)
	probe := t.TempDir()
	systemAgentDir := filepath.Join(probe, "agent")
	if err := os.MkdirAll(systemAgentDir, 0o755); err != nil {
		t.Fatalf("mkdir agent: %v", err)
	}
	// Note: no "package" dir under probe — the path resolver must
	// not synthesize a hit from a remote-looking string.
	settings, _ := json.Marshal(map[string]any{"packages": []string{"@some-org/unrelated@1.2.3"}})
	if err := os.WriteFile(filepath.Join(systemAgentDir, "settings.json"), settings, 0o644); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	withDefaultHomeProbe(t, probe)

	if err := EnsurePiInstalled(); err == nil {
		t.Fatal("expected error — '@some-org/unrelated' must not be matched as the piolium package")
	}
}

// RuntimeEnv must inject PI_CODING_AGENT_DIR pointing at the
// user-home agent dir when the opt-in resolves there, so `pi`
// loads the right settings/skills/agents tree.
func TestRuntimeEnv_UserHomeOptIn(t *testing.T) {
	home := sandboxPi(t)
	if err := os.MkdirAll(filepath.Join(home, ".piolium", "agent"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv(UserHomeAutoprobeEnvVar, "1")

	wantEntry := PiAgentDirEnvVar + "=" + filepath.Join(home, ".piolium", "agent")
	found := false
	for _, e := range RuntimeEnv() {
		if e == wantEntry {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("RuntimeEnv() with user-home opt-in = %v, missing %q", RuntimeEnv(), wantEntry)
	}
}

// EnsurePiInstalled must drive its settings.json lookup off the
// auto-probed path when env is unset, so an operator who's installed
// piolium at /opt/piolium without exporting PIOLIUM_HOME still sees
// the system install rather than per-user ~/.pi/.
func TestEnsurePiInstalled_AutoProbe_PackageRegistered(t *testing.T) {
	sandboxPi(t)
	probe := t.TempDir()
	systemAgentDir := filepath.Join(probe, "agent")
	if err := os.MkdirAll(systemAgentDir, 0o755); err != nil {
		t.Fatalf("mkdir agent: %v", err)
	}
	systemSettings, _ := json.Marshal(map[string]any{"packages": []string{"git:git@github.com:vigolium/piolium.git"}})
	if err := os.WriteFile(filepath.Join(systemAgentDir, "settings.json"), systemSettings, 0o644); err != nil {
		t.Fatalf("write system settings: %v", err)
	}
	withDefaultHomeProbe(t, probe)

	if err := EnsurePiInstalled(); err != nil {
		t.Fatalf("expected success when auto-probe finds a registered piolium, got: %v", err)
	}
}

// withFakePiHelp installs a shell `pi` on PATH that emits the supplied
// help text on stdout when called as `pi -h`. Any other invocation
// exits 0 with no output, so callers don't have to special-case the
// audit subprocess path.
func withFakePiHelp(t *testing.T, helpText string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-pi shim requires a POSIX shell")
	}
	dir := t.TempDir()
	body := "#!/bin/sh\nif [ \"$1\" = \"-h\" ] || [ \"$1\" = \"--help\" ]; then\ncat <<'PI_HELP_EOF'\n" +
		helpText + "\nPI_HELP_EOF\nfi\nexit 0\n"
	path := filepath.Join(dir, "pi")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake pi: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestVerifyPiLoadedPiolium_PlmFlagsPresent(t *testing.T) {
	sandboxPi(t)
	withFakePiHelp(t,
		"  --plm-dir <value>           Default target directory for /piolium-* commands\n"+
			"  --plm-scan-limit <value>    Commit archaeology max commits\n")
	if err := VerifyPiLoadedPiolium(); err != nil {
		t.Fatalf("expected nil when --plm-* appears in pi -h, got: %v", err)
	}
}

func TestVerifyPiLoadedPiolium_NoPlmFlags(t *testing.T) {
	sandboxPi(t)
	withFakePiHelp(t,
		"Options:\n  --provider <name>    Provider name\n  --model <pattern>    Model pattern\n")
	err := VerifyPiLoadedPiolium()
	if err == nil {
		t.Fatalf("expected error when --plm-* flags are absent")
	}
	if !strings.Contains(err.Error(), "--plm-") {
		t.Errorf("error should mention --plm-* marker, got: %v", err)
	}
}

func TestVerifyPiLoadedPiolium_PiMissing(t *testing.T) {
	sandboxPi(t)
	t.Setenv("PATH", t.TempDir())
	if err := VerifyPiLoadedPiolium(); err == nil {
		t.Fatalf("expected error when pi is not on PATH")
	}
}

func TestDiagnose_PiMissing(t *testing.T) {
	sandboxPi(t)
	t.Setenv("PATH", t.TempDir())
	err := Diagnose()
	if err == nil {
		t.Fatalf("expected Diagnose error when pi is missing")
	}
	if !strings.Contains(err.Error(), "pi CLI not found") {
		t.Errorf("expected friendly missing-binary message, got: %v", err)
	}
}

func TestDiagnose_PackageMissing(t *testing.T) {
	home := sandboxPi(t)
	withFakePiHelp(t, "  --plm-dir <value>   piolium loaded\n")
	piDir := filepath.Join(home, ".pi", "agent")
	if err := os.MkdirAll(piDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	settings := map[string]any{"packages": []string{"some-other-extension"}}
	data, _ := json.Marshal(settings)
	if err := os.WriteFile(filepath.Join(piDir, "settings.json"), data, 0o644); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	if err := Diagnose(); err == nil {
		t.Fatalf("expected Diagnose error when piolium is not registered")
	}
}

func TestDiagnose_HelpMissingPlmFlags(t *testing.T) {
	// Settings says piolium is installed but pi -h doesn't show --plm-*
	// — the exact false-positive case the help-text probe was added for.
	home := sandboxPi(t)
	withFakePiHelp(t, "Options:\n  --provider <name>    Provider name\n")
	piDir := filepath.Join(home, ".pi", "agent")
	if err := os.MkdirAll(piDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	settings := map[string]any{"packages": []string{"git:git@github.com:vigolium/piolium.git"}}
	data, _ := json.Marshal(settings)
	if err := os.WriteFile(filepath.Join(piDir, "settings.json"), data, 0o644); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	err := Diagnose()
	if err == nil {
		t.Fatalf("expected Diagnose error when pi -h omits --plm-* flags")
	}
	if !strings.Contains(err.Error(), "--plm-") {
		t.Errorf("error should mention --plm-* marker, got: %v", err)
	}
}

func TestDefaultHarness_Identity(t *testing.T) {
	h := DefaultHarness()
	if h.Name != "piolium" {
		t.Errorf("harness name = %q, want piolium", h.Name)
	}
	if h.SourceFolder != "piolium" {
		t.Errorf("source folder = %q, want piolium", h.SourceFolder)
	}
	if h.SessionSubdir != "piolium-audit" {
		t.Errorf("session subdir = %q, want piolium-audit", h.SessionSubdir)
	}
	if h.EnvPrefix != "PIOLIUM_" {
		t.Errorf("env prefix = %q, want PIOLIUM_", h.EnvPrefix)
	}
}

// piolium_src wraps DefaultHarness's piolium FindingSource so the test reads
// naturally. Kept private — production code uses the helper in pkg/agent.
func piolium_src() archon.FindingSource {
	h := DefaultHarness()
	return archon.FindingSource{
		Mode:      h.DBMode,
		AgentName: h.DBAgentName,
		InputType: h.DBInputType,
		IDPrefix:  h.FindingIDPrefix,
		Tag:       h.FindingTag,
	}
}
