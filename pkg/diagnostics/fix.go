package diagnostics

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cftbrowser"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// FixResult holds the outcome of a single fix attempt.
type FixResult struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// fixableItem defines a fixable doctor check.
// If ToolKey is set, IsFailing defaults to checking r.Tools[ToolKey].
// Set IsFailing explicitly only for non-tool checks (e.g., nuclei-templates).
type fixableItem struct {
	Key       string
	Label     string
	Source    string // human-readable command/source rendered under the install header
	ToolKey   string // if set, used by default IsFailing check
	DependsOn []string
	IsFailing func(*Report) bool
	Fix       func(ctx context.Context, settings *config.Settings) error
}

// aliases maps short names to canonical fix keys.
var aliases = map[string]string{
	"chrome": "chromium",
	"nuclei": "nuclei-templates",
}

// resolveAlias returns the canonical key for a given name.
func resolveAlias(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if canonical, ok := aliases[name]; ok {
		return canonical
	}
	return name
}

// fixRegistry returns the ordered set of fixable doctor items. Order is
// significant: RunFixes walks this slice in sequence, so listing native-scan
// dependencies first ensures `vigolium doctor --fix` brings the deterministic
// scan path online before touching agentic-only components.
//
// JS-package-manager model: agent-browser, pi, and piolium are installed
// through a resolved JavaScript package manager — bun when present, else
// npm, else bun is bootstrapped via its curl installer. These fix functions
// are self-resolving (they call ensureJSPM internally) rather than carrying
// a DependsOn edge, so each works correctly under `--only` even on a host
// with neither bun nor npm.
//
// Sequence rationale:
//  1. nuclei-templates / chromium — Native scan dependencies, surfaced first.
//  2. bun — installed only when no npm is present (npm-equipped hosts use
//     npm for the global installs); `--only bun` force-installs regardless.
//  3. claude — Audit Path A (claude+audit).
//  4. agent-browser — Olium-based modes (autopilot + swarm).
//  5. pi — the runtime piolium loads into; Audit Path B.
//  6. piolium — Audit Path B. Installs the @vigolium/piolium Pi extension
//     via `pi install npm:@vigolium/piolium`, self-resolving pi if missing.
func fixRegistry() []fixableItem {
	return []fixableItem{
		{
			Key:    "nuclei-templates",
			Label:  "Nuclei Templates",
			Source: "git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates",
			IsFailing: func(r *Report) bool {
				return r.NucleiTemplates != nil && r.NucleiTemplates.Status != StatusOK
			},
			Fix: fixNucleiTemplates,
		},
		{
			Key:     "chromium",
			Label:   "Chromium (Chrome for Testing)",
			Source:  "Chrome for Testing (downloads via cftbrowser to local cache)",
			ToolKey: "chromium",
			Fix:     fixChromium,
		},
		{
			Key:     "bun",
			Label:   "Bun",
			Source:  "curl -fsSL https://bun.sh/install | bash",
			ToolKey: "bun",
			Fix:     fixBun,
		},
		{
			Key:     "claude",
			Label:   "Claude Code",
			Source:  "curl -fsSL https://claude.ai/install.sh | bash",
			ToolKey: "claude",
			Fix:     fixClaude,
		},
		{
			Key:     "agent-browser",
			Label:   "agent-browser",
			Source:  "bun install --global agent-browser  (or npm install -g agent-browser)",
			ToolKey: "agent-browser",
			Fix:     fixAgentBrowser,
		},
		{
			Key:     "pi",
			Label:   "Pi (pi-coding-agent)",
			Source:  "bun add -g @earendil-works/pi-coding-agent  (or npm install -g …)",
			ToolKey: "pi",
			Fix:     fixPi,
		},
		{
			Key:    "piolium",
			Label:  "Piolium (Pi extension)",
			Source: "pi install npm:@vigolium/piolium",
			IsFailing: func(r *Report) bool {
				return r.Piolium != nil && r.Piolium.Status != StatusOK
			},
			// No DependsOn — fixPiolium self-resolves pi (and the JS
			// package manager) so it works standalone under
			// `--fix --only piolium` even on a bare host.
			Fix: fixPiolium,
		},
	}
}

func toolFailing(r *Report, key string) bool {
	t, ok := r.Tools[key]
	return ok && t.Status != StatusOK
}

// HasFixableIssues reports whether the report contains any failing checks
// that the auto-fix harness knows how to handle. Drives the `--fix` hint
// in the doctor CLI — there's no point suggesting --fix when nothing in
// the report is fixable.
//
// pi and piolium are treated as optional when claude (Path A) is available
// — the audit mode already has a working driver, so a missing Path B alone
// should not trigger the "re-run with --fix" hint. A missing bun is also
// ignored when npm is present, since the JS installs fall back to npm.
func HasFixableIssues(r *Report) bool {
	if r == nil {
		return false
	}
	claudeOK := r.Tools["claude"] != nil && r.Tools["claude"].Status == StatusOK
	npmOK := npmAvailable(r)
	for _, item := range fixRegistry() {
		// pi + piolium are Path B only — optional when claude (Path A)
		// already provides audit mode, so a bare doctor shouldn't nag
		// `--fix` over them.
		if (item.Key == "piolium" || item.Key == "pi") && claudeOK {
			continue
		}
		// A missing bun is not a fixable problem when npm is present —
		// the JS installs fall back to npm and bun is never needed.
		if item.Key == "bun" && npmOK {
			continue
		}
		isFailing := item.IsFailing
		if isFailing == nil && item.ToolKey != "" {
			key := item.ToolKey
			isFailing = func(r *Report) bool { return toolFailing(r, key) }
		}
		if isFailing != nil && isFailing(r) {
			return true
		}
	}
	return false
}

// RunFixes attempts to fix failing checks. If only is non-empty, only those
// items (and their required dependencies) are fixed.
//
// pi and piolium are skipped by default when claude (Path A) is available —
// audit mode already has a working driver, so we don't want a bare `--fix`
// to pull in the Path B stack as well. Users who want both drivers can still
// opt in with `--fix --only piolium` (or `--only pi`).
//
// The standalone bun install is skipped by default when npm is present —
// npm-equipped hosts use npm for the global installs. `--only bun` force-
// installs bun regardless.
func RunFixes(ctx context.Context, report *Report, settings *config.Settings, only []string) []FixResult {
	registry := fixRegistry()

	// Resolve aliases in only list.
	onlySet := make(map[string]bool, len(only))
	for _, name := range only {
		onlySet[resolveAlias(name)] = true
	}

	// If only is specified, auto-include failing dependencies.
	if len(onlySet) > 0 {
		for _, item := range registry {
			if !onlySet[item.Key] {
				continue
			}
			for _, dep := range item.DependsOn {
				if !onlySet[dep] && toolFailing(report, dep) {
					onlySet[dep] = true
				}
			}
		}
	}

	claudeOK := report.Tools["claude"] != nil && report.Tools["claude"].Status == StatusOK
	npmOK := npmAvailable(report)

	failedDep := make(map[string]bool)
	var results []FixResult

	for _, item := range registry {
		if len(onlySet) > 0 && !onlySet[item.Key] {
			continue
		}
		// Skip pi/piolium auto-install when claude is available and the
		// user didn't explicitly request it — Path A already covers audit
		// mode. (fixPiolium still self-resolves pi when run via --only.)
		if (item.Key == "piolium" || item.Key == "pi") && claudeOK && !onlySet[item.Key] {
			continue
		}
		// Skip the standalone bun install when npm is present and the user
		// didn't explicitly ask for bun — the JS installs use npm instead.
		if item.Key == "bun" && npmOK && !onlySet["bun"] {
			continue
		}

		// Resolve IsFailing: use ToolKey-based default if no custom check.
		isFailing := item.IsFailing
		if isFailing == nil && item.ToolKey != "" {
			key := item.ToolKey
			isFailing = func(r *Report) bool { return toolFailing(r, key) }
		}
		if isFailing != nil && !isFailing(report) {
			continue
		}

		// Check dependencies.
		depFailed := false
		for _, dep := range item.DependsOn {
			if failedDep[dep] {
				results = append(results, FixResult{
					Key:     item.Key,
					Label:   item.Label,
					Success: false,
					Message: fmt.Sprintf("skipped: dependency %q failed to install", dep),
				})
				depFailed = true
				break
			}
		}
		if depFailed {
			continue
		}

		fmt.Printf("  %s %s %s\n",
			terminal.BoldCyan(terminal.SymbolStart),
			terminal.White("Installing"),
			terminal.BoldCyan(item.Label+"..."),
		)
		if item.Source != "" {
			fmt.Printf("    %s %s\n", terminal.Gray("$"), terminal.Gray(item.Source))
		}

		fixCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		err := item.Fix(fixCtx, settings)
		cancel()

		if err != nil {
			failedDep[item.Key] = true
			results = append(results, FixResult{
				Key:     item.Key,
				Label:   item.Label,
				Success: false,
				Message: fmt.Sprintf("failed: %v", err),
			})
		} else {
			results = append(results, FixResult{
				Key:     item.Key,
				Label:   item.Label,
				Success: true,
				Message: "installed",
			})
		}
	}

	return results
}

// findBun locates the bun binary, checking PATH first then the default install location.
func findBun() (string, error) {
	if p, err := exec.LookPath("bun"); err == nil {
		return p, nil
	}
	candidate := config.ExpandPath("~/.bun/bin/bun")
	if _, err := exec.LookPath(candidate); err == nil {
		return candidate, nil
	}
	return "", fmt.Errorf("bun not found in PATH or ~/.bun/bin/bun")
}

func fixBun(ctx context.Context, _ *config.Settings) error {
	cmd := exec.CommandContext(ctx, "bash", "-c", "curl -fsSL https://bun.sh/install | bash")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bun install script failed: %w", err)
	}
	// Verify installation.
	if _, err := findBun(); err != nil {
		return fmt.Errorf("bun installed but not found: %w", err)
	}
	return nil
}

func fixClaude(ctx context.Context, _ *config.Settings) error {
	cmd := exec.CommandContext(ctx, "bash", "-c", "curl -fsSL https://claude.ai/install.sh | bash")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("claude install script failed: %w", err)
	}
	return nil
}

func fixChromium(ctx context.Context, _ *config.Settings) error {
	if !cftbrowser.IsSupported() {
		return fmt.Errorf("chrome for Testing not available for %s/%s — install Chromium manually", runtime.GOOS, runtime.GOARCH)
	}
	binPath, err := cftbrowser.EnsureBrowser(ctx)
	if err != nil {
		return fmt.Errorf("chrome for Testing download failed: %w", err)
	}
	fmt.Printf("    Chrome for Testing installed: %s\n", binPath)
	return nil
}

func fixNucleiTemplates(ctx context.Context, settings *config.Settings) error {
	dir := nucleiTemplatesDir(settings)
	// --quiet suppresses the "Cloning into…", "remote: …", and
	// "Receiving/Resolving" progress chatter so `vigolium doctor --fix` and
	// the first-run setup show a single success line. Real errors still go
	// to stderr.
	cmd := exec.CommandContext(ctx, "git", "clone", "--quiet", "--depth", "1",
		"https://github.com/projectdiscovery/nuclei-templates.git", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}
	return nil
}

// findNpm locates the npm binary on PATH. npm ships with Node, so unlike
// bun there's no well-known fixed install location to fall back to.
func findNpm() (string, error) {
	if p, err := exec.LookPath("npm"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("npm not found in PATH")
}

// npmAvailable reports whether an npm-based package manager is usable. It
// prefers the doctor report's already-probed npm tool row and falls back to
// a fresh PATH lookup for callers without a populated report.
func npmAvailable(r *Report) bool {
	if r != nil {
		if t := r.Tools["npm"]; t != nil {
			return t.Status == StatusOK
		}
	}
	_, err := findNpm()
	return err == nil
}

// jsPM is a resolved JavaScript package manager used for global installs of
// agent-browser and pi. bun is preferred; npm is the fallback.
type jsPM struct {
	name string // "bun" or "npm"
	bin  string // resolved binary path
}

// resolveJSPM returns the package manager to use for global JS installs:
// bun when present (PATH or ~/.bun/bin), else npm when present. The bool is
// false when neither is available — the caller must bootstrap one.
func resolveJSPM() (jsPM, bool) {
	if p, err := findBun(); err == nil {
		return jsPM{name: "bun", bin: p}, true
	}
	if p, err := findNpm(); err == nil {
		return jsPM{name: "npm", bin: p}, true
	}
	return jsPM{}, false
}

// ensureJSPM resolves a package manager, bootstrapping bun via its curl
// installer only when neither bun nor npm is present. This keeps the
// agent-browser / pi / piolium fixes self-sufficient under `--only`, even
// on a host with no JS toolchain at all.
func ensureJSPM(ctx context.Context) (jsPM, error) {
	if pm, ok := resolveJSPM(); ok {
		return pm, nil
	}
	fmt.Printf("    %s no bun or npm found — bootstrapping bun\n",
		terminal.Gray(terminal.SymbolDot))
	if err := fixBun(ctx, nil); err != nil {
		return jsPM{}, fmt.Errorf("bootstrap bun: %w", err)
	}
	bun, err := findBun()
	if err != nil {
		return jsPM{}, fmt.Errorf("bun installed but not found: %w", err)
	}
	return jsPM{name: "bun", bin: bun}, nil
}

// installGlobal installs a package globally with the resolved package
// manager: `bun install --global <pkg>` or `npm install -g <pkg>`.
func (pm jsPM) installGlobal(ctx context.Context, pkg string) error {
	var cmd *exec.Cmd
	switch pm.name {
	case "bun":
		cmd = exec.CommandContext(ctx, pm.bin, "install", "--global", pkg)
	case "npm":
		cmd = exec.CommandContext(ctx, pm.bin, "install", "-g", pkg)
	default:
		return fmt.Errorf("unknown package manager %q", pm.name)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s global install %s failed: %w", pm.name, pkg, err)
	}
	return nil
}

// findPi locates the pi binary: PATH, the bun global bin (~/.bun/bin/pi),
// then the npm global prefix (`npm prefix -g` + /bin/pi). A freshly
// globally-installed pi often isn't on the current process PATH, so the
// explicit probes let the piolium step run in the same `--fix` pass.
func findPi(ctx context.Context) (string, error) {
	if p, err := exec.LookPath("pi"); err == nil {
		return p, nil
	}
	if p, err := exec.LookPath(config.ExpandPath("~/.bun/bin/pi")); err == nil {
		return p, nil
	}
	if npm, err := findNpm(); err == nil {
		if out, e := exec.CommandContext(ctx, npm, "prefix", "-g").Output(); e == nil {
			cand := filepath.Join(strings.TrimSpace(string(out)), "bin", "pi")
			if p, err := exec.LookPath(cand); err == nil {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("pi not found in PATH, ~/.bun/bin, or npm global bin")
}

// piPackage is the npm package providing the pi runtime.
const piPackage = "@earendil-works/pi-coding-agent"

// pioliumPiPackage is the specifier passed to `pi install`. pi accepts the
// `npm:<name>` form to pull an extension straight from the npm registry.
const pioliumPiPackage = "npm:@vigolium/piolium"

func fixAgentBrowser(ctx context.Context, _ *config.Settings) error {
	pm, err := ensureJSPM(ctx)
	if err != nil {
		return err
	}
	return pm.installGlobal(ctx, "agent-browser")
}

// fixPi installs the pi runtime globally via the resolved package manager,
// then verifies the binary is locatable.
func fixPi(ctx context.Context, _ *config.Settings) error {
	pm, err := ensureJSPM(ctx)
	if err != nil {
		return err
	}
	if err := pm.installGlobal(ctx, piPackage); err != nil {
		return err
	}
	if _, err := findPi(ctx); err != nil {
		return fmt.Errorf("pi installed but not found: %w", err)
	}
	return nil
}

// fixPiolium installs the @vigolium/piolium Pi extension. It self-resolves
// pi (installing it via the package manager when absent) so it works as a
// standalone `--fix --only piolium` even on a bare host, then registers the
// extension with `pi install npm:@vigolium/piolium` and verifies the wiring.
func fixPiolium(ctx context.Context, settings *config.Settings) error {
	piPath, err := findPi(ctx)
	if err != nil {
		if e := fixPi(ctx, settings); e != nil {
			return fmt.Errorf("pi prerequisite: %w", e)
		}
		if piPath, err = findPi(ctx); err != nil {
			return fmt.Errorf("pi installed but not found: %w", err)
		}
	}
	cmd := exec.CommandContext(ctx, piPath, "install", pioliumPiPackage)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pi install %s failed: %w", pioliumPiPackage, err)
	}
	if err := piolium.Diagnose(); err != nil {
		return fmt.Errorf("piolium installed but verification failed: %w", err)
	}
	return nil
}
