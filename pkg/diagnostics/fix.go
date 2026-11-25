package diagnostics

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/audit/bin"
	"github.com/vigolium/vigolium/pkg/cftbrowser"
	"github.com/vigolium/vigolium/pkg/nucleitemplates"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// fixOut is where installation progress goes. It is stderr, not stdout, and
// that is the whole point.
//
// This package is reached two ways. Interactively it is `vigolium doctor --fix`,
// where the chatter is the user's feedback. It is also `vigolium init`, which
// installs nuclei templates and Chrome for Testing as part of setup (scans
// themselves fetch them lazily, per phase). That may be running under `--events
// ndjson`, whose contract is that stdout carries the event stream and nothing
// else, or it may be `doctor --fix --json`, which prints one JSON document.
// Every line below was a bare fmt.Printf and every subprocess inherited
// os.Stdout, so the very first run a new user or a CI job makes injected four
// non-JSON lines plus a git clone's output into a machine stream — at exactly
// the moment a consumer has no prior output to recover from.
//
// Routing all of it to stderr costs the interactive path nothing (a terminal
// shows both) and makes the machine path correct by construction. Mirrors
// cftbrowser.progressOut, which was fixed the same way for the same reason.
var fixOut io.Writer = os.Stderr

// fixf writes one progress line to fixOut. A failed write is dropped: this is
// progress chatter, and losing a line to a closed stderr must not fail an
// install that is otherwise working.
func fixf(format string, args ...any) {
	_, _ = fmt.Fprintf(fixOut, format, args...)
}

// FixResult holds the outcome of a single fix attempt.
type FixResult struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Success bool   `json:"success"`
	Message string `json:"message"`
	// Skipped marks an install that was not attempted because it pipes a
	// vendor installer into a shell and consent was not given.
	Skipped bool `json:"skipped,omitempty"`
	// Planned marks a --dry-run row: the install that would run, how, where
	// to and roughly how large.
	Planned     bool   `json:"planned,omitempty"`
	Method      string `json:"method,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	Size        string `json:"size,omitempty"`
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
	// VendorScript marks an install that runs (or may bootstrap) a vendor
	// script piped into a shell, or installs global agent tooling. It runs
	// only with consent: named in --only, --yes, or a TTY confirmation.
	VendorScript bool
	// Refreshable items re-install when named in --only even if their check
	// passes (`doctor --fix --only nuclei` refreshes the templates).
	Refreshable bool
	// Method, Destination and Size describe the install for --dry-run. Size
	// is an approximate constant, or "unknown".
	Method      string
	Destination func(settings *config.Settings) string
	Size        string
}

// FixOptions governs consent for VendorScript installs.
type FixOptions struct {
	// AssumeYes consents to every vendor install (doctor --fix --yes).
	AssumeYes bool
	// Confirm, when set, is asked per vendor install not named in --only
	// (an interactive prompt); nil means no consent.
	Confirm func(label, source string) bool
	// DryRun lists the installs that would run (Planned rows) and runs none.
	DryRun bool
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

// ResolveFixKey is the exported form of resolveAlias: it maps a user-supplied
// --only token (e.g. "chrome", "nuclei") to its canonical fix key (e.g.
// "chromium", "nuclei-templates"). The doctor CLI uses it to render a focused
// view of just the components named in --only.
func ResolveFixKey(name string) string {
	return resolveAlias(name)
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
//  3. vigolium-audit — prefetches the pinned helper (audit_external builds
//     only; embedded builds never report it as fixable).
//  4. claude — Audit Path A (claude+audit).
//  5. agent-browser — Olium-based modes (autopilot + swarm).
//  6. pi — the runtime piolium loads into; Audit Path B.
//  7. piolium — Audit Path B. Installs the @vigolium/piolium Pi extension
//     via `pi install npm:@vigolium/piolium`, self-resolving pi if missing.
func fixRegistry() []fixableItem {
	return []fixableItem{
		{
			Key:         "nuclei-templates",
			Label:       "Nuclei Templates",
			Source:      "release archive from github.com/projectdiscovery/nuclei-templates (pinned by known_issue_scan.templates_version)",
			Refreshable: true,
			IsFailing: func(r *Report) bool {
				return r.NucleiTemplates != nil && r.NucleiTemplates.Status != StatusOK
			},
			Fix:         fixNucleiTemplates,
			Method:      "download",
			Destination: func(s *config.Settings) string { return config.ContractPath(nucleiTemplatesDir(s)) },
			Size:        "~100 MB",
		},
		{
			Key:     "chromium",
			Label:   "Chromium (Chrome for Testing)",
			Source:  "Chrome for Testing (downloads via cftbrowser to local cache)",
			ToolKey: "chromium",
			Fix:     fixChromium,
			Method:  "download",
			Destination: func(*config.Settings) string {
				return "~/.cache/vigolium/"
			},
			Size: "~150 MB",
		},
		{
			VendorScript: true,
			Key:          "bun",
			Label:        "Bun",
			Source:       "curl -fsSL https://bun.sh/install | bash",
			ToolKey:      "bun",
			Fix:          fixBun,
			Method:       "vendor installer script",
			Destination:  func(*config.Settings) string { return "~/.bun/" },
			Size:         "~100 MB",
		},
		{
			// Only an audit_external build has anything to fix here: it
			// downloads the pinned helper, and --fix prefetches it so the
			// first audit run does not. Embedded builds extract at check time.
			Key:    "vigolium-audit",
			Label:  "vigolium-audit helper",
			Source: "download the pinned helper from " + bin.BaseURLEnv + " (audit_external builds)",
			IsFailing: func(r *Report) bool {
				c := r.EmbeddedBinaries["vigolium-audit"]
				return bin.External() && c != nil && c.Status != StatusOK
			},
			Fix:    fixAuditHelper,
			Method: "download",
			Size:   "unknown",
		},
		{
			VendorScript: true,
			Key:          "claude",
			Label:        "Claude Code",
			Source:       "curl -fsSL https://claude.ai/install.sh | bash",
			ToolKey:      "claude",
			Fix:          fixClaude,
			Method:       "vendor installer script",
			Size:         "unknown",
		},
		{
			VendorScript: true,
			Key:          "agent-browser",
			Label:        "agent-browser",
			Source:       "bun install --global agent-browser  (or npm install -g agent-browser)",
			ToolKey:      "agent-browser",
			Fix:          fixAgentBrowser,
			Method:       "global package install (bun or npm)",
			Size:         "unknown",
		},
		{
			VendorScript: true,
			Key:          "pi",
			Label:        "Pi (pi-coding-agent)",
			Source:       "bun add -g @earendil-works/pi-coding-agent  (or npm install -g …)",
			ToolKey:      "pi",
			Fix:          fixPi,
			Method:       "global package install (bun or npm)",
			Size:         "unknown",
		},
		{
			VendorScript: true,
			Key:          "piolium",
			Label:        "Piolium (Pi extension)",
			Source:       "pi install npm:@vigolium/piolium",
			IsFailing: func(r *Report) bool {
				return r.Piolium != nil && r.Piolium.Status != StatusOK
			},
			// No DependsOn — fixPiolium self-resolves pi (and the JS
			// package manager) so it works standalone under
			// `--fix --only piolium` even on a bare host.
			Fix:    fixPiolium,
			Method: "pi extension install",
			Size:   "unknown",
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
//
// Installs that pipe a vendor script into a shell or add global agent tooling
// (VendorScript: bun, claude, agent-browser, pi, piolium) are skipped unless
// named in only; RunFixesWith adds --yes and an interactive confirmation.
func RunFixes(ctx context.Context, report *Report, settings *config.Settings, only []string) []FixResult {
	return RunFixesWith(ctx, report, settings, only, FixOptions{})
}

// RunFixesWith is RunFixes with consent options for vendor installs.
func RunFixesWith(ctx context.Context, report *Report, settings *config.Settings, only []string, opts FixOptions) []FixResult {
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
		refresh := item.Refreshable && onlySet[item.Key]
		if isFailing != nil && !isFailing(report) && !refresh {
			continue
		}

		if opts.DryRun {
			plan := FixResult{Key: item.Key, Label: item.Label, Planned: true, Method: item.Method,
				Source: item.Source, Size: item.Size, Message: "would install"}
			if plan.Size == "" {
				plan.Size = "unknown"
			}
			if item.Destination != nil {
				plan.Destination = item.Destination(settings)
			}
			if item.VendorScript && !onlySet[item.Key] && !opts.AssumeYes {
				plan.Message = fmt.Sprintf("would ask before running `%s` (name it with --only %s or pass --yes)", item.Source, item.Key)
			}
			results = append(results, plan)
			continue
		}

		// A vendor installer piped into a shell, or global agent tooling,
		// runs only with consent: named in --only, --yes, or confirmed.
		if item.VendorScript && !onlySet[item.Key] && !opts.AssumeYes &&
			(opts.Confirm == nil || !opts.Confirm(item.Label, item.Source)) {
			results = append(results, FixResult{
				Key:     item.Key,
				Label:   item.Label,
				Skipped: true,
				Message: fmt.Sprintf("skipped: runs `%s`; name it with --only %s or pass --yes", item.Source, item.Key),
			})
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

		fixf("  %s %s %s\n",
			terminal.BoldCyan(terminal.SymbolStart),
			terminal.White("Installing"),
			terminal.BoldCyan(item.Label+"..."),
		)
		if item.Source != "" {
			fixf("    %s %s\n", terminal.Gray("$"), terminal.Gray(item.Source))
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
	// Return LookPath's resolved path, not the candidate: on Windows the file
	// on disk is bun.exe, and LookPath appends the PATHEXT extension it matched.
	// Handing back the extensionless candidate would fail at exec time.
	if p, err := exec.LookPath(candidate); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("bun not found in PATH or ~/.bun/bin/bun")
}

// runVendorInstaller runs a third-party install script, picking the flavor that
// exists on this host: the POSIX `curl … | bash` one-liner everywhere, and the
// vendor's PowerShell installer on Windows (a stock Windows box has neither
// bash nor curl on PATH, so the POSIX form fails with a bare
// "bash: file not found" that says nothing about what to do next).
func runVendorInstaller(ctx context.Context, label, posixURL, windowsURL string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// -NoProfile keeps a user's profile from altering the install, and
		// irm|iex is the invocation both vendors document for Windows.
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
			"-Command", "irm "+windowsURL+" | iex")
	} else {
		cmd = exec.CommandContext(ctx, "bash", "-c", "curl -fsSL "+posixURL+" | bash")
	}
	cmd.Stdout = fixOut
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s install script failed: %w", label, err)
	}
	return nil
}

func fixBun(ctx context.Context, _ *config.Settings) error {
	if err := runVendorInstaller(ctx, "bun", "https://bun.sh/install", "https://bun.sh/install.ps1"); err != nil {
		return err
	}
	// Verify installation.
	if _, err := findBun(); err != nil {
		return fmt.Errorf("bun installed but not found: %w", err)
	}
	return nil
}

func fixClaude(ctx context.Context, _ *config.Settings) error {
	return runVendorInstaller(ctx, "claude", "https://claude.ai/install.sh", "https://claude.ai/install.ps1")
}

func fixChromium(ctx context.Context, _ *config.Settings) error {
	if !cftbrowser.IsSupported() {
		// No CfT build to download: EnsureBrowser resolves the system browser.
		binPath, err := cftbrowser.EnsureBrowser(ctx, nil)
		if err != nil {
			return err
		}
		fixf("    Using system Chromium (no Chrome for Testing build for %s): %s\n", cftbrowser.Platform(), binPath)
		return nil
	}
	binPath, err := cftbrowser.EnsureBrowser(ctx, nil)
	if err != nil {
		return fmt.Errorf("chrome for Testing download failed: %w", err)
	}
	fixf("    Chrome for Testing installed: %s\n", binPath)
	return nil
}

func fixNucleiTemplates(ctx context.Context, settings *config.Settings) error {
	dir := nucleiTemplatesDir(settings)
	pin := nucleitemplates.Pin{}
	if settings != nil {
		pin = nucleitemplates.Pin{Version: settings.KnownIssueScan.TemplatesVersion, SHA256: settings.KnownIssueScan.TemplatesSHA256}
	}
	m, err := installTemplates(ctx, dir, pin)
	if err != nil {
		return err
	}
	fixf("    nuclei-templates %s installed at %s (sha256 %s)\n", m.Version, config.ContractPath(dir), shortDigest(m.SHA256))
	return nil
}

// installTemplates is nucleitemplates.Install, replaceable in tests.
var installTemplates = nucleitemplates.Install

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
	fixf("    %s no bun or npm found — bootstrapping bun\n",
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
	cmd.Stdout = fixOut
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
	cmd.Stdout = fixOut
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pi install %s failed: %w", pioliumPiPackage, err)
	}
	if err := piolium.Diagnose(); err != nil {
		return fmt.Errorf("piolium installed but verification failed: %w", err)
	}
	return nil
}

// fixAuditHelper downloads, verifies and caches the pinned vigolium-audit
// helper of an audit_external build.
func fixAuditHelper(ctx context.Context, _ *config.Settings) error {
	path, err := bin.PathContext(ctx)
	if err != nil {
		return err
	}
	fixf("    %s %s\n", terminal.Gray("installed"), terminal.Gray(config.ContractPath(path)))
	return nil
}
