package diagnostics

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cftbrowser"
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

func fixRegistry() []fixableItem {
	return []fixableItem{
		{Key: "bun", Label: "Bun", ToolKey: "bun", Fix: fixBun},
		{Key: "claude", Label: "Claude Code", ToolKey: "claude", Fix: fixClaude},
		{Key: "chromium", Label: "Chromium (Chrome for Testing)", ToolKey: "chromium", Fix: fixChromium},
		{
			Key:   "nuclei-templates",
			Label: "Nuclei Templates",
			IsFailing: func(r *Report) bool {
				return r.NucleiTemplates != nil && r.NucleiTemplates.Status != StatusOK
			},
			Fix: fixNucleiTemplates,
		},
		{Key: "ast-grep", Label: "ast-grep", ToolKey: "ast-grep", DependsOn: []string{"bun"}, Fix: fixAstGrep},
		{Key: "agent-browser", Label: "agent-browser", ToolKey: "agent-browser", DependsOn: []string{"bun"}, Fix: fixAgentBrowser},
	}
}

func toolFailing(r *Report, key string) bool {
	t, ok := r.Tools[key]
	return ok && t.Status != StatusOK
}

// RunFixes attempts to fix failing checks. If only is non-empty, only those
// items (and their required dependencies) are fixed.
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

	failedDep := make(map[string]bool)
	var results []FixResult

	for _, item := range registry {
		if len(onlySet) > 0 && !onlySet[item.Key] {
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

		fmt.Printf("  ► Installing %s...\n", item.Label)

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
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1",
		"https://github.com/projectdiscovery/nuclei-templates.git", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}
	return nil
}

func fixAstGrep(ctx context.Context, _ *config.Settings) error {
	return bunInstallGlobal(ctx, "@ast-grep/cli")
}

func fixAgentBrowser(ctx context.Context, _ *config.Settings) error {
	return bunInstallGlobal(ctx, "agent-browser")
}

func bunInstallGlobal(ctx context.Context, pkg string) error {
	bunPath, err := findBun()
	if err != nil {
		return fmt.Errorf("bun not found, cannot install %s: %w", pkg, err)
	}
	cmd := exec.CommandContext(ctx, bunPath, "install", "--global", pkg)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bun install --global %s failed: %w", pkg, err)
	}
	return nil
}
