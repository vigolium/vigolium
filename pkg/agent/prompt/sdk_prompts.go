package prompt

import (
	"os"
	"path/filepath"

	"github.com/vigolium/vigolium/internal/paths"
	"github.com/vigolium/vigolium/public"
	"go.uber.org/zap"
)

const browserPromptSectionFile = "autopilot-browser-section.md"

// LoadBrowserPromptSection loads the optional browser instructions section that
// gets appended to the autopilot system prompt when agent-browser is enabled.
// Returns empty string when the file is not found (non-fatal).
func LoadBrowserPromptSection() string {
	// 1. User override: ~/.vigolium/prompts/autopilot-browser-section.md
	if userDir := paths.VigoliumPath("prompts"); userDir != "" {
		path := filepath.Join(userDir, browserPromptSectionFile)
		if data, err := os.ReadFile(path); err == nil {
			zap.L().Debug("loaded browser prompt section from user file", zap.String("path", path))
			return string(data)
		}
	}

	// 2. Embedded
	embeddedPath := "presets/prompts/autopilot/" + browserPromptSectionFile
	if data, err := public.StaticFS.ReadFile(embeddedPath); err == nil {
		return string(data)
	}

	return ""
}
