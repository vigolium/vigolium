package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/utils"
)

// runAuthPhase executes the browser-based authentication phase using agent-browser.
func (s *SwarmRunner) runAuthPhase(ctx context.Context, cfg SwarmConfig, targetURL string, sessionDir string) (string, error) {
	hostname := hostnameFromURL(targetURL)

	extra := map[string]string{
		"TargetURL": targetURL,
		"Hostname":  hostname,
	}
	if cfg.Credentials != "" {
		extra["Credentials"] = cfg.Credentials
	}
	if cfg.BrowserStartURL != "" {
		extra["BrowserStartURL"] = cfg.BrowserStartURL
	}
	if len(cfg.FocusRoutes) > 0 {
		if data, err := json.Marshal(cfg.FocusRoutes); err == nil {
			extra["FocusRoutes"] = string(data)
		}
	}
	if len(cfg.CredentialSets) > 0 {
		if data, err := json.Marshal(cfg.CredentialSets); err == nil {
			extra["CredentialSets"] = string(data)
		}
	}
	if utils.EnvTruthy(spitolas.EnvBrowserHeaded) {
		extra["BrowserHeaded"] = "1"
	}

	opts := Options{
		AgentName:      cfg.AgentName,
		PromptTemplate: SwarmPromptAuth,
		TargetURL:      targetURL,
		Hostname:       hostname,
		Instruction:    cfg.Instruction,
		SessionDir:     sessionDir,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
	}

	agentResult, runErr := s.engine.RunWithExtra(ctx, opts, extra)
	if runErr != nil {
		return "", fmt.Errorf("auth phase agent failed: %w", runErr)
	}

	writePromptToSessionDir(sessionDir, "auth-prompt.md", agentResult.RenderedPrompt)
	if sessionDir != "" && agentResult.RawOutput != "" {
		_ = os.WriteFile(filepath.Join(sessionDir, "auth-output.md"), []byte(agentResult.RawOutput), 0o644)
	}

	authConfigPath := filepath.Join(sessionDir, "auth-config.yaml")
	if _, err := os.Stat(authConfigPath); err == nil {
		return authConfigPath, nil
	}

	return "", nil
}
