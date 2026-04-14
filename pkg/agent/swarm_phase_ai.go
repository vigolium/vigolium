package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/agent/backend"
	"github.com/vigolium/vigolium/pkg/agent/parsing"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

func (s *SwarmRunner) runSASTReview(ctx context.Context, cfg SwarmConfig, targetURL string, sessionDir string) *SourceAnalysisResult {
	if s.repo == nil {
		zap.L().Warn("SAST review skipped: no database repository")
		return nil
	}

	sastFindings, err := database.NewFindingsQueryBuilder(s.repo.DB(), database.QueryFilters{
		ProjectUUID: cfg.ProjectUUID,
		ModuleType:  database.ModuleTypeSAST,
		Limit:       200,
	}).Execute(ctx)
	if err != nil {
		zap.L().Warn("Failed to query SAST findings", zap.Error(err))
		return nil
	}

	codeAuditModuleID := "agent-" + SwarmPromptCodeAudit
	allAgentFindings, caErr := database.NewFindingsQueryBuilder(s.repo.DB(), database.QueryFilters{
		ProjectUUID: cfg.ProjectUUID,
		ModuleType:  database.ModuleTypeAgent,
		Limit:       100,
	}).Execute(ctx)
	if caErr != nil {
		zap.L().Debug("Failed to query agent findings for SAST review", zap.Error(caErr))
	}
	for _, f := range allAgentFindings {
		if f.ModuleID == codeAuditModuleID {
			sastFindings = append(sastFindings, f)
		}
	}

	if len(sastFindings) == 0 {
		zap.L().Info("No SAST findings to review")
		return nil
	}

	var findingsSummary strings.Builder
	for i, f := range sastFindings {
		if i > 0 {
			findingsSummary.WriteString("\n---\n")
		}
		fmt.Fprintf(&findingsSummary, "### Finding %d\n", i+1)
		fmt.Fprintf(&findingsSummary, "- **Module**: %s (%s)\n", f.ModuleName, f.ModuleID)
		fmt.Fprintf(&findingsSummary, "- **Severity**: %s\n", f.Severity)
		fmt.Fprintf(&findingsSummary, "- **Source**: %s\n", f.FindingSource)
		if f.Description != "" {
			fmt.Fprintf(&findingsSummary, "- **Description**: %s\n", f.Description)
		}
		if len(f.MatchedAt) > 0 {
			fmt.Fprintf(&findingsSummary, "- **Matched at**: %s\n", strings.Join(f.MatchedAt, ", "))
		}
		if len(f.Tags) > 0 {
			fmt.Fprintf(&findingsSummary, "- **Tags**: %s\n", strings.Join(f.Tags, ", "))
		}
	}

	hostname := hostnameFromURL(targetURL)
	var routesSummary string
	if hostname != "" {
		dbRecords, recErr := s.repo.GetRecordsByHostname(ctx, cfg.ProjectUUID, hostname, 100)
		if recErr == nil && len(dbRecords) > 0 {
			var rs strings.Builder
			for i, rec := range dbRecords {
				if i >= 100 {
					fmt.Fprintf(&rs, "\n... and %d more routes", len(dbRecords)-100)
					break
				}
				fmt.Fprintf(&rs, "- %s %s\n", rec.Method, rec.URL)
			}
			routesSummary = rs.String()
		}
	}

	sastReviewSessionID := uuid.New().String()
	opts := Options{
		AgentName:      cfg.AgentName,
		PromptTemplate: SwarmPromptSASTReview,
		TargetURL:      targetURL,
		Hostname:       hostname,
		SourcePath:     cfg.SourcePath,
		Instruction:    cfg.Instruction,
		SessionKey:     SwarmPhaseSASTReview,
		SessionID:      sastReviewSessionID,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
	}

	agentResult, runErr := s.engine.RunWithExtra(ctx, opts, map[string]string{
		"SASTFindings":     findingsSummary.String(),
		"SASTFindingCount": fmt.Sprintf("%d", len(sastFindings)),
		"DiscoveredRoutes": routesSummary,
	})
	if runErr != nil {
		zap.L().Warn("SAST review agent failed", zap.Error(runErr))
		return nil
	}

	WriteSDKSessionEntry(sessionDir, SDKSessionEntry{
		SessionID: sastReviewSessionID,
		Phase:     SwarmPhaseSASTReview,
		AgentName: cfg.AgentName,
		Timestamp: time.Now(),
	})

	writePromptToSessionDir(sessionDir, "sast-review-prompt.md", agentResult.RenderedPrompt)
	if sessionDir != "" && agentResult.RawOutput != "" {
		_ = os.WriteFile(filepath.Join(sessionDir, "sast-review-output.md"), []byte(agentResult.RawOutput), 0o644)
	}

	if cfg.DryRun {
		return nil
	}

	saResult, parseErr := parsing.ParseSourceAnalysisResult(agentResult.RawOutput)
	if parseErr != nil {
		zap.L().Warn("Failed to parse SAST review result", zap.Error(parseErr))
		return nil
	}

	zap.L().Info("SAST review completed",
		zap.Int("validated_routes", len(saResult.HTTPRecords)),
		zap.Int("extensions", len(saResult.Extensions)))

	if sessionDir != "" && len(saResult.Extensions) > 0 {
		writeSourceExtensionsToSessionDir(saResult.Extensions, sessionDir)
	}

	if saResult.SessionConfig != nil && len(saResult.SessionConfig.Sessions) > 0 {
		vr := backend.ValidateSessionConfigDetailed(saResult.SessionConfig)
		if len(vr.Invalid) > 0 {
			invalidCfg := &AgentSessionConfig{}
			for _, inv := range vr.Invalid {
				invalidCfg.Sessions = append(invalidCfg.Sessions, inv.Entry)
			}
			repaired := RepairInvalidSessionConfig(ctx, s.engine, invalidCfg, targetURL, RepairConfig{
				AgentName:  cfg.AgentName,
				ShowPrompt: cfg.ShowPrompt,
			})
			if repaired != nil {
				vr.Valid = append(vr.Valid, repaired.Sessions...)
			}
		}
		if len(vr.Valid) > 0 {
			saResult.SessionConfig = &AgentSessionConfig{Sessions: vr.Valid}
		} else {
			saResult.SessionConfig = nil
		}
	}
	if sessionDir != "" && saResult.SessionConfig != nil && len(saResult.SessionConfig.Sessions) > 0 {
		writeSessionConfigToDir(saResult.SessionConfig, sessionDir)
	}

	return saResult
}

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

	authSessionID := uuid.New().String()
	opts := Options{
		AgentName:      cfg.AgentName,
		PromptTemplate: SwarmPromptAuth,
		TargetURL:      targetURL,
		Hostname:       hostname,
		Instruction:    cfg.Instruction,
		SessionKey:     SwarmPhaseAuth,
		SessionID:      authSessionID,
		SessionDir:     sessionDir,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
		Autopilot:      true,
		MaxCommands:    30,
	}

	agentResult, runErr := s.engine.RunWithExtra(ctx, opts, extra)
	if runErr != nil {
		return "", fmt.Errorf("auth phase agent failed: %w", runErr)
	}

	WriteSDKSessionEntry(sessionDir, SDKSessionEntry{
		SessionID: authSessionID,
		Phase:     SwarmPhaseAuth,
		AgentName: cfg.AgentName,
		Timestamp: time.Now(),
	})

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
