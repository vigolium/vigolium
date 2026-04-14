package agent

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/agent/backend"
	"github.com/vigolium/vigolium/pkg/session"
)

func (r *AutopilotPipelineRunner) prepareAutopilotAuth(ctx context.Context, cfg *AutopilotPipelineConfig) (*AutopilotPreparedAuth, []string) {
	prepared := &AutopilotPreparedAuth{
		Requested:       shouldPrepareAutopilotAuth(*cfg),
		AuthRequired:    cfg.AuthRequired,
		RequiresBrowser: cfg.RequiresBrowser,
		BrowserStartURL: cfg.BrowserStartURL,
		FocusRoutes:     append([]string(nil), cfg.FocusRoutes...),
		ProtectedRoutes: append([]string(nil), cfg.FocusRoutes...),
	}
	if !prepared.Requested {
		return nil, nil
	}

	cfg.Instruction = stripPromptCredentials(cfg.Instruction, cfg.Credentials, cfg.CredentialSets)

	var warnings []string
	var sessionCfg *AgentSessionConfig
	var sourceNotes string

	if cfg.SourcePath != "" && cfg.TargetURL != "" {
		saResult, _, _, err := r.engine.RunSourceAnalysisParallel(ctx, SourceAnalysisConfig{
			AgentName:    cfg.AgentName,
			TargetURL:    cfg.TargetURL,
			SourcePath:   cfg.SourcePath,
			Files:        cfg.Files,
			Instruction:  cfg.Instruction,
			SessionKey:   "autopilot-auth-source",
			SessionDir:   cfg.SessionDir,
			DryRun:       cfg.DryRun,
			ShowPrompt:   cfg.ShowPrompt,
			ScanUUID:     cfg.ScanUUID,
			ProjectUUID:  cfg.ProjectUUID,
			StreamWriter: cfg.StreamWriter,
		})
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("auth preflight source analysis failed: %v", err))
		} else if saResult != nil {
			sourceNotes = saResult.SessionExploreNotes
			sessionCfg = saResult.SessionConfig
			if sessionCfg != nil && len(sessionCfg.Sessions) > 0 {
				prepared.Source = "source-analysis"
				prepared.Notes = append(prepared.Notes, "derived login/session flows from source analysis")
			}
		}
	}

	sets := cfg.CredentialSets
	if len(sets) == 0 && strings.TrimSpace(cfg.Credentials) != "" {
		sets = parseCredentialSetsFromString(cfg.Credentials)
	}
	cfg.CredentialSets = append([]agenttypes.IntentCredentialSet(nil), sets...)
	if len(sets) > 0 {
		cfg.AuthRequired = true
		prepared.AuthRequired = true
	}

	if len(sets) > 0 {
		if sessionCfg != nil {
			sessionCfg = applyIntentCredentialsToSessionConfig(sessionCfg, sets)
			prepared.Notes = append(prepared.Notes, "applied prompt-provided credentials to discovered login flows")
		} else {
			prepared.Notes = append(prepared.Notes, "prompt provided credentials but no login flow was discovered from source")
		}
	}

	sessionCfg = normalizeAutopilotSessionConfig(ctx, r.engine, cfg, sessionCfg, sourceNotes, &warnings)
	if sessionCfg != nil {
		writeSessionConfigToDir(sessionCfg, cfg.SessionDir)
		prepared.SessionCount = len(sessionCfg.Sessions)
		prepared.SessionConfig = filepath.Join(cfg.SessionDir, "session-config.json")
	}

	authHeaders := hydrateSessionConfig(sessionCfg)
	if len(authHeaders) > 0 {
		cfg.AuthHeaders = authHeaders
		prepared.Hydrated = true
		prepared.HeaderCount = len(authHeaders)
		prepared.Notes = append(prepared.Notes, "hydrated auth headers from HTTP login flow")
	}

	if len(authHeaders) == 0 && cfg.TargetURL != "" && cfg.BrowserEnabled && (cfg.RequiresBrowser || cfg.BrowserRequested) {
		browserCfg, browserHeaders, note, err := r.prepareBrowserAuth(ctx, *cfg)
		if note != "" {
			prepared.Notes = append(prepared.Notes, note)
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("browser auth preflight failed: %v", err))
		} else if browserCfg != nil {
			sessionCfg = browserCfg
			authHeaders = browserHeaders
			prepared.Source = "browser-auth"
			prepared.SessionCount = len(browserCfg.Sessions)
			prepared.SessionConfig = filepath.Join(cfg.SessionDir, "session-config.json")
			prepared.Hydrated = len(browserHeaders) > 0
			prepared.HeaderCount = len(browserHeaders)
		}
	}

	cfg.SessionConfig = sessionCfg
	cfg.AuthHeaders = authHeaders
	cfg.PreparedAuth = prepared

	if sessionCfg != nil && r.repo != nil && cfg.TargetURL != "" {
		hostname := hostnameFromURL(cfg.TargetURL)
		if hostname != "" {
			rows := backend.AgentSessionConfigToSessionHostnames(sessionCfg, cfg.ProjectUUID, cfg.ScanUUID, hostname, "agent-autopilot")
			if len(authHeaders) > 0 {
				now := time.Now().UTC()
				for _, row := range rows {
					row.HydratedAt = &now
				}
			}
			if len(rows) > 0 {
				if err := r.repo.SaveSessionHostnames(ctx, rows); err != nil {
					warnings = append(warnings, fmt.Sprintf("failed to persist prepared auth state: %v", err))
				}
			}
		}
	}

	return prepared, warnings
}

func shouldPrepareAutopilotAuth(cfg AutopilotPipelineConfig) bool {
	return cfg.AuthRequired ||
		strings.TrimSpace(cfg.Credentials) != "" ||
		len(cfg.CredentialSets) > 0 ||
		cfg.RequiresBrowser ||
		cfg.BrowserRequested ||
		cfg.BrowserStartURL != "" ||
		len(cfg.FocusRoutes) > 0 ||
		(cfg.SourcePath != "" && cfg.TargetURL != "")
}

func normalizeAutopilotSessionConfig(ctx context.Context, engine *Engine, cfg *AutopilotPipelineConfig, sessionCfg *AgentSessionConfig, sourceNotes string, warnings *[]string) *AgentSessionConfig {
	if sessionCfg == nil || len(sessionCfg.Sessions) == 0 {
		return nil
	}
	vr := backend.ValidateSessionConfigDetailed(sessionCfg)
	if len(vr.Invalid) > 0 {
		invalidCfg := &AgentSessionConfig{}
		for _, inv := range vr.Invalid {
			invalidCfg.Sessions = append(invalidCfg.Sessions, inv.Entry)
		}
		repaired := RepairInvalidSessionConfig(ctx, engine, invalidCfg, cfg.TargetURL, RepairConfig{
			AgentName:    cfg.AgentName,
			ShowPrompt:   cfg.ShowPrompt,
			ExploreNotes: sourceNotes,
		})
		if repaired != nil {
			vr.Valid = append(vr.Valid, repaired.Sessions...)
		} else {
			*warnings = append(*warnings, "some discovered auth sessions were invalid and could not be repaired")
		}
	}
	if len(vr.Valid) == 0 {
		return nil
	}
	return &AgentSessionConfig{Sessions: vr.Valid}
}

func (r *AutopilotPipelineRunner) prepareBrowserAuth(ctx context.Context, cfg AutopilotPipelineConfig) (*AgentSessionConfig, map[string]string, string, error) {
	if cfg.SessionDir == "" {
		return nil, nil, "", fmt.Errorf("session dir is required for browser auth preflight")
	}
	swarm := NewSwarmRunner(r.engine, r.repo)
	authPath, err := swarm.runAuthPhase(ctx, SwarmConfig{
		AgentName:    cfg.AgentName,
		Instruction:  cfg.Instruction,
		DryRun:       cfg.DryRun,
		ShowPrompt:   cfg.ShowPrompt,
		ScanUUID:     cfg.ScanUUID,
		ProjectUUID:  cfg.ProjectUUID,
		StreamWriter: cfg.StreamWriter,
		Credentials:  cfg.Credentials,
	}, cfg.TargetURL, cfg.SessionDir)
	if err != nil {
		return nil, nil, "", err
	}
	if authPath == "" {
		return nil, nil, "browser auth did not produce an auth-config.yaml artifact", nil
	}

	sessions, err := session.LoadFromConfig(authPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to load browser auth config: %w", err)
	}
	cfgOut := sessionsToAgentSessionConfig(sessions)
	if cfgOut == nil {
		return nil, nil, "", fmt.Errorf("browser auth config did not contain usable sessions")
	}
	writeSessionConfigToDir(cfgOut, cfg.SessionDir)
	headers := primaryHeadersFromSessions(sessions)
	return cfgOut, headers, "captured auth state with browser-assisted login", nil
}

func sessionsToAgentSessionConfig(sessions []*session.Session) *AgentSessionConfig {
	if len(sessions) == 0 {
		return nil
	}
	out := &AgentSessionConfig{Sessions: make([]AgentSessionEntry, 0, len(sessions))}
	for _, s := range sessions {
		entry := AgentSessionEntry{
			Name:    s.Name,
			Role:    string(s.Role),
			Headers: cloneStringMap(s.Headers),
		}
		if s.Login != nil {
			entry.Login = &AgentLoginFlow{
				URL:         s.Login.URL,
				Method:      s.Login.Method,
				ContentType: s.Login.ContentType,
				Body:        s.Login.Body,
				Type:        string(s.Login.Type),
				TokenPath:   s.Login.TokenPath,
			}
			if s.Login.Expect != nil {
				entry.Login.Expect = &AgentExpectResponse{
					Status:       append([]int(nil), s.Login.Expect.Status...),
					BodyContains: s.Login.Expect.BodyContains,
				}
			}
			for _, rule := range s.Login.Extract {
				entry.Login.Extract = append(entry.Login.Extract, AgentExtractRule{
					Source:  string(rule.Source),
					Name:    rule.Name,
					Path:    rule.Path,
					ApplyAs: rule.ApplyAs,
					Pattern: rule.Pattern,
					Group:   rule.Group,
				})
			}
		}
		out.Sessions = append(out.Sessions, entry)
	}
	return out
}

func primaryHeadersFromSessions(sessions []*session.Session) map[string]string {
	if len(sessions) == 0 {
		return nil
	}
	mgr, err := session.NewManager(sessions)
	if err != nil {
		return nil
	}
	headers := mgr.PrimaryHeaders()
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for _, h := range headers {
		parts := strings.SplitN(h, ": ", 2)
		if len(parts) == 2 {
			out[parts[0]] = parts[1]
		}
	}
	return out
}

func stripPromptCredentials(in, raw string, sets []agenttypes.IntentCredentialSet) string {
	out := in
	if strings.TrimSpace(raw) != "" {
		out = strings.ReplaceAll(out, raw, "")
	}
	for _, set := range sets {
		pair := strings.TrimSpace(set.Username + "/" + set.Password)
		if pair != "/" {
			out = strings.ReplaceAll(out, pair, "")
		}
	}
	return strings.TrimSpace(out)
}
