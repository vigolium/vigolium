package runner

import (
	"context"
	"fmt"

	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"go.uber.org/zap"
)

// initSessions loads, validates, hydrates sessions and creates compare requesters.
// Sources (in priority order): --auth-file/--auth flags → DB authentication_hostnames fallback.
func (r *Runner) initSessions(infra *phaseInfra) error {
	opts := r.options
	sessionCfg := r.settings.ScanningStrategy.Session
	hasCLISessions := len(opts.AuthFiles) > 0 || len(opts.AuthInline) > 0

	var sessions []*authentication.Session
	var sessionHostnameMap map[string]string // session name → hostname (from DB)
	fromDB := false

	if hasCLISessions {
		if len(opts.AuthFiles) > 0 {
			loaded, err := authentication.LoadFromAuthFiles(opts.AuthFiles, sessionCfg.SessionDir)
			if err != nil {
				return err
			}
			sessions = append(sessions, loaded...)
		}
		if len(opts.AuthInline) > 0 {
			loaded, err := authentication.LoadFromAuthInline(opts.AuthInline)
			if err != nil {
				return err
			}
			sessions = append(sessions, loaded...)
		}
	} else {
		// Fallback: load from DB authentication_hostnames for this project's target hostnames
		sessions, sessionHostnameMap, fromDB = r.loadSessionsFromDB()
		if len(sessions) == 0 {
			return nil
		}
	}

	mgr, err := authentication.NewManager(sessions, authentication.WithSessionDir(sessionCfg.SessionDir))
	if err != nil {
		return err
	}

	// Execute login flows (re-hydrate DB sessions to refresh potentially stale tokens)
	if err := mgr.HydrateSessions(); err != nil {
		return fmt.Errorf("session hydration failed: %w", err)
	}

	// Persist CLI sessions to DB for reuse in future scans
	if hasCLISessions {
		r.persistSessionsToDB(mgr.AllSessions())
	}

	// Merge primary session headers into the main requester's options.
	// When use_in_discovery is false, primary headers are only applied to the
	// dynamic-assessment phase requester (handled downstream), not the main one used
	// for discovery and spidering.
	primaryHeaders := mgr.PrimaryHeaders()
	if len(primaryHeaders) > 0 && sessionCfg.UseInDiscovery {
		opts.Headers = append(opts.Headers, primaryHeaders...)
		// Rebuild the main requester with updated headers
		httpRequester, err := http.NewRequester(opts, infra.svc)
		if err != nil {
			return fmt.Errorf("failed to rebuild requester with session headers: %w", err)
		}
		infra.httpRequester = httpRequester
	}

	// Create separate requesters for compare sessions (IDOR/BOLA testing)
	if !sessionCfg.CompareEnabled {
		zap.L().Info("Multi-session scanning enabled (compare disabled by config)",
			zap.String("primary", mgr.Primary().Name))
		return nil
	}

	cmpSessions := mgr.CompareSessions()
	if len(cmpSessions) == 0 {
		return nil
	}

	for _, cs := range cmpSessions {
		// Clone options, merge global headers with session-specific auth headers
		compareOpts := *opts
		compareOpts.Headers = append(append([]string{}, opts.Headers...), cs.HeaderSlice()...)
		compareRequester, err := http.NewRequester(&compareOpts, infra.svc)
		if err != nil {
			return fmt.Errorf("failed to create requester for session %q: %w", cs.Name, err)
		}
		cmpEntry := compareSession{
			Name:   cs.Name,
			Client: compareRequester,
		}
		// Preserve per-hostname association from DB sessions
		if sessionHostnameMap != nil {
			cmpEntry.Hostname = sessionHostnameMap[cs.Name]
		}
		infra.compareSessions = append(infra.compareSessions, cmpEntry)
	}

	sourceLabel := "CLI"
	if fromDB {
		sourceLabel = "DB"
	}
	zap.L().Info("Multi-session scanning enabled",
		zap.String("source", sourceLabel),
		zap.String("primary", mgr.Primary().Name),
		zap.Int("compare_sessions", len(cmpSessions)))

	return nil
}

// loadSessionsFromDB loads sessions from the authentication_hostnames table for target hostnames.
// Returns the loaded sessions, a map of session name → hostname for per-host filtering,
// and true if sessions were loaded from DB.
func (r *Runner) loadSessionsFromDB() ([]*authentication.Session, map[string]string, bool) {
	if r.repository == nil || r.options.ProjectUUID == "" {
		return nil, nil, false
	}

	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Extract hostnames from CLI targets
	hostnames := r.targetHostnames()
	if len(hostnames) == 0 {
		// No specific targets — try loading all project sessions
		rows, err := r.repository.GetAuthenticationHostnamesByProject(ctx, r.options.ProjectUUID)
		if err != nil || len(rows) == 0 {
			return nil, nil, false
		}
		cfg := database.AuthenticationHostnamesToSessionConfig(rows)
		if cfg == nil || len(cfg.Sessions) == 0 {
			return nil, nil, false
		}
		sessions := make([]*authentication.Session, len(cfg.Sessions))
		hostnameMap := make(map[string]string, len(rows))
		for i := range cfg.Sessions {
			sessions[i] = &cfg.Sessions[i]
		}
		for _, row := range rows {
			hostnameMap[row.SessionName] = row.Hostname
		}
		zap.L().Info("Loaded sessions from DB (project-wide)",
			zap.Int("sessions", len(sessions)))
		return sessions, hostnameMap, true
	}

	// Query authentication_hostnames for each target hostname, deduplicate by session name+hostname
	seen := make(map[string]bool)
	hostnameMap := make(map[string]string)
	var sessions []*authentication.Session
	for _, hostname := range hostnames {
		rows, err := r.repository.GetAuthenticationHostnamesByHostname(ctx, r.options.ProjectUUID, hostname)
		if err != nil || len(rows) == 0 {
			continue
		}
		for _, row := range rows {
			key := row.SessionName + ":" + row.Hostname
			if seen[key] {
				continue
			}
			seen[key] = true
			s := database.AuthenticationHostnameToSession(row)
			if s != nil {
				sessions = append(sessions, s)
				hostnameMap[s.Name] = row.Hostname
			}
		}
	}

	if len(sessions) > 0 {
		zap.L().Info("Loaded sessions from DB (authentication_hostnames)",
			zap.Int("sessions", len(sessions)),
			zap.Strings("hostnames", hostnames))
	}
	return sessions, hostnameMap, len(sessions) > 0
}

// persistSessionsToDB saves hydrated CLI sessions to authentication_hostnames for future reuse.
func (r *Runner) persistSessionsToDB(sessions []*authentication.Session) {
	if r.repository == nil || r.options.ProjectUUID == "" || len(sessions) == 0 {
		return
	}

	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	hostnames := r.targetHostnames()
	if len(hostnames) == 0 {
		return
	}

	for _, hostname := range hostnames {
		rows := database.SessionsToAuthenticationHostnames(sessions, r.options.ProjectUUID, hostname)
		if len(rows) == 0 {
			continue
		}
		if err := r.repository.SaveAuthenticationHostnames(ctx, rows); err != nil {
			zap.L().Debug("Failed to persist sessions to DB",
				zap.String("hostname", hostname), zap.Error(err))
		}
	}

	zap.L().Info("Persisted CLI sessions to authentication_hostnames",
		zap.Int("sessions", len(sessions)),
		zap.Strings("hostnames", hostnames))
}
