package server

import (
	"fmt"
	"io"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/audit/bin"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/piolium/pistream"
	"go.uber.org/zap"
)

// resolveAuditRequestAuthOverride builds the BYOK AuthOverride for a
// request. Values come straight from the JSON body — unlike the CLI,
// the REST endpoint does NOT honor $ENV / @path indirection (resolving
// either against a network-supplied string would let a caller probe
// the server's process env or filesystem). The agent (claude/codex)
// is resolved via the same precedence as ResolveAuditDriverInvocation:
// req.Agent → server's olium provider → claude default.
//
// When req.OAuthCredJSON is set, the JSON is staged to a per-request
// 0600 temp file under <sessions_dir>/byok-creds/ and the returned
// cleanup func removes that file. Callers MUST defer cleanup once the
// audit run finishes — staged files are scoped to a single run.
//
// req.OAuthCredFile (a server-side path) is still accepted for back-
// compat but emits a deprecation warning; new integrations should use
// req.OAuthCredJSON.
func (h *Handlers) resolveAuditRequestAuthOverride(req *AgentAuditRequest) (agent.AuthOverride, func(), error) {
	return h.resolveBYOKForAudit(req.AgentBYOK, h.auditPlatformForReq(req))
}

// resolveBYOKForAudit is the reusable resolver: it takes the embedded
// AgentBYOK plus an agent platform hint and returns a fully-validated
// agent.AuthOverride + a cleanup func that tears down any per-request
// staged cred file. Used by every subprocess-driver endpoint
// (audit, audit, and the per-driver paths under driver=both).
func (h *Handlers) resolveBYOKForAudit(byok AgentBYOK, agentPlatform string) (agent.AuthOverride, func(), error) {
	override := agent.AuthOverride{
		APIKey:        strings.TrimSpace(byok.APIKey),
		OAuthToken:    strings.TrimSpace(byok.OAuthToken),
		OAuthCredFile: strings.TrimSpace(byok.OAuthCredFile),
		Agent:         agent.ResolveAuthAgent(strings.TrimSpace(agentPlatform), h.settings.Agent.Olium.Provider),
	}
	noopCleanup := func() {}

	if strings.TrimSpace(byok.OAuthCredJSON) != "" {
		if override.OAuthCredFile != "" {
			return agent.AuthOverride{}, noopCleanup,
				fmt.Errorf("oauth_cred_json and oauth_cred_file are mutually exclusive")
		}
		path, cleanup, err := stageInlineCredJSON(h.settings.Agent.EffectiveSessionsDir(), byok.OAuthCredJSON)
		if err != nil {
			return agent.AuthOverride{}, noopCleanup, err
		}
		override.OAuthCredFile = path
		if err := agent.ValidateAuthOverride(override); err != nil {
			cleanup()
			return agent.AuthOverride{}, noopCleanup, err
		}
		return override, cleanup, nil
	}

	if override.OAuthCredFile != "" {
		zap.L().Warn("agent BYOK: oauth_cred_file is deprecated — use oauth_cred_json (inline) for new integrations",
			zap.String("path", override.OAuthCredFile))
	}

	if err := agent.ValidateAuthOverride(override); err != nil {
		return agent.AuthOverride{}, noopCleanup, err
	}
	return override, noopCleanup, nil
}

// HandleAgentAudit handles POST /api/agent/run/audit — launches one or both
// audit drivers (audit and piolium) against a source tree.
//
// `driver` selects which harnesses participate; "both" (default) runs them
// sequentially under one parent AgenticScan with per-driver child rows,
// multiplexed SSE events tagged by driver, and a post-pass project-wide
// findings dedup. With "both", `mode` is restricted to the shared set —
// driver-specific modes require an explicit single-driver value.
func (h *Handlers) HandleAgentAudit(c fiber.Ctx) error {
	var req AgentAuditRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
		})
	}

	if strings.TrimSpace(req.Source) == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "source is required (local path or git URL)",
		})
	}

	driver := strings.TrimSpace(req.Driver)
	if driver == "" {
		driver = agent.AuditDriverAuto
	}
	if !agent.IsValidAuditDriver(driver) {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: fmt.Sprintf("invalid driver %q: must be auto, both, audit, or piolium", driver),
		})
	}

	intensity, err := agent.ValidateIntensity(req.Intensity)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
		})
	}
	explicitMode := strings.TrimSpace(req.Mode)
	explicitTimeout := strings.TrimSpace(req.Timeout)
	explicitModes := agent.ParseModesCSV(strings.Join(req.Modes, ","))
	preset := agent.ResolveAuditDriverIntensity(intensity, agent.AuditDriverIntensityPreset{
		Mode:        explicitMode,
		Modes:       explicitModes,
		Timeout:     parseDurationOrDefault(req.Timeout, 0),
		CommitDepth: req.CommitDepth,
	}, map[string]bool{
		"modes":        len(explicitModes) > 0,
		"mode":         explicitMode != "",
		"timeout":      explicitTimeout != "",
		"commit-depth": req.CommitDepth != 0,
	})
	modeChain := preset.Modes

	auditChain, pioliumModes, err := agent.ValidateAuditDriverModes(
		driver, modeChain, piolium.IsValidMode, agent.IsValidAuditDriverMode)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{Error: err.Error()})
	}

	// Per-driver availability probe. For single-driver runs we 503 when the
	// requested driver's runtime is missing (caller asked for X, X isn't
	// installed — fail fast). For driver=both we never block: a missing
	// runtime becomes a warning log here, and the per-driver dispatch will
	// surface the failure on the child run while the other driver still runs.
	auditOK, auditReason := h.auditAvailable(&req)
	pioliumOK := h.pioliumAvailableCached()

	if agent.DriverIncludesAudit(driver) {
		platform := h.auditPlatformForReq(&req)
		if !agent.IsValidAuditDriverPlatform(platform) {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: fmt.Sprintf("invalid audit platform %q: must be claude or codex", platform),
			})
		}
	}

	switch driver {
	case agent.AuditDriverPiolium:
		if !pioliumOK {
			return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
				Error: "pi CLI not found in server PATH (install: https://www.npmjs.com/package/@earendil-works/pi-coding-agent), or piolium is not registered in ~/.pi/agent/settings.json",
			})
		}
	case agent.AuditDriverAudit:
		if !auditOK {
			return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
				Error: auditReason,
			})
		}
	case agent.AuditDriverBoth, agent.AuditDriverAuto:
		// Never block a multi-driver run on a single missing runtime — the
		// per-driver dispatch runs whatever's installed. For driver=auto a
		// missing piolium is expected and benign (it only runs if audit
		// fails), so this stays a debug-level note rather than a warning.
		if !auditOK {
			zap.L().Warn("audit: audit runtime unavailable",
				zap.String("driver", driver),
				zap.String("reason", auditReason))
		}
		if !pioliumOK {
			zap.L().Debug("audit: piolium runtime unavailable (fallback only for driver=auto)",
				zap.String("driver", driver),
				zap.String("reason", "pi CLI missing from PATH or piolium not registered in ~/.pi/agent/settings.json"))
		}
	}

	additionalArgs := piolium.PlmFlags{
		ScanLimit:       req.PlmScanLimit,
		ScanSince:       req.PlmScanSince,
		PhaseRetries:    req.PlmPhaseRetries,
		CommandRetries:  req.PlmCommandRetries,
		LongshotLimit:   req.PlmLongshotLimit,
		LongshotTimeout: req.PlmLongshotTimeout,
		LongshotLangs:   req.PlmLongshotLangs,
	}.Args()

	// Resolve BYOK once so single-driver and driver=both paths share the
	// same validation and agent-resolution. Validation errors land back
	// at the client as 400s so misconfigured creds are caught before we
	// kick off any subprocess work.
	authOverride, byokCleanup, err := h.resolveAuditRequestAuthOverride(&req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{Error: err.Error()})
	}
	cleanups := []func(){byokCleanup}
	chainedCleanup := func() {
		for _, c := range cleanups {
			c()
		}
	}
	// chainedCleanup tears down any per-request staged cred file(s). On
	// pre-dispatch failure we run it here; on success ownership transfers
	// to the plan and it fires when the run finishes.
	dispatched := false
	defer func() {
		if !dispatched {
			chainedCleanup()
		}
	}()

	// Per-driver BYOK overrides (multi-driver runs only: both/auto). Each
	// sub-override gets its own staging + cleanup so an audit-side
	// oauth_cred_json stays isolated from a piolium-side one.
	auditOverride := authOverride
	pioliumOverride := authOverride
	if agent.IsMultiDriverAudit(driver) {
		if req.AuditDriverAuth != nil && !req.AuditDriverAuth.IsZero() {
			ov, cl, perr := h.resolveBYOKForAudit(*req.AuditDriverAuth, h.auditPlatformForReq(&req))
			if perr != nil {
				return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{Error: "audit_auth: " + perr.Error()})
			}
			auditOverride = ov
			cleanups = append(cleanups, cl)
		}
		if req.PioliumAuth != nil && !req.PioliumAuth.IsZero() {
			ov, cl, perr := h.resolveBYOKForAudit(*req.PioliumAuth, h.auditPlatformForReq(&req))
			if perr != nil {
				return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{Error: "piolium_auth: " + perr.Error()})
			}
			pioliumOverride = ov
			cleanups = append(cleanups, cl)
		}
	} else {
		// Reject per-driver overrides on single-driver runs — the top-level
		// AgentBYOK already targets the one driver that runs.
		if req.AuditDriverAuth != nil && !req.AuditDriverAuth.IsZero() {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: "audit_auth is only valid with driver=both or driver=auto; use the top-level api_key/oauth_token/oauth_cred_json fields instead",
			})
		}
		if req.PioliumAuth != nil && !req.PioliumAuth.IsZero() {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: "piolium_auth is only valid with driver=both or driver=auto; use the top-level api_key/oauth_token/oauth_cred_json fields instead",
			})
		}
	}

	switch driver {
	case agent.AuditDriverPiolium:
		plan := h.buildPioliumAuditPlan(req, pioliumModes, preset, additionalArgs, pioliumOverride)
		plan.authCleanup = chainedCleanup
		dispatched = true
		return h.startAuditRun(c, plan)
	case agent.AuditDriverAudit:
		plan, err := h.buildAuditDriverPlan(req, auditChain, preset, auditOverride)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{Error: err.Error()})
		}
		plan.authCleanup = chainedCleanup
		dispatched = true
		return h.startAuditRun(c, plan)
	case agent.AuditDriverBoth, agent.AuditDriverAuto:
		dispatched = true
		return h.startCombinedAuditRun(c, driver, req, auditChain, pioliumModes, preset, additionalArgs, auditOverride, pioliumOverride, chainedCleanup)
	}
	// Unreachable: validation above rejects unknown drivers and the switch
	// is exhaustive over the constants. A panic here would catch a future
	// driver added to the constants but missed in the switch.
	panic("audit dispatcher: unreachable driver " + driver)
}

func (h *Handlers) buildPioliumAuditPlan(req AgentAuditRequest, modes []string, preset agent.AuditDriverIntensityPreset, additionalArgs []string, authOverride agent.AuthOverride) auditRunPlan {
	return auditRunPlan{
		source:        req.Source,
		target:        req.Target,
		diff:          req.Diff,
		lastCommits:   req.LastCommits,
		commitDepth:   preset.CommitDepth,
		files:         req.Files,
		stream:        req.Stream,
		uploadResults: req.UploadResults,
		projectUUID:   req.ProjectUUID,
		scanUUID:      req.ScanUUID,
		timeout:       preset.Timeout,
		harness:       piolium.DefaultHarness(),
		buildCfg: func(cfg *agent.AuditAgentConfig) {
			cfg.Mode = agent.FirstMode(modes)
			cfg.Modes = modes
			cfg.Platform = agent.PlatformPi
			cfg.Stream = true
			cfg.AdditionalArgs = additionalArgs
			cfg.PiProvider = req.PiProvider
			cfg.PiModel = req.PiModel
			cfg.CommitScanLimit = req.PlmScanLimit
			cfg.CommitScanSince = req.PlmScanSince
			cfg.AuthOverride = authOverride
			cfg.StreamDecoder = func(r io.Reader, render io.Writer, raw io.Writer) error {
				return pistream.Stream(r, render, pistream.Options{RawLog: raw})
			}
		},
	}
}

func (h *Handlers) buildAuditDriverPlan(req AgentAuditRequest, modes []string, preset agent.AuditDriverIntensityPreset, authOverride agent.AuthOverride) (auditRunPlan, error) {
	invocation := agent.ResolveAuditDriverInvocation(h.settings.Agent.Olium, h.auditPlatformForReq(&req), authOverride)
	return auditRunPlan{
		source:        req.Source,
		target:        req.Target,
		diff:          req.Diff,
		lastCommits:   req.LastCommits,
		commitDepth:   preset.CommitDepth,
		files:         req.Files,
		stream:        req.Stream,
		uploadResults: req.UploadResults,
		projectUUID:   req.ProjectUUID,
		scanUUID:      req.ScanUUID,
		timeout:       preset.Timeout,
		harness:       agent.DefaultAuditHarness(),
		buildCfg: func(cfg *agent.AuditAgentConfig) {
			cfg.Mode = agent.FirstMode(modes)
			cfg.Modes = modes
			cfg.Platform = agent.PlatformAuditBin
			cfg.AuditDriverInvocation = invocation
			cfg.AuthOverride = authOverride
			cfg.Stream = true
			cfg.KeepRaw = req.KeepRaw
		},
	}, nil
}

// auditPlatformForReq returns the request's `agent` override (if set)
// or empty (signaling "inherit from olium config") for the audit
// invocation resolver.
func (h *Handlers) auditPlatformForReq(req *AgentAuditRequest) string {
	return strings.TrimSpace(req.Agent)
}

// auditAvailable checks whether the embedded vigolium-audit binary was staged
// at vigolium build time. Returns the resolved error message when the
// binary is missing or the request's `agent` value is unrecognized —
// used both to gate single-driver requests with 503 and to warn-log
// under driver=both.
func (h *Handlers) auditAvailable(req *AgentAuditRequest) (bool, string) {
	platform := h.auditPlatformForReq(req)
	if !agent.IsValidAuditDriverPlatform(platform) {
		return false, fmt.Sprintf("invalid audit platform %q: must be claude or codex", platform)
	}
	if !bin.Available() {
		return false, "vigolium-audit binary not embedded — rebuild vigolium with `make build-audit`"
	}
	return true, ""
}
