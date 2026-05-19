package server

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/archon/archonbin"
)

// HandleAgentArchon handles POST /api/agent/run/archon — launches a foreground
// archon-audit run against a source tree (local path or git URL) and registers
// it as an AgenticScan so the existing /agent/status, /agent/sessions/:id/logs,
// and /agent/sessions/:id/artifacts endpoints can be used to monitor it.
func (h *Handlers) HandleAgentArchon(c fiber.Ctx) error {
	var req AgentArchonRequest
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

	// Resolve the intensity preset; explicit Mode/Timeout/CommitDepth
	// override. Mirrors ResolveAutopilotIntensity / ResolveSwarmIntensity so
	// every agent mode shares the same intensity → preset → overrides shape.
	intensity, err := agent.ValidateIntensity(req.Intensity)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
		})
	}
	explicitMode := strings.TrimSpace(req.Mode)
	explicitTimeout := strings.TrimSpace(req.Timeout)
	explicitModes := agent.ParseModesCSV(strings.Join(req.Modes, ","))
	preset := agent.ResolveArchonIntensity(intensity, agent.ArchonIntensityPreset{
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
	mode := preset.Mode
	modeChain := preset.Modes
	for _, m := range modeChain {
		if !agent.IsValidArchonMode(m) {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: fmt.Sprintf("invalid mode %q: must be one of lite, balanced, scan, deep, revisit, reinvest, confirm, merge, diff, longshot, refresh", m),
			})
		}
	}

	// Probe the embedded archon binary up front so a missing build
	// artifact surfaces as a clear 503 before we resolve sources.
	if !archonbin.Available() {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: "archon binary not embedded — rebuild vigolium with `make build-archon` and restart the server",
		})
	}

	// Resolve per-request BYOK (api_key / oauth_token / oauth_cred_file /
	// oauth_cred_json) and stage any inline cred JSON before we touch
	// the archon binary. Mirrors the audit endpoint's behavior so a
	// caller targeting /agent/run/archon can supply the same fields as
	// /agent/run/audit.
	authOverride, byokCleanup, err := h.resolveBYOKForAudit(req.AgentBYOK, req.EffectivePlatform())
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{Error: err.Error()})
	}
	dispatched := false
	defer func() {
		if !dispatched {
			byokCleanup()
		}
	}()

	// Resolve archon's --agent + auth from the configured olium provider,
	// with the request's optional `agent` field + BYOK override.
	invocation := agent.ResolveArchonInvocation(h.settings.Agent.Olium, strings.TrimSpace(req.EffectivePlatform()), authOverride)

	plan := auditRunPlan{
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
		harness:       agent.DefaultArchonHarness(),
		authCleanup:   byokCleanup,
		buildCfg: func(cfg *agent.AuditAgentConfig) {
			cfg.Mode = mode
			cfg.Modes = modeChain
			cfg.Platform = agent.PlatformArchonBin
			cfg.ArchonInvocation = invocation
			cfg.AuthOverride = authOverride
			// archon always emits NDJSON (`--json`) so the streaming
			// goroutine can capture the result event for cost reporting.
			cfg.Stream = true
		},
	}
	dispatched = true
	return h.startAuditRun(c, plan)
}
