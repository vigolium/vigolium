package agent

import (
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/piolium"
	"go.uber.org/zap"
)

// Audit configuration and harness resolution: deciding whether the audit agent
// runs, which mode/harness to use, and validating shared driver modes. Split
// out of audit_agent.go to separate config resolution from the scanner runtime.

// Audit is enabled by default when source code is available. Pass noAudit=true
// to force-disable it (--no-audit flag). The mode defaults to "lite" when empty.
// Returns nil when the audit agent should not run.
func ResolveAuditAgentConfig(noAudit bool, mode string, sourcePath string, agentCfg config.AuditAgentConfig) *config.AuditAgentConfig {
	// Explicit disable
	if noAudit {
		return nil
	}
	// No source code — audit has nothing to audit
	if sourcePath == "" {
		return nil
	}
	// Source is provided and not disabled: always enabled
	effectiveMode := mode
	if effectiveMode == "" {
		effectiveMode = agentCfg.EffectiveMode()
	}
	if effectiveMode == "" {
		effectiveMode = "lite"
	}
	// Validate mode
	if !isValidAuditDriverMode(effectiveMode) {
		zap.L().Warn("Invalid audit mode, falling back to lite", zap.String("mode", effectiveMode))
		effectiveMode = "lite"
	}
	enabled := true
	return &config.AuditAgentConfig{
		Enable:       &enabled,
		Mode:         effectiveMode,
		SyncInterval: agentCfg.SyncInterval,
	}
}

// PickAuditHarness picks the audit cfg + harness pair to run from already-
// resolved mode strings. Piolium wins when its mode is non-empty/"off"
// (callers do their own auto-pick before invoking this — see the CLI's
// post-intensity switch and the server's resolveAutopilotAuditCfgServer).
// Returns (nil, zero-spec) when no audit should run.
func PickAuditHarness(pioliumMode, auditModeLocal string, auditNoAudit bool, sourcePath string, settingsAudit config.AuditAgentConfig) (*config.AuditAgentConfig, HarnessSpec) {
	if cfg := ResolvePioliumAuditConfig(pioliumMode, sourcePath); cfg != nil {
		return cfg, piolium.DefaultHarness()
	}
	if cfg := ResolveAuditAgentConfig(auditNoAudit, auditModeLocal, sourcePath, settingsAudit); cfg != nil {
		return cfg, DefaultAuditHarness()
	}
	return nil, HarnessSpec{}
}

// ResolvePioliumAuditConfig is the piolium counterpart of
// ResolveAuditAgentConfig: returns nil when the audit should not run
// (mode empty/"off" or no source). The returned cfg is intentionally
// minimal — Platform and StreamDecoder are auto-installed inside
// StartAuditAgent based on the harness it receives.
func ResolvePioliumAuditConfig(mode, sourcePath string) *config.AuditAgentConfig {
	if mode == "" || mode == "off" {
		return nil
	}
	if sourcePath == "" {
		return nil
	}
	if !piolium.IsValidMode(mode) {
		zap.L().Warn("Invalid piolium mode, falling back to lite", zap.String("mode", mode))
		mode = "lite"
	}
	enabled := true
	return &config.AuditAgentConfig{
		Enable: &enabled,
		Mode:   mode,
	}
}

// sharedAuditModes is the intersection of modes supported by both audit
// and piolium. Used to gate `vigolium agent audit --driver=both` — when
// both drivers run sequentially, the mode must be one they both understand.
// Driver-specific modes (piolium's longshot, audit's mock) require
// `--driver=piolium` or `--driver=audit` so the user opts into the
// single-driver path explicitly.
var sharedAuditModes = map[string]bool{
	"lite":     true,
	"balanced": true,
	"scan":     true, // legacy audit alias for balanced
	"deep":     true,
	"revisit":  true,
	"confirm":  true,
	"merge":    true,
}

// IsSharedAuditMode returns true when the given audit mode is supported by
// both audit and piolium harnesses. Used by the unified audit dispatcher
// to validate `--driver=both` runs, where the same mode is dispatched to
// each driver in turn.
func IsSharedAuditMode(mode string) bool {
	return sharedAuditModes[mode]
}

// isValidAuditDriverMode returns true for recognized audit modes.
// "scan" is accepted as a legacy alias for "balanced"; EffectiveMode()
// normalizes it when the slash command is dispatched.
func isValidAuditDriverMode(mode string) bool {
	switch mode {
	case "lite", "balanced", "scan", "deep", "mock", "confirm", "merge", "revisit", "reinvest":
		return true
	default:
		return false
	}
}
