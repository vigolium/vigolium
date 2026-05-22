package agent

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Audit driver IDs for the unified `vigolium agent audit` and
// `POST /api/agent/run/audit` dispatcher. The JSON `driver` field on
// `AgentAuditRequest` accepts these values verbatim, and `vigolium agent
// audit --driver=...` mirrors the same set, so they live here as the
// single source of truth shared by CLI and server packages.
const (
	AuditDriverPiolium = "piolium"
	AuditDriverAudit   = "audit"
	AuditDriverBoth    = "both"
	// AuditDriverAuto is the default. It runs audit first; piolium is
	// only invoked as a fallback when audit fails (or isn't available).
	// A clean audit run finishes the audit without ever consulting
	// piolium, so a missing piolium runtime is not reported up front.
	AuditDriverAuto = "auto"
)

// DefaultAuditSyncInterval is the per-runner audit-state.json sync
// cadence used by every audit dispatcher entry point.
const DefaultAuditSyncInterval = 30 * time.Second

// AuditDedupTimeout caps the post-pass project-wide findings dedup so
// a large findings table can't stall the orchestrator's exit. Failure
// is logged-and-swallowed; the audit still reports completion.
const AuditDedupTimeout = 30 * time.Second

// auditDriverModes is the canonical accepted set of audit `--mode`
// values, mirroring vigolium-audit's CLI validator. Single source of truth
// shared by the CLI command, the REST handler, and the audit driver
// dispatcher. "scan" stays as a legacy alias for balanced.
var auditDriverModes = map[string]bool{
	"lite":     true,
	"balanced": true,
	"scan":     true,
	"deep":     true,
	"revisit":  true,
	"reinvest": true,
	"confirm":  true,
	"merge":    true,
	"diff":     true,
	"longshot": true,
	"refresh":  true,
}

// IsValidAuditDriverMode reports whether mode is a recognized audit mode.
func IsValidAuditDriverMode(mode string) bool { return auditDriverModes[mode] }

// IsValidAuditDriverPlatform reports whether platform is a recognized audit
// agent identifier. Same set as IsValidAuditDriverAgent plus the empty
// string, which is treated as "inherit agent from olium config" by the
// resolver.
func IsValidAuditDriverPlatform(platform string) bool {
	return platform == "" || IsValidAuditDriverAgent(platform)
}

// IsValidAuditDriver reports whether driver is a recognized audit driver.
func IsValidAuditDriver(driver string) bool {
	switch driver {
	case AuditDriverPiolium, AuditDriverAudit, AuditDriverBoth, AuditDriverAuto:
		return true
	}
	return false
}

// IsMultiDriverAudit reports whether the driver can dispatch both
// harnesses in one run (so per-driver auth overrides are allowed, the
// shared-mode restriction applies, and a missing single runtime is a
// warning rather than a hard error). True for "both" and "auto".
func IsMultiDriverAudit(driver string) bool {
	return driver == AuditDriverBoth || driver == AuditDriverAuto
}

// DriverIncludesAudit reports whether the audit driver runs audit.
func DriverIncludesAudit(driver string) bool {
	return driver == AuditDriverAudit || IsMultiDriverAudit(driver)
}

// DriverIncludesPiolium reports whether the audit driver may run
// piolium. For "auto" piolium only runs as an audit fallback, but it
// is still in the potential driver set, so mode/auth validation treats
// it as included.
func DriverIncludesPiolium(driver string) bool {
	return driver == AuditDriverPiolium || IsMultiDriverAudit(driver)
}

// AuditDriverCfgInput collects everything BuildAuditDriverCfg needs to
// produce a runnable AuditAgentConfig. The embedded vigolium-audit binary
// self-contains its content bundle, so there is no plugin-dir
// extraction step anymore. Invocation carries the resolved
// agent + auth (resolved from olium config / CLI override by the
// caller via ResolveAuditDriverInvocation). Stream toggles audit's
// `--json` mode so the streaming goroutine can capture the result
// event for cost reporting.
type AuditDriverCfgInput struct {
	Mode                  string
	Modes                 []string
	SourcePath            string
	SessionDir            string
	ProjectUUID           string
	ScanUUID              string
	ParentAgenticScanUUID string
	Invocation            AuditDriverInvocation
	Stream                bool
	StreamWriter          io.Writer

	// ShowThinking opts into rendering agent thinking blocks (audit NDJSON
	// `thinking` events) in the live stream. Off by default; controlled by
	// `vigolium agent audit --show-thinking`.
	ShowThinking bool

	// KeepRaw maps to vigolium-audit's `--keep-raw`: opt out of the
	// deep/confirm auto-prune so raw scanner output, draft findings, and
	// intermediate workspaces stay on disk for manual review. Audit-only;
	// ignored for the piolium harness.
	KeepRaw bool

	// AuthOverride carries the resolved BYOK bundle for this run. It is
	// already folded into Invocation.Auth by the caller (via
	// ResolveAuditDriverInvocation's variadic override or
	// ApplyAuthOverrideToAudit), so audit's argv reflects it. The
	// field is also stored on AuditAgentConfig so the launcher can match
	// audit's auth to whatever staging/env injection the piolium driver
	// would do (currently only piolium consumes it; audit stays argv-only).
	AuthOverride AuthOverride
}

// BuildAuditDriverCfg assembles the AuditAgentConfig that drives an
// audit run. Used by every entry point that launches audit (CLI
// agent dispatcher, server combined dispatcher) so the platform /
// invocation plumbing stays in one place.
func BuildAuditDriverCfg(in AuditDriverCfgInput) AuditAgentConfig {
	return AuditAgentConfig{
		Harness:               DefaultAuditHarness(),
		Mode:                  in.Mode,
		Modes:                 in.Modes,
		Platform:              PlatformAuditBin,
		SourcePath:            in.SourcePath,
		SessionDir:            in.SessionDir,
		ProjectUUID:           in.ProjectUUID,
		ScanUUID:              in.ScanUUID,
		ParentAgenticScanUUID: in.ParentAgenticScanUUID,
		AuditDriverInvocation: in.Invocation,
		SyncInterval:          DefaultAuditSyncInterval,
		Stream:                in.Stream,
		StreamWriter:          in.StreamWriter,
		ShowThinking:          in.ShowThinking,
		KeepRaw:               in.KeepRaw,
		AuthOverride:          in.AuthOverride,
	}
}

// ValidateAuditDriverMode returns an error when mode is not valid for
// the given audit driver. driver=both restricts to the shared set so
// both runners can dispatch the same mode without coercion surprises;
// single-driver invocations accept the driver's full mode set.
//
// modeIsValidForPiolium and modeIsValidForAudit are injected to avoid
// dragging the piolium and audit driver-specific validators into
// pkg/agent's import graph.
func ValidateAuditDriverMode(driver, mode string, modeIsValidForPiolium, modeIsValidForAudit func(string) bool) error {
	switch driver {
	case AuditDriverBoth, AuditDriverAuto:
		if !IsSharedAuditMode(mode) {
			return fmt.Errorf("mode %q is not supported with driver=%s (use lite, balanced, deep, revisit, confirm, or merge; or pass driver=piolium / driver=audit for driver-specific modes)", mode, driver)
		}
	case AuditDriverPiolium:
		if !modeIsValidForPiolium(mode) {
			return fmt.Errorf("invalid mode %q for piolium (must be one of: lite, balanced, deep, revisit, confirm, merge, diff, longshot, status, smoke)", mode)
		}
	case AuditDriverAudit:
		if !modeIsValidForAudit(mode) {
			return fmt.Errorf("invalid mode %q for audit (must be one of: lite, balanced, deep, revisit, reinvest, confirm, merge, diff, status, mock)", mode)
		}
	}
	return nil
}

// ParseModesCSV splits a comma-separated --modes value into a clean,
// order-preserving, de-duplicated slice. Whitespace around each token is
// trimmed and empty tokens are dropped. A bare "" returns nil so callers
// can fall back to the single --mode / intensity-derived value.
func ParseModesCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, tok := range strings.Split(s, ",") {
		m := strings.ToLower(strings.TrimSpace(tok))
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

// JoinModes renders a mode chain back to the comma-separated form audit's
// `--modes` flag expects and the audit banner / DB Mode column display.
func JoinModes(modes []string) string { return strings.Join(modes, ",") }

// FirstMode returns the first mode of a chain, or "" for an empty chain.
// Used to keep AuditAgentConfig.Mode populated alongside Modes for the
// single-mode consumers that never chain.
func FirstMode(modes []string) string {
	if len(modes) == 0 {
		return ""
	}
	return modes[0]
}

// ValidateAuditDriverModes validates a mode chain for the given driver
// and returns the per-driver filtered chains (audit's modes first, then
// piolium's). A mode invalid for BOTH drivers is always an error (typo
// guard). For an explicit single driver every mode must be valid for
// that driver — silently dropping one the operator asked for would be
// surprising. For multi-driver paths (auto/both) each mode only has to
// be valid for at least one driver; per-driver-unsupported modes are
// skipped on that driver's leg.
func ValidateAuditDriverModes(driver string, modes []string, modeIsValidForPiolium, modeIsValidForAudit func(string) bool) (auditChain, pioliumChain []string, err error) {
	if len(modes) == 0 {
		return nil, nil, fmt.Errorf("no audit modes supplied")
	}

	var unknown []string
	for _, m := range modes {
		okA := modeIsValidForAudit(m)
		okP := modeIsValidForPiolium(m)
		if !okA && !okP {
			unknown = append(unknown, m)
			continue
		}
		if okA {
			auditChain = append(auditChain, m)
		}
		if okP {
			pioliumChain = append(pioliumChain, m)
		}
	}
	if len(unknown) > 0 {
		return nil, nil, fmt.Errorf("unknown audit mode(s): %s", strings.Join(unknown, ", "))
	}

	switch driver {
	case AuditDriverAudit:
		if len(auditChain) != len(modes) {
			return nil, nil, fmt.Errorf("mode chain %q contains modes audit does not support (audit modes: lite, balanced, deep, revisit, reinvest, confirm, merge, diff, longshot, refresh)", JoinModes(modes))
		}
		pioliumChain = nil
	case AuditDriverPiolium:
		if len(pioliumChain) != len(modes) {
			return nil, nil, fmt.Errorf("mode chain %q contains modes piolium does not support (piolium modes: lite, balanced, deep, revisit, confirm, merge, diff, longshot)", JoinModes(modes))
		}
		auditChain = nil
	case AuditDriverBoth, AuditDriverAuto:
		// per-driver skip: filtered chains already reflect what each leg
		// can run; an empty leg just means that driver runs nothing.
	default:
		return nil, nil, fmt.Errorf("invalid --driver %q", driver)
	}
	return auditChain, pioliumChain, nil
}
