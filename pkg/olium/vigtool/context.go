// Package vigtool defines olium-engine tools that bridge the agent into
// vigolium's native scanning, session storage, and JS extension subsystems.
//
// Tools in this package are vigolium-aware (they import internal/runner and
// pkg/database) and so live separately from the generic tool set in
// pkg/olium/tool/. Each tool is constructed with a ScanContext / SessionsContext
// that pins the project, repository, and config under which the tool operates —
// one context per olium run, shared across every tool the run constructs.
package vigtool

import (
	"context"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"go.uber.org/zap"
)

// ScanContext pins the project/repo/config under which scan-launch tools
// (run_scan, run_extension) operate. One instance per olium run.
type ScanContext struct {
	// Repo is required. Without it, scans run but findings aren't
	// persisted and the result struct comes back near-empty.
	Repo *database.Repository

	// ProjectUUID scopes scans this run kicks off.
	ProjectUUID string

	// ConfigPath optionally overrides vigolium-configs.yaml resolution.
	// Empty = default search.
	ConfigPath string

	// AgenticScanUUID is the parent agentic scan. run_native_scan stamps it
	// onto each child scan row and that scan's findings after the scan
	// completes (Repository.AttributeScanToAgenticScan), so tool-launched
	// scans surface under `finding --agentic-scan <parent>`.
	AgenticScanUUID string

	// Target is the run's primary target (URL or host). Used by
	// send_raw_http to hard-block out-of-scope destinations — an
	// autonomous agent writing arbitrary bytes to an arbitrary socket is
	// the highest-risk capability in the toolkit, so it stays anchored to
	// what the operator actually authorised.
	Target string

	// Scope carries the operator-supplied scope patterns (autopilot
	// Options.Scope). Host-like entries widen the send_raw_http allowlist
	// beyond the primary Target host.
	Scope []string
}

// attributeChildScan links a native scan this run launched (and its findings)
// to the parent agentic scan, so tool-launched scans surface under
// `finding --agentic-scan <parent>`. Every scan-launch tool (run_native_scan,
// run_module, run_extension) calls it after its blocking LaunchScan returns —
// every finding exists by then. Best-effort: the scan already succeeded, so an
// attribution hiccup is logged rather than surfaced as a tool failure. No-op
// when the run isn't part of an agentic scan or has no repo.
func (c *ScanContext) attributeChildScan(ctx context.Context, scanUUID string) {
	if c == nil || c.Repo == nil || c.AgenticScanUUID == "" || scanUUID == "" {
		return
	}
	if err := c.Repo.AttributeScanToAgenticScan(ctx, scanUUID, c.AgenticScanUUID); err != nil {
		zap.L().Warn("agentic-scan attribution failed",
			zap.String("scan_uuid", scanUUID),
			zap.String("agentic_scan_uuid", c.AgenticScanUUID),
			zap.Error(err))
	}
}

// SessionsContext pins the read-only repo handle that session/finding query
// tools use. Separated from ScanContext so query tools can be wired up even
// when scan-launch isn't (e.g. read-only inspection sessions).
type SessionsContext struct {
	Repo        *database.Repository
	ProjectUUID string
}

func (c *SessionsContext) repo() *database.Repository {
	if c == nil {
		return nil
	}
	return c.Repo
}

// requireRepo centralizes the "no repository configured" guard every
// vigtool tool runs at the top of Execute. When ok=false, the caller
// should return res to the model unchanged.
func requireRepo(repo *database.Repository, toolName string) (res tool.Result, ok bool) {
	if repo == nil {
		return tool.Result{
			Content: toolName + " unavailable: no repository configured",
			IsError: true,
		}, false
	}
	return tool.Result{}, true
}
