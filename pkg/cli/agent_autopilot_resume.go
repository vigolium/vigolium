package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/sessionlog"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// prepareAutopilotResume rewires the autopilot CLI globals so a run continues an
// existing agentic scan (durable-autopilot v1). It reuses the run's identity —
// session dir, project, target, source — so runAutopilotOlium reopens the same
// session dir and CreateAgenticScan no-ops on the existing UUID (no new scan).
// The durable scratchpad (session dir) and candidate ledger (DB) are reloaded
// automatically by the operator. Any section left running from a crashed run is
// marked interrupted.
//
// v1 limitations (documented in DURABLE_AUTOPILOT_REVIEW.md): resume skips the
// native pre-scan and audit re-prep (the durable state already holds the
// captured surface + plan) and does not replay the original prompt; it
// re-enters the operator loop seeded from the durable scratchpad + candidates.
func prepareAutopilotResume(ctx context.Context, repo *database.Repository, resumeUUID, sessionsDir string) error {
	if repo == nil {
		//vigolium:not-usage no database is open; a store problem, not a flag problem
		return fmt.Errorf("--resume requires a database connection")
	}
	run, err := repo.GetAgenticScan(ctx, resumeUUID)
	if err != nil {
		//vigolium:not-usage database lookup result
		wrapped := fmt.Errorf("--resume: agentic scan %s not found: %w", resumeUUID, err)
		if errors.Is(err, sql.ErrNoRows) {
			return clicommon.NewCodedError(apicontract.CodeScanNotFound, wrapped)
		}
		return wrapped
	}
	if run.Mode != "autopilot" {
		//vigolium:not-usage decided from the stored run, after I/O
		return fmt.Errorf("--resume: %s is a %q run, not an autopilot run", resumeUUID, run.Mode)
	}

	// Reuse the run's identity. globalScanUUID drives the session-dir + parent
	// AgenticScan UUID in runAutopilotOlium; the project is pinned so findings
	// land back in the original project.
	globalScanUUID = run.UUID
	if run.ProjectUUID != "" {
		globalProjectUUID = run.ProjectUUID
		// Pin the resolver too: resolveProjectUUID caches via sync.Once, so setting
		// the global flag alone would be ignored once the first resolve has fired.
		// This makes the resumed project authoritative regardless of call ordering.
		clicommon.PinProjectUUID(run.ProjectUUID)
	}
	if autopilotTarget == "" {
		autopilotTarget = run.TargetURL
	}
	if autopilotSource == "" {
		autopilotSource = run.SourcePath
	}

	// Durable state already holds the captured surface + plan; don't re-run the
	// native pre-scan, the pre-flight discovery, or the source audit.
	autopilotNoPrescan = true
	autopilotNoPreflight = true
	autopilotAudit = "off"
	autopilotPiolium = "off"

	sessionDir := run.SessionDir
	if sessionDir == "" {
		sessionDir = filepath.Join(sessionsDir, run.UUID)
	}

	markInterruptedSections(ctx, repo, run.UUID, sessionDir)

	// Flip the (possibly terminal) run back to running so finalize/summary
	// reflect the resumed pass.
	_ = repo.UpdateAgenticScan(ctx, &database.AgenticScan{UUID: run.UUID, Status: "running"})

	fmt.Fprintf(os.Stderr, "%s Resuming autopilot %s (target=%s, session=%s)\n",
		terminal.InfoSymbol(), run.UUID,
		clicommon.ValueOrNone(autopilotTarget),
		terminal.ShortenHome(sessionDir))
	return nil
}

// markInterruptedSections flips any still-running section for the run to
// interrupted (crash recovery) and appends a section_interrupted event to the
// run's transcript. Best-effort; a failure just leaves the stale status.
func markInterruptedSections(ctx context.Context, repo *database.Repository, agenticScanUUID, sessionDir string) {
	sections, err := repo.ListAgentSections(ctx, agenticScanUUID)
	if err != nil {
		return
	}
	var rec *sessionlog.Recorder
	if sessionDir != "" {
		if r, rerr := sessionlog.New(filepath.Join(sessionDir, sessionlog.Filename), sessionlog.Meta{SessionID: agenticScanUUID}); rerr == nil {
			rec = r
			defer func() { _ = rec.Close() }()
		}
	}
	for _, s := range sections {
		if s.Status != database.SectionStatusRunning {
			continue
		}
		_ = repo.UpdateAgentSection(ctx, &database.AgentSection{UUID: s.UUID, Status: database.SectionStatusInterrupted})
		if rec != nil {
			rec.SectionInterrupted(s.UUID)
		}
	}
}
