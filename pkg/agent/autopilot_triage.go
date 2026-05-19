package agent

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// autopilotTriageBatchSize mirrors swarm's per-batch ceiling so a large
// finding set doesn't blow the triage prompt context.
const autopilotTriageBatchSize = 25

// AutopilotTriageParams configures the post-scan triage pass.
type AutopilotTriageParams struct {
	TargetURL       string
	SourcePath      string
	ScanUUID        string
	ProjectUUID     string
	AgenticScanUUID string // verdicts are written back scoped to this run
	SessionDir      string
	StreamWriter    io.Writer
	Verbose         bool
}

// RunAutopilotTriage runs a single AI triage pass over the project's findings
// after an autopilot scan completes. Each finding is classified as confirmed
// (→ status "triaged") or a false positive (→ "false_positive") and the
// verdict is written back, scoped to this run's AgenticScanUUID so only
// findings this scan produced are touched.
//
// It is a pure classification pass: ScanFunc is nil and MaxRounds is 1, so
// triage never kicks off native rescans (that remains swarm's job). It reuses
// the shared RunTriageLoop machinery and the agent-swarm-triage prompt.
//
// Callers should treat a returned error as non-fatal — a triage failure must
// not fail an otherwise-completed scan.
func RunAutopilotTriage(ctx context.Context, engine *Engine, repo *database.Repository, p AutopilotTriageParams) (*TriageLoopResult, error) {
	if engine == nil || repo == nil {
		return nil, fmt.Errorf("autopilot triage: engine and repository are required")
	}
	if p.ProjectUUID == "" || p.AgenticScanUUID == "" {
		return nil, fmt.Errorf("autopilot triage: project and agentic-scan UUID are required")
	}

	streamf := func(format string, a ...any) {
		if p.StreamWriter != nil {
			_, _ = fmt.Fprintf(p.StreamWriter, format, a...)
		}
	}
	streamf("\n[triage] reviewing findings — confirming real issues vs false positives…\n")

	cfg := TriageLoopConfig{
		Engine:                    engine,
		Repository:                repo,
		PromptTemplate:            SwarmPromptTriage,
		TargetURL:                 p.TargetURL,
		Hostname:                  hostnameFromTarget(p.TargetURL),
		SourcePath:                p.SourcePath,
		ScanUUID:                  p.ScanUUID,
		ProjectUUID:               p.ProjectUUID,
		AgenticScanUUID:           p.AgenticScanUUID,
		StreamWriter:              p.StreamWriter,
		Verbose:                   p.Verbose,
		MaxRounds:                 1,
		MaxFindingsPerTriageBatch: autopilotTriageBatchSize,
		SessionDir:                p.SessionDir,
		// ScanFunc deliberately nil — see doc comment.
	}

	res, err := RunTriageLoop(ctx, cfg)
	if err != nil {
		streamf("[triage] aborted: %v\n", err)
		return res, err
	}
	if res != nil {
		zap.L().Info("Autopilot triage complete",
			zap.Int("confirmed", res.Confirmed),
			zap.Int("false_positives", res.FalsePositives))
		streamf("[triage] done — %d confirmed, %d false positive(s)\n", res.Confirmed, res.FalsePositives)
	}
	return res, nil
}

// hostnameFromTarget extracts a bare hostname from a target URL/host for the
// triage prompt context. Best-effort: an empty result is fine — triage loads
// findings from the DB by project, not by host.
func hostnameFromTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if i := strings.IndexAny(target, "/:"); i > 0 {
		return target[:i]
	}
	return target
}
