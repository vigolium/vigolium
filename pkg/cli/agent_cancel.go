package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// agentCancelPollInterval is how often a running agent command checks
// whether another process asked it to stop.
var agentCancelPollInterval = 5 * time.Second

// agentCancelFilename is the cancel sentinel `agent cancel` drops into the
// run's session directory, for a run whose row is in a store the canceller
// cannot reach (-S runs into a temporary database).
const agentCancelFilename = "cancel"

// errAgentCancelRequested is the cancellation cause of a run stopped by
// `agent cancel` (or the REST cancel endpoint on a run the server does not
// own).
var errAgentCancelRequested = errors.New("cancel requested (vigolium agent cancel)")

// activeAgentRun is the agentic-scan UUID of this invocation's run, once one
// started: the error envelope names it, so a failed run can be found again.
var activeAgentRun atomic.Value

// noteAgentRun records this invocation's run UUID.
func noteAgentRun(uuid string) {
	if uuid = strings.TrimSpace(uuid); uuid != "" {
		activeAgentRun.Store(uuid)
	}
}

// activeAgentRunUUID is the run UUID noteAgentRun recorded, "" for none.
func activeAgentRunUUID() string {
	v, _ := activeAgentRun.Load().(string)
	return v
}

// watchAgentCancel returns ctx wrapped so that a cancel request for runUUID
// — agentic_scans.cancel_requested_at, or the cancel sentinel in sessionDir —
// cancels it. ctx.Err() is then context.Canceled, so the run finalizes as
// "cancelled" exactly as on Ctrl-C; context.Cause names the request. Call the
// returned stop when the run ends.
func watchAgentCancel(ctx context.Context, repo *database.Repository, sessionDir, runUUID string) (context.Context, func()) {
	noteAgentRun(runUUID)
	ctx, cancel := context.WithCancelCause(ctx)
	if runUUID == "" || (repo == nil && sessionDir == "") {
		return ctx, func() { cancel(nil) }
	}
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(agentCancelPollInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if agentCancelRequested(ctx, repo, sessionDir, runUUID) {
				zap.L().Info("Agent run cancel requested; stopping", zap.String("agentic_scan_uuid", runUUID))
				fmt.Fprintf(os.Stderr, "%s cancel requested for run %s; stopping\n", terminal.WarningSymbol(), runUUID)
				cancel(errAgentCancelRequested)
				return
			}
		}
	}()
	var once atomic.Bool
	return ctx, func() {
		if once.CompareAndSwap(false, true) {
			close(done)
			cancel(nil)
			if sessionDir != "" {
				_ = os.Remove(filepath.Join(sessionDir, agentCancelFilename))
			}
		}
	}
}

// agentCancelRequested checks the row, then the sentinel.
func agentCancelRequested(ctx context.Context, repo *database.Repository, sessionDir, runUUID string) bool {
	if repo != nil {
		readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		ok, err := repo.AgenticScanCancelRequested(readCtx, runUUID)
		cancel()
		if err == nil && ok {
			return true
		}
	}
	if sessionDir != "" {
		if _, err := os.Stat(filepath.Join(sessionDir, agentCancelFilename)); err == nil {
			return true
		}
	}
	return false
}

var (
	agentCancelWait    bool
	agentCancelTimeout time.Duration
)

var agentCancelCmd = &cobra.Command{
	Use:   "cancel <run-uuid|prefix>",
	Short: "Ask a running agent run (query, autopilot, swarm, audit, triage) to stop",
	Long: `Stop an agent run started by another process: a CLI run, or one a REST
server runs.

A cancel request is written on the run's agentic_scans row
(cancel_requested_at) and, when its session directory is on this host, a cancel
sentinel is dropped there. The running process checks both every 5 seconds and
stops as on Ctrl-C: the run is finalized as cancelled. A run that already
finished is left as it is (changed: false). Nothing is ever signalled.

--wait polls the row until the run has finished; if it does not within
--timeout, the result is exit 1 wait_timeout.`,
	Example: FormatExamples(
		"# Stop a run by a prefix of its UUID",
		"vigolium agent cancel 3f9a12bc",
		"# Stop it and wait for it to finish",
		"vigolium agent cancel 3f9a12bc --wait -j",
	),
	Args: cobra.ExactArgs(1),
	RunE: runAgentCancel,
}

func init() {
	agentCmd.AddCommand(agentCancelCmd)
	f := agentCancelCmd.Flags()
	f.BoolVar(&agentCancelWait, "wait", false, "Wait until the run has finished")
	f.DurationVar(&agentCancelTimeout, "timeout", 60*time.Second, "With --wait, how long to wait")

	registerCommandSchema(contract.Command{Name: "agent cancel", Item: agentCancelView{},
		Description: "The agent run a cancel was asked of: action cancel_requested (the request was written on its row and/or session sentinel) or already_finished (changed false). --wait adds acknowledged."})
}

// agentCancelView is the one item `agent cancel -j` reports.
type agentCancelView struct {
	AgenticScanUUID string `json:"agentic_scan_uuid"`
	// Action: cancel_requested | already_finished.
	Action string `json:"action"`
	Status string `json:"status"`
	// Via lists where the request was written: "db" and/or "sentinel".
	Via          []string `json:"via"`
	Acknowledged *bool    `json:"acknowledged,omitempty"`
}

func runAgentCancel(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	if agentCancelTimeout < 0 {
		return usageErrorf("--timeout must not be negative (got %s)", agentCancelTimeout)
	}
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}
	sessionsDir := settings.Agent.EffectiveSessionsDir()
	ctx := context.Background()

	var repo *database.Repository
	var db *database.DB
	if d, err := getDB(); err == nil {
		db, repo = d, database.NewRepository(d)
	}
	projectUUID := ""
	if repo != nil && !statelessReadRequested() {
		if projectUUID, err = resolveProjectUUID(); err != nil {
			return err
		}
	}
	uuid, err := resolveRunRef(ctx, db, "agentic_scans", projectUUID, args[0], func(prefix string) []string {
		return sessionDirsWithPrefix(sessionsDir, prefix)
	})
	if err != nil {
		return err
	}

	out := agentCancelView{AgenticScanUUID: uuid, Via: []string{}}
	changed := false
	var run *database.AgenticScan
	if repo != nil {
		if r, getErr := repo.GetAgenticScan(ctx, uuid); getErr == nil {
			run = r
		}
	}
	if run != nil && projectUUID != "" && run.ProjectUUID != "" && run.ProjectUUID != projectUUID {
		return codedErrorf(apicontract.CodeNotFound, "no agent run %s in this project (it belongs to project %s; pass --project-uuid to act on it)", uuid, run.ProjectUUID)
	}
	sessionDir := filepath.Join(sessionsDir, uuid)
	if run != nil && run.SessionDir != "" {
		sessionDir = run.SessionDir
	}
	_, statErr := os.Stat(sessionDir)
	haveSession := statErr == nil

	switch {
	case run != nil:
		ok, status, reqErr := repo.RequestAgenticScanCancel(ctx, uuid)
		if reqErr != nil {
			return fmt.Errorf("record the cancel request on run %s: %w", uuid, reqErr)
		}
		out.Status = status
		if !ok {
			out.Action = "already_finished"
			break
		}
		out.Action, changed = "cancel_requested", true
		out.Via = append(out.Via, "db")
		if haveSession && writeAgentCancelSentinel(sessionDir) == nil {
			out.Via = append(out.Via, "sentinel")
		}
	case haveSession:
		if err := writeAgentCancelSentinel(sessionDir); err != nil {
			return fmt.Errorf("write cancel sentinel for run %s: %w", uuid, err)
		}
		out.Action, out.Status, changed = "cancel_requested", "unknown", true
		out.Via = append(out.Via, "sentinel")
	default:
		return codedErrorf(apicontract.CodeNotFound, "no agent run %s: not in this store and no session directory at %s", uuid, terminal.ShortenHome(sessionDir))
	}

	var waitErr error
	if agentCancelWait && out.Action == "cancel_requested" && run != nil {
		ack := false
		deadline := time.Now().Add(agentCancelTimeout)
		for {
			status, stErr := repo.AgenticScanStatusByUUID(ctx, uuid)
			if stErr == nil && isTerminalAgenticStatus(status) {
				out.Status, ack = status, true
				break
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Second)
		}
		out.Acknowledged = &ack
		if !ack {
			waitErr = codedErrorf(apicontract.CodeWaitTimeout, "agent run %s did not stop within --timeout %s; the request stays on its row", uuid, agentCancelTimeout)
		}
	}

	if globalJSON {
		if err := emitMutation(cmd, "", mutationResult{
			Changed: changed, Action: out.Action, Items: out,
			Query: []string{"agent", "session", uuid},
		}); err != nil {
			return err
		}
		return waitErr
	}
	if !globalSilent {
		switch out.Action {
		case "cancel_requested":
			fmt.Printf("%s cancel requested for agent run %s (via %s); it stops within ~5s\n", terminal.InfoSymbol(), uuid, strings.Join(out.Via, ", "))
			if out.Acknowledged != nil && *out.Acknowledged {
				fmt.Printf("%s run %s is %s\n", terminal.SuccessSymbol(), uuid, out.Status)
			}
		default:
			fmt.Printf("%s agent run %s is not running (%s); nothing to cancel\n", terminal.InfoSymbol(), uuid, out.Status)
		}
	}
	return waitErr
}

func writeAgentCancelSentinel(sessionDir string) error {
	return atomicfile.WriteBytes(filepath.Join(sessionDir, agentCancelFilename),
		[]byte(fmt.Sprintf(`{"by":%q,"at":%q}`, stopRequester(), time.Now().UTC().Format(time.RFC3339))))
}

// isTerminalAgenticStatus reports whether an agentic_scans status is final.
func isTerminalAgenticStatus(status string) bool {
	for _, s := range database.TerminalAgenticScanStatuses {
		if s == status {
			return true
		}
	}
	return false
}

// agentRunFailure is the error for an agent run that ended with err: a run
// stopped by `agent cancel` says so instead of reporting a bare
// "context canceled".
func agentRunFailure(ctx context.Context, err error) error {
	if errors.Is(context.Cause(ctx), errAgentCancelRequested) {
		return fmt.Errorf("agent run cancelled: %w", errAgentCancelRequested)
	}
	return fmt.Errorf("agent run failed: %w", err)
}
