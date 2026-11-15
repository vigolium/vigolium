package cli

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// scanStopBy names who stopped this invocation's scan through a stop request
// ("" when nobody did); withFailOnGate reports it as the interrupt's cause.
var scanStopBy atomic.Value

// noteScanStopRequest records (or, with "", clears) the stop request that
// ended this invocation's scan.
func noteScanStopRequest(by string) { scanStopBy.Store(strings.TrimSpace(by)) }

// scanStopRequestedBy names who stopped this invocation's scan, "" for nobody.
func scanStopRequestedBy() string {
	v, _ := scanStopBy.Load().(string)
	return v
}

// interruptSelfOnStopRequest ends a direct scan-url / scan-request pass on a
// stop request by interrupting this process, exactly as Ctrl-C would: the
// invocation's one signal context stops the batch and every row is finalized
// as interrupted. Signalling our own pid is safe where signalling a recorded
// one is not. Where the platform cannot deliver os.Interrupt to itself the
// request is still recorded, and the scan runs to its end.
func interruptSelfOnStopRequest(req runner.StopRequest) {
	by := req.By
	if by == "" {
		by = "unknown"
	}
	noteScanStopRequest(by)
	if p, err := os.FindProcess(os.Getpid()); err == nil {
		_ = p.Signal(os.Interrupt)
	}
}

var (
	scanStopWait    bool
	scanStopTimeout time.Duration
)

var scanStopCmd = &cobra.Command{
	Use:   "stop <scan-uuid|prefix>",
	Short: "Ask a running scan to stop, or finalize one whose process is gone",
	Long: `Stop a native scan started by another process: a CLI scan, a scan the
REST server runs, or a -S/--db-isolate scan whose row lives in a scratch file.

The scan is not signalled. A stop request is written on the scan's row
(stop_requested_at) and, when the scan's session directory is on this host, a
stop sentinel is dropped next to its status.json. The running process checks
both with every heartbeat (every 10s), stops like a Ctrl-C, finalizes its row as
cancelled with stop_reason user_stopped, and exits 5 (interrupted).

A scan whose row still says running but whose process is gone (nothing written
for 2 minutes, or the pid is dead on this host) is finalized as abandoned
instead, like 'vigolium log ls --reap'. A scan that already finished is left as
it is (changed: false).

--wait polls until the scan acknowledges by finishing. If it does not within
--timeout, the result names its pid so you can interrupt it by hand
(kill -INT <pid>); nothing is ever signalled automatically.

Pause and resume are REST-only (POST /api/scans/<uuid>/pause|resume on the
server that runs the scan).`,
	Example: FormatExamples(
		"# Ask a scan to stop and wait for it to finish",
		"vigolium scan stop 7c0e1a2b --wait -j",
		"# Fire and forget",
		"vigolium scan stop 7c0e1a2b-…-uuid",
	),
	Args: cobra.ExactArgs(1),
	RunE: runScanStop,
}

var scanLsCmd = &cobra.Command{
	Use:     "ls",
	Aliases: []string{"list"},
	Short:   "List scan sessions (alias of 'vigolium log ls')",
	Long: `List native scan and agentic scan sessions, newest first, with their
liveness. The same command as 'vigolium log ls': same flags, same -j rows.`,
	Example: FormatExamples(
		"# Running and recent scans",
		"vigolium scan ls -j",
		"# Finalize scans whose process died",
		"vigolium scan ls --reap",
	),
	Args: cobra.NoArgs,
	RunE: runLogLs,
}

func init() {
	scanCmd.AddCommand(scanStopCmd)
	f := scanStopCmd.Flags()
	f.BoolVar(&scanStopWait, "wait", false, "Wait until the scan has finished (acknowledged the stop)")
	f.DurationVar(&scanStopTimeout, "timeout", 60*time.Second, "With --wait, how long to wait before giving up and naming the pid")

	// The alias shares log ls' flags (same variables), so the two cannot
	// drift. log.go's init has registered them by now: the files of a package
	// are initialized in name order.
	scanCmd.AddCommand(scanLsCmd)
	scanLsCmd.Flags().AddFlagSet(logLsCmd.Flags())

	registerCommandSchema(contract.Command{Name: "scan ls", Item: logRowView{}, Extras: logLsExtras{},
		Description: "Alias of log ls: native and agentic scan sessions with liveness; --reap adds reaped and status_files_removed."})
	registerCommandSchema(contract.Command{Name: "scan stop", Item: scanStopView{},
		Description: "The scan a stop was asked of: action stop_requested (the request was written on its row and/or session sentinel), reaped (its process was gone; finalized as abandoned) or already_finished (changed false). --wait adds acknowledged; a scan that does not stop in time is exit 1 wait_timeout with a manual kill hint."})
}

// scanStopView is the one item `scan stop -j` reports.
type scanStopView struct {
	ScanUUID string `json:"scan_uuid"`
	// Action: stop_requested | reaped | already_finished.
	Action string `json:"action"`
	// Status is the stored status after the action; EffectiveStatus is what
	// to act on (see scan status).
	Status          string `json:"status"`
	EffectiveStatus string `json:"effective_status"`
	// Via lists where the stop request was written: "db" (the row) and/or
	// "sentinel" (the session's stop file).
	Via         []string `json:"via"`
	RequestedBy string   `json:"requested_by,omitempty"`
	// Acknowledged is set under --wait: whether the scan finished in time.
	Acknowledged *bool  `json:"acknowledged,omitempty"`
	PID          int    `json:"pid,omitempty"`
	RunnerHost   string `json:"runner_host,omitempty"`
	// Hint is the manual fallback when the scan did not acknowledge.
	Hint string `json:"hint,omitempty"`
}

// Stop actions.
const (
	stopActionRequested       = "stop_requested"
	stopActionReaped          = "reaped"
	stopActionAlreadyFinished = "already_finished"
)

// stopRequester names this process as the asker of a stop request.
func stopRequester() string {
	who := "cli"
	if u := strings.TrimSpace(os.Getenv("USER")); u != "" {
		who += " " + u
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		who += "@" + h
	}
	return fmt.Sprintf("%s (pid %d)", who, os.Getpid())
}

func runScanStop(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	if scanStopTimeout < 0 {
		return usageErrorf("--timeout must not be negative (got %s)", scanStopTimeout)
	}
	ref := strings.TrimSpace(args[0])
	if ref == "" {
		return usageErrorf("scan stop needs a scan UUID or a unique prefix of one")
	}
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}
	sessionsDir := settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir()
	ctx := context.Background()

	// The shared store, write intent: the request is a write. A store that
	// cannot be opened still leaves the sentinel for a scan running on this
	// host.
	var repo *database.Repository
	var db *database.DB
	if d, err := getDB(); err == nil {
		db, repo = d, database.NewRepository(d)
	} else {
		zap.L().Debug("scan stop: database unavailable; only the stop sentinel can be written", zap.Error(err))
	}
	projectUUID := ""
	if repo != nil && !statelessReadRequested() {
		if projectUUID, err = resolveProjectUUID(); err != nil {
			return err
		}
	}

	uuid, err := resolveRunRef(ctx, db, "scans", projectUUID, ref, func(prefix string) []string {
		return sessionDirsWithPrefix(sessionsDir, prefix)
	})
	if err != nil {
		return err
	}

	reader := &scanStatusReader{repo: repo, sessionsDir: sessionsDir}
	view, err := reader.read(ctx, uuid)
	if err != nil {
		return err
	}
	if view.ProjectUUID != "" && projectUUID != "" && view.ProjectUUID != projectUUID {
		return codedErrorf(apicontract.CodeScanNotFound, "no scan %s in this project (it belongs to project %s; pass --project-uuid to act on it)", uuid, view.ProjectUUID)
	}

	out := scanStopView{ScanUUID: uuid, Via: []string{}, PID: view.PID, RunnerHost: view.RunnerHost}
	changed := false
	switch view.EffectiveStatus {
	case effStatusRunning:
		by := stopRequester()
		out.Action, out.RequestedBy = stopActionRequested, by
		if repo != nil && hasSource(view.Source, "db") {
			ok, err := repo.RequestScanStop(ctx, uuid, by)
			if err != nil {
				return fmt.Errorf("record the stop request on scan %s: %w", uuid, err)
			}
			if ok {
				out.Via = append(out.Via, "db")
			}
		}
		if _, err := runner.WriteStopSentinel(sessionsDir, uuid, by); err == nil {
			out.Via = append(out.Via, "sentinel")
		}
		if len(out.Via) == 0 {
			return fmt.Errorf("could not deliver a stop request to scan %s: its row is not in this store and its session directory is not on this host", uuid)
		}
		changed = true
	case effStatusAbandoned:
		out.Action = stopActionReaped
		if repo == nil || !hasSource(view.Source, "db") {
			out.Action = stopActionAlreadyFinished
			out.Hint = "the scan's process is gone and its row is not in this store; nothing to stop"
			break
		}
		row, err := repo.GetScanByUUID(ctx, uuid)
		if err != nil {
			return err
		}
		var last time.Time
		if view.Liveness.LastWriteAt != nil {
			last, _ = time.Parse(time.RFC3339Nano, *view.Liveness.LastWriteAt)
		}
		ok, err := repo.ReapAbandonedScan(ctx, row, last)
		if err != nil {
			return fmt.Errorf("finalize abandoned scan %s: %w", uuid, err)
		}
		changed = ok
		if ok {
			out.Via = append(out.Via, "db")
		}
	default:
		out.Action = stopActionAlreadyFinished
	}

	var waitErr error
	if out.Action == stopActionRequested && scanStopWait {
		w := &scanWaiter{
			uuid:          uuid,
			probe:         func(ctx context.Context) (*scanStatusView, error) { return reader.read(ctx, uuid) },
			clock:         realWaitClock{},
			timeout:       scanStopTimeout,
			poll:          time.Second,
			notFoundGrace: 0,
		}
		final, err := w.wait(ctx)
		ack := err == nil
		out.Acknowledged = &ack
		if final != nil {
			view = final
		}
		if !ack {
			out.Hint = stopFallbackHint(view)
			waitErr = clicommon.CLIError{
				Err:  fmt.Errorf("scan %s did not stop within --timeout %s", uuid, scanStopTimeout),
				Code: apicontract.CodeWaitTimeout,
				Hint: out.Hint,
			}
		}
	}

	// Re-read so the reported status is the one after the action.
	if after, err := reader.read(ctx, uuid); err == nil {
		view = after
	}
	out.Status, out.EffectiveStatus = view.Status, view.EffectiveStatus
	if out.PID == 0 {
		out.PID, out.RunnerHost = view.PID, view.RunnerHost
	}

	if globalJSON {
		if err := emitMutation(cmd, "", mutationResult{
			Changed: changed,
			Action:  out.Action,
			Items:   out,
			Query:   []string{"scan", "status", uuid},
		}); err != nil {
			return err
		}
		return waitErr
	}
	printScanStopHuman(out)
	return waitErr
}

// stopFallbackHint is the manual step when a scan did not acknowledge a stop
// request: interrupt its process by hand, when it runs on this host.
func stopFallbackHint(v *scanStatusView) string {
	host, _ := os.Hostname()
	if v != nil && v.PID > 0 && (v.RunnerHost == "" || v.RunnerHost == host) {
		return fmt.Sprintf("interrupt it by hand: kill -INT %d (check `ps -p %d` first: the pid is what the scan recorded)", v.PID, v.PID)
	}
	if v != nil && v.RunnerHost != "" {
		return fmt.Sprintf("the scan runs on %s; interrupt its process there (pid %d)", v.RunnerHost, v.PID)
	}
	return "the request stays on the row; the scan stops at its next heartbeat"
}

func printScanStopHuman(v scanStopView) {
	if globalSilent {
		return
	}
	switch v.Action {
	case stopActionRequested:
		fmt.Printf("%s stop requested for scan %s (via %s)\n", terminal.InfoSymbol(), v.ScanUUID, strings.Join(v.Via, ", "))
		if v.Acknowledged != nil && *v.Acknowledged {
			fmt.Printf("%s scan %s is %s\n", terminal.SuccessSymbol(), v.ScanUUID, v.EffectiveStatus)
		} else if v.Acknowledged == nil {
			fmt.Printf("  it stops at its next heartbeat (≤10s); wait for it: vigolium scan wait %s\n", v.ScanUUID)
		}
	case stopActionReaped:
		fmt.Printf("%s scan %s was abandoned (its process is gone); finalized as failed, stop_reason abandoned\n", terminal.InfoSymbol(), v.ScanUUID)
	default:
		fmt.Printf("%s scan %s is not running (%s); nothing to stop\n", terminal.InfoSymbol(), v.ScanUUID, v.EffectiveStatus)
	}
	if v.Hint != "" {
		fmt.Printf("  %s\n", v.Hint)
	}
}

func hasSource(sources []string, s string) bool {
	for _, x := range sources {
		if x == s {
			return true
		}
	}
	return false
}

// runRefShape is what a run reference may contain: a UUID or a prefix of one.
var runRefShape = regexp.MustCompile(`^[0-9a-fA-F-]+$`)

// minRunRefPrefix is the shortest prefix a run reference may be.
const minRunRefPrefix = 8

// resolveRunRef resolves a run reference — a full UUID, or a unique prefix of
// at least minRunRefPrefix characters — against table ("scans" or
// "agentic_scans") within projectUUID ("" reads across projects). extra lists
// further candidates for a prefix from outside the store (session directories
// of scratch-database runs). A full UUID is returned as is: whether it exists
// is the caller's question.
func resolveRunRef(ctx context.Context, db *database.DB, table, projectUUID, ref string, extra func(prefix string) []string) (string, error) {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if scanUUIDShape.MatchString(ref) {
		return ref, nil
	}
	if !runRefShape.MatchString(ref) {
		return "", usageErrorf("%q is not a run UUID or a UUID prefix", ref)
	}
	if len(ref) < minRunRefPrefix {
		return "", usageErrorf("UUID prefix %q is too short: give at least %d characters", ref, minRunRefPrefix)
	}
	seen := map[string]bool{}
	var matches []string
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			matches = append(matches, u)
		}
	}
	if db != nil {
		var uuids []string
		q := db.NewSelect().TableExpr(table).Column("uuid").Where("uuid LIKE ?", ref+"%").Limit(10)
		if projectUUID != "" {
			q = q.Where("project_uuid = ?", projectUUID)
		}
		if err := q.Scan(ctx, &uuids); err != nil {
			return "", fmt.Errorf("look up %q: %w", ref, err)
		}
		for _, u := range uuids {
			add(u)
		}
	}
	if extra != nil {
		for _, u := range extra(ref) {
			add(u)
		}
	}
	switch len(matches) {
	case 0:
		code := apicontract.CodeScanNotFound
		if table == "agentic_scans" {
			code = apicontract.CodeNotFound
		}
		return "", codedErrorf(code, "no run matches %q", ref)
	case 1:
		return matches[0], nil
	}
	sort.Strings(matches)
	return "", clicommon.CLIError{
		Err:  fmt.Errorf("UUID prefix %q matches %d runs: %s", ref, len(matches), strings.Join(matches, ", ")),
		Code: apicontract.CodeAmbiguousID,
		Hint: "give more characters of the UUID",
	}
}

// sessionDirsWithPrefix lists the session directories under sessionsDir whose
// name starts with prefix: the runs on this host, including scratch-database
// runs whose row no shared store holds.
func sessionDirsWithPrefix(sessionsDir, prefix string) []string {
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(strings.ToLower(e.Name()), prefix) && scanUUIDShape.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}
