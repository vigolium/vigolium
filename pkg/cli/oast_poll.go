package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

var (
	oastPollScan  string
	oastPollOpen  bool
	oastPollClose bool
	oastPollWait  time.Duration
)

var oastPollCmd = &cobra.Command{
	Use:   "poll",
	Short: "Collect late out-of-band callbacks for the interactsh sessions scans kept open",
	Long: `Resume the interactsh sessions earlier scans kept open (oast.keep_session,
on by default for scans that persist to a database) and collect the callbacks
that arrived since: a blind XSS rendered later, a queued job, a second-order
injection. Each callback is correlated to the probe that planted it through the
stored payload contexts, rated like a live callback, and saved as a finding of
the scan that planted it.

Pick the sessions with --scan <uuid> (one scan's) or --open (every open session
in the project). --close deregisters the sessions after polling; a closed
session's keys are dropped. 'vigolium server' polls open sessions on its own
every oast.session_poll_interval minutes.`,
	Example: `  vigolium oast poll --open
  vigolium oast poll --scan 3f2a... -j
  vigolium oast poll --open --close`,
	Args: cobra.NoArgs,
	RunE: runOASTPoll,
}

func init() {
	f := oastPollCmd.Flags()
	f.StringVar(&oastPollScan, "scan", "", "Poll the session(s) kept by this scan")
	f.BoolVar(&oastPollOpen, "open", false, "Poll every open session in the project")
	f.BoolVar(&oastPollClose, "close", false, "Deregister each session after polling it")
	f.DurationVar(&oastPollWait, "wait", 3*time.Second, "How long to poll each session")
	oastCmd.AddCommand(oastPollCmd)
}

func runOASTPoll(cmd *cobra.Command, _ []string) error {
	defer closeDatabaseOnExit()
	if (oastPollScan == "") == !oastPollOpen {
		return usageErrorf("oast poll needs exactly one of --scan <uuid> or --open")
	}
	if oastPollWait <= 0 {
		return usageErrorf("--wait must be positive")
	}
	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return err
	}
	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	repo := database.NewRepository(db)
	ctx := context.Background()
	sessions, err := repo.ListOpenOASTSessions(ctx, projectUUID, oastPollScan)
	if err != nil {
		return err
	}
	var findings []*output.ResultEvent
	results := oast.PollSessions(ctx, repo, sessions, oast.PollOptions{
		Wait:  oastPollWait,
		Close: oastPollClose,
		Emit:  func(ev *output.ResultEvent) { findings = append(findings, ev) },
	})

	if globalJSON {
		correlated := 0
		for _, r := range results {
			correlated += r.Correlated
		}
		return emitMutation(cmd, "", mutationResult{
			Changed: correlated > 0 || oastPollClose && len(results) > 0,
			Action:  "import",
			Items:   results,
			Extra: map[string]any{
				"sessions":   len(results),
				"correlated": correlated,
				"findings":   len(findings),
			},
		}, withProjectScope(projectUUID), withDBPath(resolvedReadDBPath()))
	}
	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "%s no open OAST sessions to poll\n", terminal.InfoSymbol())
		return nil
	}
	for _, r := range results {
		fmt.Printf("%s %s\n", terminal.InfoSymbol(), r.String())
	}
	for _, f := range findings {
		fmt.Printf("%s %s %s %s\n", terminal.SuccessSymbol(), terminal.BoldYellow(f.Info.Severity.String()), f.ModuleID, f.URL)
	}
	return nil
}

// pollOASTSessions polls every project's open sessions once (the server's
// periodic poll); findings go to the store only.
func pollOASTSessions(ctx context.Context, repo *database.Repository) int {
	sessions, err := repo.ListOpenOASTSessions(ctx, "", "")
	if err != nil || len(sessions) == 0 {
		return 0
	}
	correlated := 0
	for _, r := range oast.PollSessions(ctx, repo, sessions, oast.PollOptions{}) {
		correlated += r.Correlated
	}
	if correlated > 0 {
		zap.L().Info("OAST: periodic poll correlated late callbacks", zap.Int("callbacks", correlated))
	}
	return correlated
}

// runOASTSessionPoller runs poll every interval until ctx ends.
func runOASTSessionPoller(ctx context.Context, repo *database.Repository, every time.Duration, poll func(context.Context, *database.Repository) int) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll(ctx, repo)
		}
	}
}
