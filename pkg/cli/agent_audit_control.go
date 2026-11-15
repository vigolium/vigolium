package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	auditDryRun      bool
	auditMaxDuration time.Duration
	auditMaxCostUSD  float64
	auditTokenBudget int64
)

// registerAuditControlFlags adds the run-control flags every agent command
// shares: --dry-run and --max-duration. --max-cost-usd and --token-budget are
// accepted only to be refused with a reason: the audit drivers (claude/codex
// via vigolium-audit, pi via piolium) report their usage once, when they
// finish, so a cap could not stop them in time and would promise a limit that
// is not enforced.
func registerAuditControlFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVar(&auditDryRun, "dry-run", false, "Print the resolved drivers, mode chain, source and agent without cloning the source, launching a driver or calling a provider")
	f.DurationVar(&auditMaxDuration, "max-duration", 0, "Maximum wall-clock duration for the whole audit (e.g. 2h; 0 = no limit). Reaching it stops the drivers: status timed_out, exit 5")
	f.Float64Var(&auditMaxCostUSD, "max-cost-usd", 0, "Not supported on audit (its drivers report cost only when they finish)")
	f.Int64Var(&auditTokenBudget, "token-budget", 0, "Not supported on audit (its drivers report usage only when they finish)")
	_ = f.MarkHidden("max-cost-usd")
	_ = f.MarkHidden("token-budget")
}

// rejectAuditBudgetFlags refuses the spend caps audit cannot enforce.
func rejectAuditBudgetFlags(cmd *cobra.Command) error {
	if cmd == nil {
		return nil
	}
	for _, name := range []string{"max-cost-usd", "token-budget"} {
		if cmd.Flags().Changed(name) {
			return usageErrorf("--%s is not supported on audit: its drivers (claude/codex via vigolium-audit, pi via piolium) report usage only when they finish, so the cap could not be enforced; bound the run with --max-duration instead", name)
		}
	}
	return nil
}

// auditDryRunView is what `audit --dry-run` prints.
type auditDryRunView struct {
	Driver        string   `json:"driver"`
	Modes         []string `json:"modes"`
	AuditModes    []string `json:"audit_modes"`
	PioliumModes  []string `json:"piolium_modes"`
	Source        string   `json:"source"`
	Agent         string   `json:"agent,omitempty"`
	SessionsDir   string   `json:"sessions_dir"`
	MaxDurationMS int64    `json:"max_duration_ms"`
	// DriverCheck is "ok", or why the requested driver could not start (the
	// same PATH/binary probe a live run fails fast on).
	DriverCheck string `json:"driver_check"`
	Interactive bool   `json:"interactive,omitempty"`
	Note        string `json:"note"`
}

// printAuditDryRun reports what a live audit would run, without cloning the
// source, creating a session, opening the store or starting a driver.
func printAuditDryRun(cmd *cobra.Command, settings *config.Settings, authOverride agent.AuthOverride) error {
	view := auditDryRunView{
		Driver:        auditDriver,
		Modes:         nonNilStrings(auditModeChain),
		AuditModes:    nonNilStrings(auditDriverModes),
		PioliumModes:  nonNilStrings(auditPioliumModes),
		Source:        auditSource,
		SessionsDir:   settings.Agent.EffectiveSessionsDir(),
		MaxDurationMS: auditMaxDuration.Milliseconds(),
		DriverCheck:   "ok",
		Interactive:   auditInteractive,
		Note:          "dry run: the source was not cloned, no driver was launched and no provider was called",
	}
	if agent.DriverIncludesAudit(auditDriver) {
		view.Agent = string(resolveAuditDriverInvocation(settings.Agent.Olium, settings.Agent.Audit.DefaultAgent, authOverride).Agent)
	}
	if err := ensureAuditDriversFeasible(auditDriver); err != nil {
		view.DriverCheck = err.Error()
	}
	if globalJSON {
		return emitObject(cmd, ".", view)
	}
	fmt.Printf("driver:       %s\n", view.Driver)
	fmt.Printf("modes:        %s\n", agent.JoinModes(view.Modes))
	if len(view.AuditModes) > 0 {
		fmt.Printf("audit leg:    %s (agent %s)\n", agent.JoinModes(view.AuditModes), view.Agent)
	}
	if len(view.PioliumModes) > 0 {
		fmt.Printf("piolium leg:  %s\n", agent.JoinModes(view.PioliumModes))
	}
	fmt.Printf("source:       %s\n", view.Source)
	fmt.Printf("driver check: %s\n", view.DriverCheck)
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), view.Note)
	return nil
}

// auditRunEndFromContext folds a --max-duration deadline or a cancel (agent
// cancel, Ctrl-C) into the audit's run end, so the parent row and the run
// document say timed_out / cancelled rather than a driver failure.
func auditRunEndFromContext(ctx context.Context, end *database.AgenticRunEnd) {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		end.TimedOut = true
	case errors.Is(ctx.Err(), context.Canceled):
		end.Cancelled = true
	}
}
