package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/runner"
)

// Execution paths a scan-url/scan-request plan names.
const (
	executionPathRunner = "runner"
	executionPathDirect = "direct"
)

func init() {
	scanURLCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, dryRunUsage+". Names the path the scan would take (execution_path: runner or direct)")
	scanRequestCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, dryRunUsage+". Names the path the scan would take (execution_path: runner or direct); the scheme is not probed")
}

// runLightweightDryRun is --dry-run on scan-url and scan-request: the plan of
// the scan the inputs would get, printed like `scan --dry-run`, with nothing
// sent. The Runner path's plan is the scan plan itself; the direct path is
// described by the same plan, marked execution_path "direct", with a warning
// saying what that path does not do.
func runLightweightDryRun(cmd *cobra.Command, inputs []scanInput) error {
	targets := make([]string, 0, len(inputs))
	for _, in := range inputs {
		targets = append(targets, in.target)
	}
	first := ""
	if len(targets) > 0 {
		first = targets[0]
	}
	opts, err := buildPhaseOptions(first)
	if err != nil {
		return err
	}
	opts.Targets = targets
	opts.Stateless = globalStateless
	settings, err := loadProjectSettings(opts.ConfigPath)
	if err != nil {
		return err
	}
	if !opts.Stateless && globalDB != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = globalDB
	}
	applyGlobalExtFlagsToSettings(settings)
	applyRequestBudgetConfig(settings, opts)
	if err := resolveLightweightScanOptions(settings, opts); err != nil {
		return err
	}

	repo, dbPath, closeDB := openPlanDB(settings)
	defer closeDB()
	plan, err := resolveCLIScanPlan(cmd, opts, settings, opts.ScanningStrategy, repo, true)
	if err != nil {
		return err
	}
	plan.ExecutionPath = executionPathDirect
	if needsRunnerScan() {
		plan.ExecutionPath = executionPathRunner
	} else {
		plan.AddWarning("direct_path",
			"runs in memory: the selected modules over the input request only, with no seed, preflight, other phases or feedback rounds; stored records are not read (-o, --format, -S, --intensity, --auth or a phase flag would take the runner path this plan otherwise describes)")
	}
	if plan.Targets.Seeded > 0 && plan.Targets.Admitted == 0 {
		if !globalJSON {
			renderPlan(os.Stdout, plan)
		}
		return noTargetsInScopeError(runner.AdmitTargets(settings.Scope, targets))
	}
	return printDryRunPlan(cmd, plan, dbPath)
}
