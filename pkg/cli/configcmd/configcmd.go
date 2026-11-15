// Package configcmd implements the `vigolium config` command group.
//
// It is the first command group split out of the flat pkg/cli package into its
// own subpackage. Rather than self-registering via init() into a package-private
// rootCmd, it exposes an explicit NewCommand(deps, examples) constructor that
// pkg/cli wires onto the root command. All of the implicit package-global state
// the commands previously reached for (the --config / --force flag values and
// the first-run reinitializer) is passed in explicitly via Deps, so this package
// has no dependency back on pkg/cli.
package configcmd

import (
	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
)

// Deps carries the runtime dependencies the config commands need, injected by
// pkg/cli so this package stays decoupled from the CLI's global flag state.
type Deps struct {
	// ConfigFlag returns the raw --config flag value (may be empty).
	ConfigFlag func() string
	// Force returns the --force flag value.
	Force func() bool
	// Reinitialize regenerates ~/.vigolium with fresh defaults (used by `config clean`).
	Reinitialize func() error

	// JSON reports whether the caller asked for machine output. The config
	// commands accepted the persistent --json flag and ignored it, printing
	// ANSI-colored prose to stdout and exiting 0 — so a consumer's parse failed
	// for a reason the exit code did not describe.
	JSON func() bool
	// WriteJSON emits a result through the CLI's shared envelope writer, so a
	// config result has the same schema_version/items/generated_at spine as every
	// other -j payload rather than a second shape invented here. total is the row
	// count, which the caller already knows — passing it avoids reflecting over
	// the slice on the other side of the seam. cmd names the document.
	WriteJSON func(cmd *cobra.Command, legacyKey string, items any, total int, extra map[string]any) error
	// WriteMutation emits a state-changing command's result through the CLI's
	// mutation spine (kind "mutation", changed, action, dry_run). changed and
	// action are arguments, not extras: the envelope owns those keys, and an
	// extra named "changed" is dropped rather than rendered.
	WriteMutation func(cmd *cobra.Command, items any, changed bool, action string, extra map[string]any) error
	// WriteDryRunMutation is WriteMutation for a --dry-run: dry_run true and
	// changed false.
	WriteDryRunMutation func(cmd *cobra.Command, items any, action string, extra map[string]any) error

	// RecentScanTargets returns the targets of the n most recent scans in the
	// given project ("" = the project the CLI resolves by default), for
	// `config validate`'s scope_include_matches_no_recent_target rule. Injected
	// because this package cannot reach the database. nil, or an error (no
	// database yet), skips the rule.
	RecentScanTargets func(projectUUID string, n int) ([]string, error)

	// ProjectSettings loads the settings a scan in the invocation's project
	// runs under (global config, then the project overlay) and names that
	// project ("" = no overlay). nil falls back to the global config alone.
	ProjectSettings func() (*config.Settings, string, error)
	// FlagKeys lists the settings keys a global flag of this invocation sets
	// (--db → database.sqlite.path), for the provenance column.
	FlagKeys func() []string
}

// loadSettings is ProjectSettings, or the global config when it is not wired.
func (d Deps) loadSettings() (*config.Settings, string, error) {
	if d.ProjectSettings != nil {
		return d.ProjectSettings()
	}
	s, err := config.LoadSettings(d.ConfigFlag())
	return s, "", err
}

// jsonRequested reports whether machine output was asked for, tolerating a Deps
// built without the hooks (older callers, tests).
func (d Deps) jsonRequested() bool {
	return d.JSON != nil && d.WriteJSON != nil && d.JSON()
}

// mutationJSONRequested is jsonRequested for the mutation writer.
func (d Deps) mutationJSONRequested() bool {
	return d.JSON != nil && d.WriteMutation != nil && d.JSON()
}

// Examples carries the per-command example blocks, defined in pkg/cli.
type Examples struct {
	Parent   string
	Ls       string
	Set      string
	Clean    string
	Validate string
}

// NewCommand builds the `config` command group with its subcommands.
func NewCommand(deps Deps, ex Examples) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "config",
		Short:   "Manage configuration",
		Long:    "Inspect and edit Vigolium settings stored in ~/.vigolium/vigolium-configs.yaml. Subcommands list current values, set keys via dot-notation, validate the effective settings, and reset to clean defaults.",
		Example: ex.Parent,
	}
	cmd.AddCommand(
		newLsCmd(deps, ex.Ls),
		newSetCmd(deps, ex.Set),
		newCleanCmd(deps, ex.Clean),
		newValidateCmd(deps, ex.Validate),
		newEnvCmd(deps),
		newGetCmd(deps),
		newUnsetCmd(deps),
	)
	return cmd
}
