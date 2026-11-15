package cli

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/configcmd"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// wire.go registers command groups that have been extracted into their own
// subpackages. Unlike the legacy in-package commands (which self-register via
// init() onto rootCmd), subpackaged groups expose an explicit constructor and
// receive their dependencies here, where the CLI's global flag state lives.
//
// As more groups move out of the flat pkg/cli package they should be wired the
// same way, until rootCmd's children are assembled entirely from explicit
// constructors and the per-file init() registrations are gone.
func init() {
	rootCmd.AddCommand(configcmd.NewCommand(
		configcmd.Deps{
			ConfigFlag: func() string { return globalConfig },
			Force:      func() bool { return globalForce },
			// Always with the default database: `config clean` has just deleted
			// ~/.vigolium, default store included, so regenerating without it
			// would leave the install short of a file the user did not ask to
			// lose. A pinned --db names a different file, which clean never
			// touched.
			Reinitialize:      func() error { return initializeVigolium(true) },
			JSON:              func() bool { return globalJSON },
			WriteJSON:         writeConfigEnvelope,
			WriteMutation:     writeConfigMutation,
			RecentScanTargets: recentScanTargets,
			ProjectSettings:   configProjectSettings,
			FlagKeys:          configFlagKeys,
		},
		configcmd.Examples{
			Parent:   configExamples,
			Ls:       configLsExamples,
			Set:      configSetExamples,
			Clean:    configCleanExamples,
			Validate: configValidateExamples,
		},
	))
}

// writeConfigEnvelope lets the extracted config group emit through the CLI's
// shared -j envelope without importing pkg/cli. Passing the writer rather than
// the envelope type keeps the dependency pointing one way, and means a config
// result carries the same schema_version/items/generated_at spine as every other
// machine payload instead of a second shape invented in that package.
func writeConfigEnvelope(cmd *cobra.Command, legacyKey string, items any, total int, extra map[string]any) error {
	env := newMachineEnvelope(cmd, kindRead, legacyKey, items, int64(total), 0, total)
	for k, v := range extra {
		env.With(k, v)
	}
	return writeAgentJSON(env)
}

// writeConfigMutation is writeConfigEnvelope for the state-changing config
// commands: the same envelope through the mutation spine.
func writeConfigMutation(cmd *cobra.Command, items any, changed bool, action string, extra map[string]any) error {
	return emitMutation(cmd, "", mutationResult{Changed: changed, Action: action, Items: items, Extra: extra})
}

// recentScanTargets feeds `config validate`'s recent-target scope rule. It
// opens the store with read intent and never creates one: a SQLite file that
// does not exist yet answers with an error, which the rule treats as "skip" —
// validating configuration must not leave a fresh database behind.
func recentScanTargets(projectUUID string, n int) ([]string, error) {
	cfg, err := clicommon.ResolveDatabaseConfig(globalConfig, globalDB)
	if err != nil {
		return nil, err
	}
	if cfg.Driver == "sqlite" {
		if _, err := os.Stat(database.ExpandPath(cfg.SQLite.Path)); err != nil {
			return nil, err
		}
	}
	db, err := getDBFor(clicommon.IntentRead)
	if err != nil {
		return nil, err
	}
	defer closeDatabaseOnExit()
	if projectUUID == "" {
		if projectUUID, err = resolveProjectUUID(); err != nil {
			return nil, err
		}
	}
	scans, _, err := database.NewRepository(db).ListScans(context.Background(), projectUUID, n, 0)
	if err != nil {
		return nil, err
	}
	targets := make([]string, 0, len(scans))
	for _, sc := range scans {
		if sc.Target != "" {
			targets = append(targets, sc.Target)
		}
	}
	return targets, nil
}
