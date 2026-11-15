package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// Guardrail: every command group rejects an unknown subcommand with a usage
// error (exit 2) naming the nearest subcommand. A group with no positional of
// its own rejects any word; a group whose bare form takes a filter word rejects
// a near miss of one of its subcommands.
func TestGroupsRejectUnknownSubcommand(t *testing.T) {
	root := preparedMachineTree(t)
	groups := 0
	walkTree(root, func(c *cobra.Command) {
		if c == root || !c.HasSubCommands() {
			return
		}
		groups++
		path := commandPathWithoutRoot(c)
		require.Truef(t, c.Runnable(), "%s: a group must be runnable, or cobra prints help and exits 0 before checking Args", path)

		subs := subcommandNames(c)
		require.NotEmpty(t, subs, path)
		nearMiss := subs[0] + "x"
		err := c.ValidateArgs([]string{nearMiss})
		require.Errorf(t, err, "%s %s: a near miss of a subcommand must be rejected", path, nearMiss)
		require.Equalf(t, ExitUsageError, classifyExitCode(err), "%s: %v", path, err)
		var cli clicommon.CLIError
		require.Truef(t, errors.As(err, &cli), "%s: a structured error", path)
		require.Equalf(t, path+" "+subs[0], cli.DidYouMean, "%s", path)
		require.NotEmpty(t, cli.UsageArgv)

		if groupTakesNoPositional(c) {
			err := c.ValidateArgs([]string{"zzqqbogus"})
			require.Errorf(t, err, "%s: an unknown word must be rejected", path)
			require.Equal(t, ExitUsageError, classifyExitCode(err))
			require.True(t, strings.HasPrefix(err.Error(), "unknown command"), err.Error())
		}
	})
	require.Greater(t, groups, 10)
}

// groupTakesNoPositional reports whether c rejects any positional word (it has
// no filter form of its own).
func groupTakesNoPositional(c *cobra.Command) bool {
	return c.ValidateArgs([]string{"zzqqbogus"}) != nil
}

// Every positional-argument error is a usage error (exit 2), including cobra's
// own count validators.
func TestArgsValidatorsAreUsageErrors(t *testing.T) {
	root := preparedMachineTree(t)
	checked := 0
	walkTree(root, func(c *cobra.Command) {
		if c.Args == nil {
			return
		}
		for _, args := range [][]string{nil, {"a", "b", "c", "d", "e", "f", "g", "h"}} {
			err := c.ValidateArgs(args)
			if err == nil {
				continue
			}
			checked++
			require.Equalf(t, ExitUsageError, classifyExitCode(err), "%s %q: %v", c.CommandPath(), args, err)
		}
	})
	require.Greater(t, checked, 20)
}

// The pure group's bare form is help for a human and a usage error under -j.
func TestPureGroupBareFormUnderJSON(t *testing.T) {
	withMachineDocumentState(t)
	root := preparedMachineTree(t)
	cfg, _, err := root.Find([]string{"db"})
	require.NoError(t, err)
	globalJSON = true
	err = cfg.RunE(cfg, nil)
	require.Error(t, err)
	require.Equal(t, ExitUsageError, classifyExitCode(err))
}

// enumValue rejects a value outside its set while flags parse, with the
// valid values and the nearest one.
func TestEnumFlagRejectsUnknownValue(t *testing.T) {
	c := &cobra.Command{Use: "x"}
	root := &cobra.Command{Use: "vigolium"}
	root.AddCommand(c)
	c.SetFlagErrorFunc(flagErrorFunc)
	var sort string
	var sev []string
	c.Flags().StringVar(&sort, "sort", "", "")
	c.Flags().StringSliceVar(&sev, "severity", nil, "")
	enumFlag(c.Flags(), "sort", []string{"newest", "oldest"}, enumAllowEmpty())
	enumFlag(c.Flags(), "severity", []string{"info", "low", "medium", "high", "critical"})

	require.NoError(t, c.ParseFlags([]string{"--sort", "NEWEST", "--severity", "high,critical"}))
	require.Equal(t, []string{"high", "critical"}, sev)
	require.Equal(t, "string", c.Flags().Lookup("sort").Value.Type(), "the type is unchanged")
	require.Equal(t, []string{"newest", "oldest"}, flagEnumValues(c.Flags().Lookup("sort")))

	err := parseErr(t, c, "--severity", "high,higj")
	require.Error(t, err)
	require.Equal(t, ExitUsageError, classifyExitCode(err))
	var cli clicommon.CLIError
	require.True(t, errors.As(err, &cli))
	require.Equal(t, "high", cli.DidYouMean)
	require.Contains(t, cli.Fact(), "must be one of: info, low, medium, high, critical")
}

// Guardrail: every flag that declares a closed set rejects a value outside it,
// and every flag known to be closed declares its set.
func TestEnumFlagsRejectUnknownValues(t *testing.T) {
	root := preparedMachineTree(t)
	seen := map[string]bool{}
	walkTree(root, func(c *cobra.Command) {
		path := commandPathWithoutRoot(c)
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			allowed := flagEnumValues(f)
			if allowed == nil {
				return
			}
			seen[strings.TrimSpace(path+" --"+f.Name)] = true
			ev, ok := f.Value.(*enumValue)
			require.Truef(t, ok, "%s --%s: annotated but not validated", path, f.Name)
			require.Errorf(t, ev.Set("zz-not-a-value"), "%s --%s must reject an unknown value", path, f.Name)
		})
	})
	for _, want := range requiredEnumFlags {
		require.Truef(t, seen[want], "%q has a closed value set and must be an enum flag (enumFlag)", want)
	}
}

// requiredEnumFlags are flags whose value set is closed: each must be an enum
// flag. "<path> --<name>"; a persistent flag is listed under the command that
// declares it.
var requiredEnumFlags = []string{
	"finding --severity", "finding --sort", "traffic --sort", "db list --severity", "db list --sort",
	"db export --severity", "db clean --severity", "export --severity", "import --severity",
	"replay --sort", "module --type", "module ls --type", "fuzz --mode",
	"agent query --provider", "agent autopilot --provider",
}

// cobra's root-level unknown command becomes the structured error: the fact as
// message, the suggestion as did_you_mean.
func TestStructureUnknownCommand(t *testing.T) {
	root := preparedMachineTree(t)
	_, _, err := root.Find([]string{"scna"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Did you mean this?")
	out := structureUnknownCommand(root, err)
	var cli clicommon.CLIError
	require.True(t, errors.As(out, &cli))
	require.Equal(t, `unknown command "scna" for "vigolium"`, cli.Fact())
	require.Equal(t, "scan", cli.DidYouMean)
	require.Equal(t, ExitUsageError, classifyExitCode(out))
}
