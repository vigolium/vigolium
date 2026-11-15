package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var storageRmCmd = &cobra.Command{
	Use:     "rm <key> [<key>...]",
	Aliases: []string{"delete"},
	Short:   "Delete one or more objects from cloud storage",
	Long:    "Permanently delete objects from the active project's storage. Prompts for confirmation unless --force is set.",
	Args:    cobra.MinimumNArgs(1),
	RunE:    runStorageRm,
}

func init() {
	storageCmd.AddCommand(storageRmCmd)
}

func runStorageRm(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	sc, projectUUID, err := openStorageClient()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s Will delete %d object(s) from project %s:\n",
		terminal.WarningSymbol(), len(args), terminal.Cyan(projectUUID))
	for _, key := range args {
		fmt.Fprintf(os.Stderr, "  - %s\n", terminal.Gray(key))
	}

	if done, err := handleConfirmation(fmt.Sprintf("deleting %d stored object(s) from project %s",
		len(args), projectUUID)); done {
		if err == nil && globalJSON {
			return emitMutation(cmd, "", mutationResult{Action: "noop", Extra: map[string]any{"aborted": true}},
				withProjectScope(projectUUID))
		}
		return err
	}

	ctx := context.Background()
	out := humanOut()
	var failures int
	items := make([]storageObjectView, 0, len(args))
	for _, key := range args {
		if err := sc.Delete(ctx, projectUUID, key); err != nil {
			failures++
			_, _ = fmt.Fprintf(out, "%s %s: %s\n", terminal.ErrorSymbol(), terminal.Gray(key), err)
			deleted := false
			items = append(items, storageObjectView{Key: key, Deleted: &deleted, Error: err.Error()})
			continue
		}
		_, _ = fmt.Fprintf(out, "%s Deleted %s\n", terminal.SuccessSymbol(), terminal.Gray(key))
		deleted := true
		items = append(items, storageObjectView{Key: key, Deleted: &deleted})
	}

	var failErr error
	if failures > 0 {
		failErr = fmt.Errorf("%d of %d deletion(s) failed", failures, len(args))
	}
	if globalJSON {
		// One document with the per-key outcome; on a partial failure it also
		// carries ok:false and the error, and the exit code still reports it.
		removed := len(args) - failures
		action := "delete"
		if removed == 0 {
			action = "noop"
		}
		opts := []envOpt{withProjectScope(projectUUID)}
		if err := emitMutation(cmd, "", mutationResult{
			Changed: removed > 0,
			Action:  action,
			Items:   items,
			Extra:   map[string]any{"deleted": removed, "failed": failures},
		}, opts...); err != nil {
			return err
		}
	}
	return failErr
}
