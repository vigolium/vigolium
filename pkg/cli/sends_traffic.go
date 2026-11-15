package cli

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

// stampSendsTraffic marks a sending command's document.
func stampSendsTraffic(env *agentEnvelope) {
	if env != nil && commandTraits[env.Command].SendsTraffic {
		env.With("sends_traffic", true)
	}
}

// CheckFollowUpArgv reports why argv is not a safe follow-up for a document
// read from dbPath: it must name a real command, that command must be a read
// (kind read or stream) that sends no traffic, and when the source named a
// database the follow-up must name the same one. Used by the contract tests
// on every query_argv a command emits.
//
// It parses argv against the shared command tree, so calls are serialised.
func CheckFollowUpArgv(root *cobra.Command, argv []string, sourceDB string) error {
	followUpCheckMu.Lock()
	defer followUpCheckMu.Unlock()
	if len(argv) < 2 || argv[0] != "vigolium" {
		return fmt.Errorf("query_argv must start with vigolium and name a command: %q", argv)
	}
	if root == nil {
		root = rootCmd
		prepareCommandTree(root)
	}
	cmd, rest, err := root.Find(argv[1:])
	if err != nil || cmd == nil || cmd == root {
		return fmt.Errorf("query_argv names no command: %q: %w", argv, err)
	}
	if err := cmd.ParseFlags(rest); err != nil {
		return fmt.Errorf("query_argv does not parse: %q: %w", argv, err)
	}
	if err := cmd.ValidateArgs(cmd.Flags().Args()); err != nil {
		return fmt.Errorf("query_argv arguments rejected: %q: %w", argv, err)
	}
	path := commandPathWithoutRoot(cmd)
	t := commandTraits[path]
	switch t.Kind {
	case kindRead, kindStream:
	default:
		return fmt.Errorf("query_argv %q runs %q, which is not a read (kind %q)", argv, path, t.Kind)
	}
	if t.SendsTraffic {
		return fmt.Errorf("query_argv %q runs %q, which sends traffic", argv, path)
	}
	if sourceDB != "" {
		i := slices.Index(argv, "--db")
		if i < 0 || i+1 >= len(argv) || !sameDBPath(argv[i+1], sourceDB) {
			return fmt.Errorf("query_argv %q does not repeat the source's --db %s", argv, sourceDB)
		}
	}
	return nil
}

var followUpCheckMu sync.Mutex

func sameDBPath(a, b string) bool {
	return strings.TrimSpace(absOrRaw(a)) == strings.TrimSpace(absOrRaw(b))
}
