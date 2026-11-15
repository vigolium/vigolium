package cli

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// interactiveAllowed is the fixed set of commands that may declare
// kindInteractive: their output is not a machine document at all. Anything
// else claiming the exemption fails the contract test.
var interactiveAllowed = map[string]string{
	"":                 "root: prints help",
	"help":             "cobra help",
	"kit":              "group: prints help",
	"kit oast":         "group: prints help",
	"oast":             "group: prints help",
	"auth":             "group: prints help (usage error under -j)",
	"config":           "group: prints help (usage error under -j)",
	"db":               "group: prints help (usage error under -j)",
	"project":          "group: prints help (usage error under -j)",
	"server ca":        "group: prints help (usage error under -j)",
	"storage":          "group: prints help (usage error under -j)",
	"agent olium":      "TUI",
	"olium":            "TUI",
	"server":           "long-running service",
	"arjun":            "passthrough shim",
	"dig":              "passthrough shim",
	"host":             "passthrough shim",
	"ffuf":             "passthrough shim",
	"gau":              "passthrough shim",
	"katana":           "passthrough shim",
	"nuclei":           "passthrough shim",
	"skills gen-flags": "hidden dev generator",
}

// knownNonConforming is the ratchet: commands whose -j output does not yet match
// their declared kind, with what they do today. B8 emptied it, and it stays
// empty: a command that regresses (or a new one that ships off-contract) would
// have to be added here, which knownNonConformingCeiling forbids. Fix the
// command instead; test/e2e/machine_contract_e2e_test.go checks the real
// output of every leaf.
var knownNonConforming = map[string]string{}

// knownNonConformingCeiling pins the ratchet's size; it never rises.
const knownNonConformingCeiling = 0

// shadowCheckedFlags are the local flag names that must not shadow a persistent
// one: a local --json silently replaces the global -j on that command.
var shadowCheckedFlags = []string{"json", "pretty", "format"}

// preparedMachineTree returns the finished command tree with cobra's own
// commands in place, exactly as Execute builds it.
func preparedMachineTree(t *testing.T) *cobra.Command {
	t.Helper()
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()
	prepareCommandTree(rootCmd)
	return rootCmd
}

func isInteractiveAllowed(path string) bool {
	if _, ok := interactiveAllowed[path]; ok {
		return true
	}
	// cobra-generated families: `completion <shell>`, `__complete`, `__completeNoDesc`.
	return path == "completion" || strings.HasPrefix(path, "completion ") || strings.HasPrefix(path, "__complete")
}

// TestMachineContractCobraTree: every runnable command declares its -j kind,
// only the fixed list is exempt, no local flag shadows -j/--json, and the
// non-conforming ratchet only shrinks.
func TestMachineContractCobraTree(t *testing.T) {
	root := preparedMachineTree(t)

	runnable := map[string]*cobra.Command{}
	walkTree(root, func(c *cobra.Command) {
		if c.Runnable() {
			runnable[commandPathWithoutRoot(c)] = c
		}
	})
	if len(runnable) < 80 {
		t.Fatalf("walked only %d runnable commands; the tree was not prepared", len(runnable))
	}

	for _, path := range sortedMapKeys(runnable) {
		c := runnable[path]
		t0, ok := commandTraits[path]
		kind := t0.Kind
		if !ok {
			t.Errorf("%q declares no machine kind: add it to commandTraits (command_traits.go)", path)
			continue
		}
		switch machineKind(kind) {
		case kindRead, kindMutation, kindScan, kindStream:
		case kindInteractive:
			if !isInteractiveAllowed(path) {
				t.Errorf("%q claims %q, which is reserved for help, TUIs, the server and shims", path, kind)
			}
		default:
			t.Errorf("%q declares unknown machine kind %q", path, kind)
		}
		if machineKind(kind) == kindInteractive {
			if _, listed := knownNonConforming[path]; listed {
				t.Errorf("%q is interactive and exempt; it does not belong in knownNonConforming", path)
			}
		}

		for _, name := range shadowCheckedFlags {
			f := c.LocalNonPersistentFlags().Lookup(name)
			if f == nil {
				continue
			}
			shadows := name == "json" || root.PersistentFlags().Lookup(name) != nil
			if !shadows {
				continue
			}
			if name == "format" && machineKind(kind) == kindStream {
				continue
			}
			if _, listed := knownNonConforming[path]; listed {
				continue
			}
			t.Errorf("%q defines a local --%s, which shadows the global flag; read the global instead", path, name)
		}
	}

	// The table and the ratchet name real commands only: a stale entry is a
	// declaration nobody checks.
	for path := range commandTraits {
		if _, ok := runnable[path]; !ok {
			t.Errorf("commandTraits declares %q, which is not a runnable command", path)
		}
	}
	for path := range knownNonConforming {
		if _, ok := runnable[path]; !ok {
			t.Errorf("knownNonConforming lists %q, which is not a runnable command", path)
		}
	}
	for path := range interactiveAllowed {
		if commandTraits[path].Kind != kindInteractive {
			t.Errorf("interactiveAllowed lists %q, but commandTraits declares it %q", path, commandTraits[path].Kind)
		}
	}

	if n := len(knownNonConforming); n > knownNonConformingCeiling {
		t.Errorf("knownNonConforming has %d entries, over the ceiling of %d: the ratchet only shrinks — "+
			"make the new command emit its declared kind instead", n, knownNonConformingCeiling)
	} else if n < knownNonConformingCeiling {
		t.Errorf("knownNonConforming shrank to %d: lower knownNonConformingCeiling to %d so it cannot grow back", n, n)
	}
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
