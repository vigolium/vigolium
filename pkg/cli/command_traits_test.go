package cli

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

// TestCommandTraitsShapes is the static half of the shaping guardrail: every
// read declares how its -j document can be narrowed, and once the tree is
// prepared every shaped read accepts the flags its shape promises. The runtime
// half (`--fields bogus` exits 2 on every shaped read) is in the e2e contract
// matrix.
func TestCommandTraitsShapes(t *testing.T) {
	prepareCommandTree(rootCmd)
	byPath := map[string]*cobra.Command{}
	walkTree(rootCmd, func(c *cobra.Command) { byPath[commandPathWithoutRoot(c)] = c })

	for path, tr := range commandTraits {
		s := tr.Shape
		switch tr.Kind {
		case kindRead, kindStream:
			if s.Kind == "" {
				t.Errorf("%q is a %s command with no Shape: declare rowsShape(), objectShape() or noShape(reason)", path, tr.Kind)
				continue
			}
		case kindScan:
			if s.Kind == "" {
				t.Errorf("%q is a scan command with no Shape (scanDocumentShape or noShape(reason))", path)
				continue
			}
		default:
			if s.Kind != "" && s.Kind != shapeNone {
				t.Errorf("%q is %s; only reads, streams and scans are shaped", path, tr.Kind)
			}
			continue
		}
		if s.Kind == shapeNone {
			if s.Reason == "" {
				t.Errorf("%q declares no shape without saying why", path)
			}
			continue
		}
		if s.Kind == shapeRows && s.Paging == pagingNone && s.Reason == "" {
			t.Errorf("%q is unpaged without saying why", path)
		}
		vocab := s.staticVocab(path)
		if s.generic() && tr.SendsTraffic && vocab == nil {
			t.Errorf("%q sends traffic, so its --fields vocabulary must be known before it runs: declare vocabFrom(T{}) or register its schema", path)
		}
		if vocab != nil {
			for _, k := range s.CompactDrop {
				if !slices.Contains(vocab, k) {
					t.Errorf("%q --compact drops %q, which is not in its vocabulary", path, k)
				}
			}
		}

		c := byPath[path]
		if c == nil {
			t.Errorf("commandTraits names %q, which is not a command", path)
			continue
		}
		want := []string{"fields"}
		if s.Kind == shapeRows {
			want = append(want, "compact", "max-output-bytes")
			if s.Paging != pagingNone {
				want = append(want, "limit", "offset")
			}
		}
		for _, name := range want {
			if !hasFlag(c, name) {
				t.Errorf("%q has a %s shape (paging %s) but no --%s", path, s.Kind, s.Paging, name)
			}
		}
		if s.Own && slices.Contains(shapingOps(c), shapeOpFields) {
			t.Errorf("%q projects its own rows (Own) but --fields was registered generically", path)
		}
	}
}

func shapingOps(c *cobra.Command) []string {
	raw := c.Annotations[shapingAnnotation]
	if raw == "" {
		return nil
	}
	return bytesSplitComma(raw)
}

func bytesSplitComma(s string) []string {
	var out []string
	for _, p := range bytes.Split([]byte(s), []byte(",")) {
		out = append(out, string(p))
	}
	return out
}

// TestDerivedTraitViews: the per-concern tables the package reads are views of
// commandTraits, so they name exactly its commands.
func TestDerivedTraitViews(t *testing.T) {
	require.Len(t, machineKinds, len(commandTraits))
	require.Len(t, dbIntents, len(commandTraits))
	require.Len(t, MachineContractCommands(), len(commandTraits))
	for path, tr := range commandTraits {
		require.Equal(t, tr.Kind, machineKinds[path], path)
		require.Equal(t, tr.DB, dbIntents[path], path)
		require.Equal(t, tr.SendsTraffic, sendsTrafficCommands[path], path)
	}
}

// TestGenericShapingModuleLs: module ls had no shaping at all; the generic
// pass gives it --fields, --compact, -n/--offset and applies them.
func TestGenericShapingModuleLs(t *testing.T) {
	out, err := runShaped(t, []string{"module", "ls"}, "--fields", "id,type", "-n", "2", "--offset", "1")
	require.NoError(t, err)
	var doc struct {
		Total  int64            `json:"total"`
		Offset int              `json:"offset"`
		Limit  int              `json:"limit"`
		Items  []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), out)
	require.Len(t, doc.Items, 2)
	require.Equal(t, 1, doc.Offset)
	require.Equal(t, 2, doc.Limit)
	require.Greater(t, doc.Total, int64(2))
	for _, it := range doc.Items {
		require.ElementsMatch(t, []string{"id", "type"}, mapKeys(it))
	}

	_, err = runShaped(t, []string{"module", "ls"}, "--fields", "bogus")
	require.Error(t, err)
	require.Equal(t, ExitUsageError, classifyExitCode(err))
}

func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// runShaped parses flags on the command at path, runs the generic shaping
// check the root pre-run does, then the command's RunE under -j, and returns
// stdout. Every flag it touches is reset afterwards.
func runShaped(t *testing.T, path []string, flags ...string) (string, error) {
	t.Helper()
	prepareCommandTree(rootCmd)
	c, _, err := rootCmd.Find(path)
	require.NoError(t, err)
	t.Setenv("HOME", t.TempDir())
	prevJSON := globalJSON
	globalJSON = true
	reset := func() {
		jsonFields, jsonCompact, maxOutputBytes, shapeLimit, shapeOffset = nil, false, 0, 0, 0
		activeShaping = nil
		c.Flags().VisitAll(resetFlagToDefault)
	}
	reset()
	t.Cleanup(func() {
		globalJSON = prevJSON
		reset()
	})
	require.NoError(t, c.ParseFlags(flags))
	if err := validateGenericShaping(c); err != nil {
		return "", err
	}
	var runErr error
	out := captureStdout(t, func() { runErr = c.RunE(c, c.Flags().Args()) })
	return out, runErr
}

// resetFlagToDefault puts a parsed flag back to its default value.
func resetFlagToDefault(f *pflag.Flag) {
	if !f.Changed {
		return
	}
	if sv, ok := f.Value.(pflag.SliceValue); ok {
		_ = sv.Replace(nil)
	} else {
		_ = f.Value.Set(f.DefValue)
	}
	f.Changed = false
}
