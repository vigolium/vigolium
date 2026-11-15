package cli

import (
	"encoding/json"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
)

// machineTestCmd is a throwaway command at path "kit harvest" so the emitters
// derive their `command` from a real-looking cobra path.
func machineTestCmd() *cobra.Command {
	root := &cobra.Command{Use: "vigolium"}
	group := &cobra.Command{Use: "kit"}
	leaf := &cobra.Command{Use: "harvest", RunE: func(*cobra.Command, []string) error { return nil }}
	root.AddCommand(group)
	group.AddCommand(leaf)
	return leaf
}

// emitCaptured runs an emitter with -j state isolated and returns the one
// document it wrote.
func emitCaptured(t *testing.T, emit func() error) map[string]any {
	t.Helper()
	withMachineDocumentState(t)
	globalJSON = true
	var err error
	out := captureStdout(t, func() { err = emit() })
	require.NoError(t, err)
	docs := decodeStdoutDocuments(t, out)
	require.Len(t, docs, 1, "exactly one document")
	return docs[0]
}

func TestEnvelopeItemsNeverNull(t *testing.T) {
	var typedNil []map[string]any
	for name, items := range map[string]any{
		"untyped nil":     nil,
		"typed nil slice": typedNil,
		"nil map":         map[string]any(nil),
	} {
		got := marshalEnvelope(t, newAgentEnvelope("traffic", "", items, 0, 0, 0))
		arr, ok := got["items"].([]any)
		assert.True(t, ok, "%s: items must be an array, got %#v", name, got["items"])
		assert.Empty(t, arr, name)
	}

	// Reassigned after construction (the output budget does this): still [].
	env := newAgentEnvelope("traffic", "", []string{"a"}, 1, 0, 1)
	env.Items = nil
	assert.Equal(t, []any{}, marshalEnvelope(t, env)["items"])
}

func TestEnvelopeObjectItemsBecomeArray(t *testing.T) {
	env := newAgentEnvelope("db stats", "stats", map[string]any{"records": 3}, 1, 0, 1)
	got := marshalEnvelope(t, env)
	assert.Equal(t, []any{map[string]any{"records": float64(3)}}, got["items"])
	assert.False(t, resultIsPaged(env), "one object is not a page")
}

func TestEnvelopeOKAndKind(t *testing.T) {
	got := marshalEnvelope(t, newMachineEnvelope(findingCmd, "", []int{1}, 1, 0, 1))
	assert.Equal(t, true, got["ok"])
	assert.Equal(t, "read", got["kind"])
	assert.NotContains(t, got, "changed", "a read carries no mutation fields")
	assert.NotContains(t, got, "action")
	assert.NotContains(t, got, "dry_run")
}

// The mutation keys are the envelope's own: a command's extra cannot shadow them.
func TestEnvelopeMutationFieldsAreReserved(t *testing.T) {
	for _, key := range []string{"ok", "kind", "changed", "action", "dry_run"} {
		assert.True(t, envelopeFields[key], "%q must be in envelopeFields", key)
	}
	env := newAgentEnvelope("finding", "", nil, 0, 0, 0).With("ok", false).With("changed", true)
	got := marshalEnvelope(t, env)
	assert.Equal(t, true, got["ok"])
	assert.NotContains(t, got, "changed")
}

func TestEmitReadUsesCobraPath(t *testing.T) {
	doc := emitCaptured(t, func() error {
		return emitRead(machineTestCmd(), "urls", []string{"a", "b"}, 2, 0, 2, withExtra("count", 2))
	})
	assert.Equal(t, "kit harvest", doc["command"])
	assert.Equal(t, "read", doc["kind"])
	assert.Equal(t, true, doc["ok"])
	assert.Equal(t, []any{"a", "b"}, doc["items"])
	assert.EqualValues(t, 2, doc["count"])
	assert.NotContains(t, doc, "urls", "legacy alias off by default")
}

func TestEmitObjectLegacyRendering(t *testing.T) {
	obj := map[string]any{"status": "ready", "checks": 4}

	withLegacyKeys(t, false)
	doc := emitCaptured(t, func() error { return emitObject(machineTestCmd(), ".", obj) })
	assert.Equal(t, []any{map[string]any{"status": "ready", "checks": float64(4)}}, doc["items"])
	assert.EqualValues(t, 1, doc["total"])
	assert.NotContains(t, doc, "status", "no flattening without --json-legacy-keys")

	// "." flattens the object back to the top level — the bare-object shape it
	// replaced — without disturbing items or the envelope's own fields.
	withLegacyKeys(t, true)
	doc = emitCaptured(t, func() error {
		return emitObject(machineTestCmd(), ".", map[string]any{"status": "ready", "total": 99, "command": "x"},
			withExtra("status", "from-extra"))
	})
	assert.Equal(t, "from-extra", doc["status"], "the command's own extra wins a collision")
	assert.EqualValues(t, 1, doc["total"], "envelope fields win a collision")
	assert.Equal(t, "kit harvest", doc["command"])
	assert.Len(t, doc["items"], 1)

	// A named alias for an object result renders the object, not [object].
	doc = emitCaptured(t, func() error { return emitObject(machineTestCmd(), "stats", obj) })
	assert.Equal(t, map[string]any{"status": "ready", "checks": float64(4)}, doc["stats"])
}

func TestEmitMutationSpine(t *testing.T) {
	doc := emitCaptured(t, func() error {
		return emitMutation(machineTestCmd(), "", mutationResult{
			Changed: true, Action: "create", Items: nil,
			Extra: map[string]any{"records_ingested": 0},
			Query: []string{"finding"},
		})
	})
	assert.Equal(t, "mutation", doc["kind"])
	assert.Equal(t, true, doc["ok"])
	assert.Equal(t, true, doc["changed"])
	assert.Equal(t, "create", doc["action"])
	assert.Equal(t, []any{}, doc["items"], "nil items render as []")
	assert.NotContains(t, doc, "dry_run")
	assert.Contains(t, doc, "records_ingested")
	assert.Contains(t, doc, "query_argv")

	// A dry run never changed anything, and says so explicitly.
	doc = emitCaptured(t, func() error {
		return emitMutation(machineTestCmd(), "", mutationResult{Changed: true, Action: "delete", DryRun: true})
	})
	assert.Equal(t, false, doc["changed"], "changed is present and false, not omitted")
	assert.Equal(t, true, doc["dry_run"])
}

func TestEnvelopeFromStruct(t *testing.T) {
	type result struct {
		URLs    []string `json:"urls"`
		Domains []string `json:"domains"`
		Count   int      `json:"count"`
		Total   int      `json:"total"` // collides with the envelope's own
	}

	withLegacyKeys(t, false)
	env, err := envelopeFromStruct(machineTestCmd(), result{URLs: []string{"u1", "u2"}, Domains: []string{"d"}, Count: 2, Total: 7}, "urls")
	require.NoError(t, err)
	got := marshalEnvelope(t, env)
	assert.Equal(t, []any{"u1", "u2"}, got["items"])
	assert.EqualValues(t, 2, got["total"], "envelope total counts items; the struct's own total does not shadow it")
	assert.Equal(t, []any{"d"}, got["domains"], "scalar keys stay at the top level under the same names")
	assert.EqualValues(t, 2, got["count"])
	assert.NotContains(t, got, "urls")

	// A nil row slice is [] and the legacy alias is the row field's name.
	withLegacyKeys(t, true)
	env, err = envelopeFromStruct(machineTestCmd(), result{}, "urls")
	require.NoError(t, err)
	got = marshalEnvelope(t, env)
	assert.Equal(t, []any{}, got["items"])
	assert.Equal(t, []any{}, got["urls"])

	// rowsField "" is a single-object result flattened by "." under legacy keys.
	env, err = envelopeFromStruct(machineTestCmd(), result{Count: 3}, "")
	require.NoError(t, err)
	got = marshalEnvelope(t, env)
	assert.Len(t, got["items"], 1)
	assert.EqualValues(t, 3, got["count"])

	_, err = envelopeFromStruct(machineTestCmd(), []int{1}, "urls")
	assert.Error(t, err, "a non-object value cannot be split into items and extras")
}

func TestFindingViewCarriesFindingHash(t *testing.T) {
	assert.Contains(t, findingViewFields, "finding_hash")
	raw, err := json.Marshal(compactFindingView(&database.Finding{FindingHash: "fh-1"}, nil, agentViewOptions{noBodies: true}))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"finding_hash":"fh-1"`)
}
