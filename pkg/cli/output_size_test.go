package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// scanDocLike is a scan-shaped envelope: a few small findings and a bulky
// plan, target table and phase outcomes the budget may empty first.
func scanDocLike() *agentEnvelope {
	env := newAgentEnvelope("scan", "findings", budgetItems(3, 16), 3, 0, 3)
	env.Kind = string(kindScan)
	env.With("plan", map[string]any{"phases": strings.Repeat("p", 4000)})
	env.With("targets", []map[string]any{{"url": strings.Repeat("t", 1500)}})
	env.With("phase_outcomes", []map[string]any{{"phase": strings.Repeat("o", 500)}})
	env.droppable = []string{"plan", "targets", "phase_outcomes"}
	return env
}

// A budget below a scan document's floor empties the plan (then the target
// table, then phase outcomes) before it cuts a finding, and says so.
func TestOutputBudgetDropsBulkyKeysBeforeItems(t *testing.T) {
	env := scanDocLike()
	requireBudgetApplied(t, env, 2500)
	doc, parsed := decodeBudgeted(t, env)
	require.LessOrEqual(t, len(doc), 2500)
	require.Nil(t, parsed["plan"])
	require.NotNil(t, parsed["targets"], "only as much as needed is dropped")
	require.Len(t, parsed["items"], 3, "no finding is cut while a droppable key remains")
	report := parsed[outputBudgetKey].(map[string]any)
	require.Equal(t, []any{"plan"}, report["dropped_keys"])
	require.EqualValues(t, 0, report["omitted"])

	env = scanDocLike()
	requireBudgetApplied(t, env, 700)
	_, parsed = decodeBudgeted(t, env)
	report = parsed[outputBudgetKey].(map[string]any)
	require.Equal(t, []any{"plan", "targets", "phase_outcomes"}, report["dropped_keys"])
}

// A failed budget pass restores the keys it emptied.
func TestOutputBudgetRestoresDroppedKeysOnError(t *testing.T) {
	env := scanDocLike()
	_, err := applyOutputBudget(env, 50)
	require.Error(t, err)
	require.Contains(t, err.Error(), "plan, targets, phase_outcomes")
	require.NotNil(t, env.extra["plan"])
	require.NotNil(t, env.extra["targets"])
}

// --compact trims the envelope: the query string, generated_at, db_path and
// a scan document's plan go; query_argv and generated_at_ms stay.
func TestCompactEnvelope(t *testing.T) {
	env := scanDocLike()
	env.DBPath = "/tmp/x.sqlite"
	env.WithQuery("finding", "--scan-uuid", "u")
	compactEnvelope(env)
	raw, err := encodeAgentJSON(env)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	for _, gone := range []string{"query", "generated_at", "db_path"} {
		require.NotContains(t, doc, gone)
	}
	require.Contains(t, doc, "query_argv")
	require.Contains(t, doc, "generated_at_ms")
	require.Contains(t, doc, "plan")
	require.Nil(t, doc["plan"])

	// A document whose plan IS the answer (a dry run) keeps it.
	dry := newAgentEnvelope("scan", "", nil, 0, 0, 0)
	dry.With("plan", map[string]any{"phases": "x"})
	compactEnvelope(dry)
	require.NotNil(t, dry.extra["plan"])
}

// scan status --compact empties the embedded plan and keeps the key, which its
// schema requires.
func TestScanStatusCompactDropsPlan(t *testing.T) {
	prepareCommandTree(rootCmd)
	c, _, err := rootCmd.Find([]string{"scan", "status"})
	require.NoError(t, err)
	require.NotNil(t, c.Flags().Lookup("compact"), "scan status takes --compact")
	require.NotNil(t, c.Flags().Lookup("fields"))

	t.Cleanup(func() { jsonCompact, activeShaping = false, nil })
	jsonCompact = true
	activeShaping = &genericShaping{path: "scan status", ops: []string{shapeOpFields, shapeOpCompact}}
	env := newMachineEnvelope(c, kindRead, ".", []any{scanStatusView{ScanUUID: "u", Status: "running"}}, 1, 0, 1)
	env.objectResult = true
	require.NoError(t, applyGenericShaping(env))
	rows := env.Items.([]map[string]any)
	require.Contains(t, rows[0], "plan")
	require.Nil(t, rows[0]["plan"])
	require.Equal(t, "u", rows[0]["scan_uuid"])
}
