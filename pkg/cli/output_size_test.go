package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/replay"
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
	requireBudgetApplied(t, env, 3000)
	doc, parsed := decodeBudgeted(t, env)
	require.LessOrEqual(t, len(doc), 3000)
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
	env := newMachineEnvelope(c, ".", []any{scanStatusView{ScanUUID: "u", Status: "running"}}, 1, 0, 1)
	env.objectResult = true
	require.NoError(t, applyGenericShaping(env))
	rows := env.Items.([]map[string]any)
	require.Contains(t, rows[0], "plan")
	require.Nil(t, rows[0]["plan"])
	require.Equal(t, "u", rows[0]["scan_uuid"])
}

// finding -j --compact is the survey form: identity, location, severity,
// confidence and the one-line short; the module prose stays out unless
// --fields names it.
func TestCompactFindingViewDropsProse(t *testing.T) {
	f := &database.Finding{
		ID: 4, ModuleID: "m", Severity: "high", Confidence: "firm", URL: "http://x/",
		ModuleShort: "one line", Description: strings.Repeat("d", 900),
		Remediation: "fix it", AdditionalEvidence: []string{"e"},
	}
	full := compactFindingView(f, nil, agentViewOptions{})
	for _, k := range []string{"description", "remediation", "additional_evidence"} {
		require.Contains(t, full, k)
	}
	compact := compactFindingView(f, nil, agentViewOptions{noBodies: true})
	for _, k := range []string{"description", "remediation", "additional_evidence"} {
		require.NotContains(t, compact, k)
	}
	for _, k := range []string{"id", "module_id", "severity", "confidence", "url", "short"} {
		require.Contains(t, compact, k)
	}
	asked := compactFindingView(f, nil, agentViewOptions{noBodies: true, fields: []string{"id", "description"}})
	require.Equal(t, f.Description, asked["description"])
}

// module ls -j: tier and risk_high are derived from the tags; --compact drops
// the long prose (it stays without --compact); --tags answers under -j.
func TestModuleLsShaping(t *testing.T) {
	out, err := runShaped(t, []string{"module", "ls"})
	require.NoError(t, err)
	var doc struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	require.NotEmpty(t, doc.Items)
	tiers := map[string]bool{}
	sawRisk := false
	for _, it := range doc.Items {
		require.Contains(t, it, "description")
		require.Contains(t, it, "tier")
		tiers[it["tier"].(string)] = true
		if it["risk_high"] == true {
			sawRisk = true
		}
	}
	require.True(t, tiers["light"] && tiers["heavy"], "tiers come from the tier tags: %v", tiers)
	require.True(t, sawRisk, "some module carries risk:high")

	out, err = runShaped(t, []string{"module", "ls"}, "--compact")
	require.NoError(t, err)
	doc.Items = nil
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	for _, it := range doc.Items {
		require.NotContains(t, it, "description")
		require.NotContains(t, it, "confirmation_criteria")
		require.Contains(t, it, "short_description")
	}

	out, err = runShaped(t, []string{"module", "ls"}, "--tags")
	require.NoError(t, err)
	doc.Items = nil
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	require.NotEmpty(t, doc.Items)
	require.ElementsMatch(t, []string{"tag", "modules"}, mapKeys(doc.Items[0]))
}

// On a command that sends, a budgeted page points at -o instead of an offset:
// following an offset would send everything again.
func TestOutputBudgetSendingCommandHasNoNextOffset(t *testing.T) {
	env := newAgentEnvelope("replay", "", budgetItems(10, 64), 10, 0, 10)
	requireBudgetApplied(t, env, 600)
	_, parsed := decodeBudgeted(t, env)
	report := parsed[outputBudgetKey].(map[string]any)
	require.NotContains(t, report, "next_offset")
	require.Contains(t, report["full_result"], "-o")

	read := newAgentEnvelope("traffic", "", budgetItems(10, 64), 10, 0, 10)
	requireBudgetApplied(t, read, 600)
	_, parsed = decodeBudgeted(t, read)
	require.Contains(t, parsed[outputBudgetKey], "next_offset")
}

// replay rows carry the replayed status and length at the top level.
func TestReplayOutputTopLevelStatusAndLength(t *testing.T) {
	out := buildReplayOutput(&replaySource{Scheme: "http", Hostname: "x"},
		&replay.Result{Replay: &replay.Summary{Status: 404, ResponseLen: 12}}, 0, nil)
	raw, err := json.Marshal(out)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	require.EqualValues(t, 404, m["status_code"])
	require.EqualValues(t, 12, m["response_content_length"])
	require.NoError(t, validateFieldSelection([]string{"status", "length"}, replayShaping.supported))
}

// fuzz -j lists at most -n results (default 20); --all-results lists every
// result, not only matches, and total counts them; sent_total counts the
// baseline and calibration requests too.
func TestFuzzJSONLimitAndAllResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("same page"))
	}))
	defer srv.Close()
	words := filepath.Join(t.TempDir(), "w.txt")
	require.NoError(t, os.WriteFile(words, []byte("a\nb\nc\nd\ne\n"), 0o600))

	out, err := runShaped(t, []string{"fuzz"}, srv.URL+"/?q=FUZZ", "-w", words, "--all-results", "-n", "2", "--no-calibrate")
	require.NoError(t, err)
	var doc struct {
		Total     int              `json:"total"`
		Sent      int              `json:"sent"`
		SentTotal int              `json:"sent_total"`
		Items     []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), out)
	require.Len(t, doc.Items, 2)
	require.Equal(t, 5, doc.Total, "total counts every result under --all-results")
	require.Equal(t, 5, doc.Sent)
	require.Greater(t, doc.SentTotal, doc.Sent, "the baseline is a send too")
}

// --usage keeps a description's whole first clause: a full stop inside
// parentheses or after an abbreviation is not the end of it.
func TestFirstClauseKeepsExamples(t *testing.T) {
	cases := map[string]string{
		"Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token'). Commas are literal": "Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token')",
		"Module-specific options as key=value (e.g. -a xss.dom=true)":                           "Module-specific options as key=value (e.g. -a xss.dom=true)",
		"Try extensions, e.g. php. More text":                                                   "Try extensions, e.g. php",
		"Per-request timeout; the default is 15s":                                               "Per-request timeout",
		"First sentence. Second":                                                                "First sentence",
		"Range a - b inside (x - y) stays - cut here":                                           "Range a",
	}
	for in, want := range cases {
		require.Equal(t, want, firstClause(in), in)
	}
	require.GreaterOrEqual(t, usageDescMax, 100)
}
