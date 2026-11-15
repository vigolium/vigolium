package cli

import (
	"encoding/json"
	"errors"
	"math/rand"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/apicontract"
)

// budgetItems builds n rows of roughly size bytes each, so a test can state its
// budget in bytes and know how many rows that is.
func budgetItems(n, size int) []map[string]any {
	out := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, map[string]any{
			"id":   i,
			"body": strings.Repeat("x", size),
		})
	}
	return out
}

// requireBudgetApplied runs the budget pass and asserts it succeeded.
//
// It also pins the invariant writeAgentJSON now relies on: when the pass hands
// back a document, those bytes ARE what the value encodes to afterwards. The
// caller emits them instead of re-encoding, so a drift between the measured
// document and the emitted one would ship a document the budget never saw.
func requireBudgetApplied(t *testing.T, v any, budget int, msgAndArgs ...any) {
	t.Helper()
	doc, err := applyOutputBudget(v, budget)
	require.NoError(t, err, msgAndArgs...)
	if doc == nil {
		return
	}
	again, err := encodeAgentJSON(v)
	require.NoError(t, err)
	require.Equal(t, string(again), string(doc),
		"the measured document must be the document that gets emitted")
}

// decodeBudgeted parses the document an envelope would emit.
func decodeBudgeted(t *testing.T, env *agentEnvelope) ([]byte, map[string]any) {
	t.Helper()
	doc, err := encodeAgentJSON(env)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(doc, &parsed), "the budgeted document must still be valid JSON")
	return doc, parsed
}

// TestOutputBudgetTruncatesAtRecordBoundary is the central guarantee: the
// document that comes back is under the budget, is parseable, and says what it
// dropped.
//
// Cutting at a byte offset would be far simpler and completely useless — the
// caller would get a prefix of a JSON object, which is not JSON. The budget
// exists for callers who cannot pick a safe -n/--limit because row sizes vary
// by three orders of magnitude, and a truncated document would leave them worse
// off than the size they were trying to avoid.
func TestOutputBudgetTruncatesAtRecordBoundary(t *testing.T) {
	const budget = 4096
	env := newAgentEnvelope("finding", "findings", budgetItems(10, 1024), 10, 0, 10)

	requireBudgetApplied(t, env, budget)

	doc, parsed := decodeBudgeted(t, env)
	assert.LessOrEqual(t, len(doc), budget, "the emitted document must fit the budget it was given")

	report, ok := parsed["output_budget"].(map[string]any)
	require.True(t, ok, "a truncated document must say so; got keys %v", parsed)
	returned := int(report["returned"].(float64))
	omitted := int(report["omitted"].(float64))
	assert.Equal(t, 10, returned+omitted, "every item is either returned or accounted for as omitted")
	assert.Equal(t, float64(budget), report["max_bytes"])
	assert.Equal(t, float64(returned), report["next_offset"], "offset 0 + returned")

	items, ok := parsed["items"].([]any)
	require.True(t, ok)
	assert.Equal(t, returned, len(items), "the report must describe the items actually present")
	assert.Greater(t, returned, 0, "a 4 KiB budget fits at least one 1 KiB row")
}

// TestOutputBudgetLeavesTotalAlone: `total` describes the result set, not the
// page. Leaving it is what makes resultIsPaged and the -o receipt report
// complete:false for a budgeted document, exactly as they do for one cut by
// -n/--limit.
func TestOutputBudgetLeavesTotalAlone(t *testing.T) {
	env := newAgentEnvelope("traffic", "records", budgetItems(10, 1024), 10, 0, 10)
	requireBudgetApplied(t, env, 4096)

	assert.Equal(t, int64(10), env.Total)
	assert.True(t, resultIsPaged(env), "a budgeted page is a page")
}

// TestOutputBudgetZeroIsUnlimited: the default must change nothing at all. A
// consumer that never passes the flag must get a byte-identical document.
func TestOutputBudgetZeroIsUnlimited(t *testing.T) {
	items := budgetItems(10, 1024)
	env := newAgentEnvelope("finding", "findings", items, 10, 0, 10)
	before, err := encodeAgentJSON(env)
	require.NoError(t, err)

	requireBudgetApplied(t, env, 0)

	after, err := encodeAgentJSON(env)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after))
	assert.NotContains(t, string(after), "output_budget")
}

// TestOutputBudgetLeavesAFittingResultUntouched: a budget that does not bind
// must not add a report. An output_budget object on every document would make
// "this was truncated" unobservable.
func TestOutputBudgetLeavesAFittingResultUntouched(t *testing.T) {
	env := newAgentEnvelope("finding", "findings", budgetItems(2, 16), 2, 0, 10)
	requireBudgetApplied(t, env, 1<<20)

	_, parsed := decodeBudgeted(t, env)
	assert.NotContains(t, parsed, "output_budget")
	items := parsed["items"].([]any)
	assert.Len(t, items, 2)
}

// TestOutputBudgetTooSmallIsCoded: a budget below the envelope's fixed cost
// cannot be satisfied by dropping items, so it fails with a code a driver can
// branch on rather than emitting an over-budget document and hoping.
func TestOutputBudgetTooSmallIsCoded(t *testing.T) {
	env := newAgentEnvelope("finding", "findings", budgetItems(5, 64), 5, 0, 10)

	_, err := applyOutputBudget(env, 10)
	require.Error(t, err)

	var coded codedError
	require.True(t, errors.As(err, &coded))
	assert.Equal(t, apicontract.CodeOutputTooLarge, coded.Code())
	assert.Contains(t, err.Error(), "--max-output-bytes")
}

// TestOutputBudgetRestoresItemsOnError: a failed budget pass must leave the
// envelope as it found it. The search mutates Items to measure, and a prefix
// left behind by an aborted search would silently shorten the error path's
// document.
func TestOutputBudgetRestoresItemsOnError(t *testing.T) {
	items := budgetItems(5, 64)
	env := newAgentEnvelope("finding", "findings", items, 5, 0, 10)

	_, err := applyOutputBudget(env, 10)
	require.Error(t, err)

	got, ok := env.Items.([]map[string]any)
	require.True(t, ok)
	assert.Len(t, got, 5, "the envelope must be unchanged after a rejected budget")
	assert.NotContains(t, env.extra, outputBudgetKey)
}

// TestOutputBudgetCountsItsOwnReport is the subtle one. The output_budget
// object is itself bytes in the document, so a search that measures without it
// and attaches it afterwards produces a document larger than the budget — by
// the very field that announces the budget.
func TestOutputBudgetCountsItsOwnReport(t *testing.T) {
	// A budget just above the floor, so the report's own ~120 bytes are a large
	// fraction of the slack and an uncounted report would overshoot.
	env := newAgentEnvelope("finding", "findings", budgetItems(40, 32), 40, 0, 40)
	floor := newAgentEnvelope("finding", "findings", []map[string]any{}, 40, 0, 40)
	base, err := encodeAgentJSON(floor)
	require.NoError(t, err)

	budget := len(base) + 400
	requireBudgetApplied(t, env, budget)

	doc, parsed := decodeBudgeted(t, env)
	require.Contains(t, parsed, "output_budget")
	assert.LessOrEqual(t, len(doc), budget,
		"the measured size must include the output_budget object the document carries")
}

// TestOutputBudgetIgnoresNonSliceDocuments: `db stats` emits an object, not a
// row list. There is no record boundary to cut on, and failing a command whose
// shape the budget cannot address is worse than shipping it whole.
func TestOutputBudgetIgnoresNonSliceDocuments(t *testing.T) {
	env := newAgentEnvelope("db", "", map[string]any{"rows": 1}, 1, 0, 1)
	requireBudgetApplied(t, env, 8)

	receipt := map[string]any{"artifact": "json_result"}
	requireBudgetApplied(t, receipt, 8, "a non-envelope document is left alone too")
}

// TestOutputBudgetHandlesTypedSlices: the scan listings carry typed rows, not
// []map[string]any. The reflect-based search covers them, and resultIsPaged now
// does too — it used to call every paged scan listing complete.
func TestOutputBudgetHandlesTypedSlices(t *testing.T) {
	type row struct {
		ID   int    `json:"id"`
		Body string `json:"body"`
	}
	rows := make([]row, 0, 10)
	for i := range 10 {
		rows = append(rows, row{ID: i, Body: strings.Repeat("y", 1024)})
	}
	env := newAgentEnvelope("db", "scans", rows, 10, 0, 10)

	requireBudgetApplied(t, env, 4096)

	doc, parsed := decodeBudgeted(t, env)
	assert.LessOrEqual(t, len(doc), 4096)
	require.Contains(t, parsed, "output_budget")
	assert.True(t, resultIsPaged(env))
}

// TestOutputBudgetFlagValidation covers the two ways the flag is meaningless:
// a negative size, and a budget on an invocation that emits no JSON document.
// A silently ignored budget is indistinguishable from one that did not bind.
func TestOutputBudgetFlagValidation(t *testing.T) {
	orig := maxOutputBytes
	t.Cleanup(func() { maxOutputBytes = orig })

	maxOutputBytes = 0
	assert.NoError(t, validateOutputBudgetFlag(false), "unset is always fine")

	maxOutputBytes = -1
	err := validateOutputBudgetFlag(true)
	require.Error(t, err)
	assert.Equal(t, ExitUsageError, classifyExitCode(err))

	maxOutputBytes = 4096
	err = validateOutputBudgetFlag(false)
	require.Error(t, err)
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
	assert.Contains(t, err.Error(), "--json")

	assert.NoError(t, validateOutputBudgetFlag(true))
}

// TestOutputBudgetFlagRegisteredOnReadCommands: the flag is only useful where a
// result document is produced, and it must be on all three of them.
func TestOutputBudgetFlagRegisteredOnReadCommands(t *testing.T) {
	for _, path := range [][]string{{"finding"}, {"traffic"}, {"db", "ls"}} {
		cmd, _, err := rootCmd.Find(path)
		require.NoError(t, err)
		assert.NotNil(t, cmd.Flags().Lookup("max-output-bytes"),
			"%s emits a -j result document and must accept a budget", strings.Join(path, " "))
	}
}

// TestOutputBudgetSearchIsMaximalAndUnderBudget property-tests the search
// against a brute-force reference over random item sizes and random budgets.
//
// The search was rewritten to split measurement from application (so the winning
// state is restored without one more full encode) and to hand its bytes back to
// the caller. Both are easy to get subtly wrong — an off-by-one in the winner,
// or returning the document for a k the envelope is no longer in — and neither
// shows up on a fixed fixture. The reference encodes every prefix and takes the
// largest that fits, which is the definition the function is supposed to meet.
func TestOutputBudgetSearchIsMaximalAndUnderBudget(t *testing.T) {
	rng := rand.New(rand.NewSource(20261003))

	for trial := 0; trial < 300; trial++ {
		n := 1 + rng.Intn(12)
		items := make([]map[string]any, 0, n)
		for i := range n {
			items = append(items, map[string]any{
				"id":   i,
				"body": strings.Repeat("x", 1+rng.Intn(400)),
			})
		}
		// The brute-force answer, measured exactly as applyOutputBudget would:
		// each candidate prefix carrying its own output_budget report.
		budget := 1 + rng.Intn(4000)
		want := -1
		for k := n; k >= 0; k-- {
			ref := newAgentEnvelope("finding", "findings", items[:k], int64(n), 0, 100)
			ref.With(outputBudgetKey, map[string]any{
				"max_bytes": budget, "returned": k, "omitted": n - k, "next_offset": k,
			})
			doc, err := encodeAgentJSON(ref)
			require.NoError(t, err)
			if len(doc) <= budget {
				want = k
				break
			}
		}

		// One envelope for both: newAgentEnvelope stamps generated_at, so a second
		// one would differ from the first by a millisecond and never compare equal.
		env := newAgentEnvelope("finding", "findings", items, int64(n), 0, 100)
		full, err := encodeAgentJSON(env)
		require.NoError(t, err)

		doc, err := applyOutputBudget(env, budget)

		switch {
		case len(full) <= budget:
			// Fits whole: untouched, and the returned bytes are the full document.
			require.NoError(t, err)
			require.Equal(t, string(full), string(doc))
			assert.NotContains(t, env.extra, outputBudgetKey)
		case want <= 0:
			// Not even the first row fits (or not even an empty item list): a
			// budget too small for this result, never an empty page.
			require.Error(t, err)
			assert.True(t, isOutputTooLarge(err), "a budget below one row must be coded")
		default:
			require.NoError(t, err)
			require.NotNil(t, doc)
			assert.LessOrEqual(t, len(doc), budget, "the emitted document must fit the budget")

			got, ok := env.Items.([]map[string]any)
			require.True(t, ok)
			assert.Equal(t, want, len(got), "the search must find the LARGEST prefix that fits")

			again, err := encodeAgentJSON(env)
			require.NoError(t, err)
			assert.Equal(t, string(again), string(doc),
				"the returned bytes must be the document the envelope was left in")
		}
	}
}

func isOutputTooLarge(err error) bool {
	var coded codedError
	return errors.As(err, &coded) && coded.Code() == apicontract.CodeOutputTooLarge
}

// Rows exist and none fits: output_too_large, never an empty page whose
// next_offset points back at itself.
func TestOutputBudgetNoRowFitsIsTooLarge(t *testing.T) {
	rows := []map[string]any{{"uuid": strings.Repeat("a", 4000)}, {"uuid": "b"}}
	env := newAgentEnvelope("scan diff", "", rows, 2, 0, 2)
	empty, err := encodeAgentJSON(newAgentEnvelope("scan diff", "", []map[string]any{}, 2, 0, 2))
	require.NoError(t, err)
	_, err = applyOutputBudget(env, len(empty)+300)
	require.Error(t, err)
	require.Equal(t, apicontract.CodeOutputTooLarge, classifyErrorCode(err, classifyExitCode(err)))
}

// Every command whose -j document the output budget can cut accepts --offset,
// so output_budget.next_offset can be followed.
func TestNextOffsetIsFollowable(t *testing.T) {
	root := preparedMachineTree(t)
	seen := map[string]bool{}
	walkTree(root, func(c *cobra.Command) {
		if c.Flag("max-output-bytes") == nil {
			return
		}
		path := commandPathWithoutRoot(c)
		if reason, ok := nextOffsetExempt[path]; ok {
			seen[path] = true
			require.NotEmpty(t, reason)
			return
		}
		require.NotNilf(t, c.Flag("offset"), "%s takes --max-output-bytes but no --offset: its next_offset is a dead end", path)
	})
	for path := range nextOffsetExempt {
		require.Truef(t, seen[path], "nextOffsetExempt lists %q, which has no --max-output-bytes: delete it", path)
	}
}

// nextOffsetExempt are budgeted commands where following next_offset would
// mean running the work again, with why.
var nextOffsetExempt = map[string]string{
	"scan":            "sends traffic: a second page would re-run the scan; page the stored findings with finding --scan-uuid",
	"run":             "sends traffic: as scan",
	"scan-url":        "sends traffic: as scan",
	"scan-request":    "sends traffic: as scan",
	"fingerprint":     "sends traffic: as scan",
	"fuzz":            "sends traffic: a second page would re-send every payload",
	"dns":             "sends DNS queries: a second page would resolve again",
	"match-not-found": "reads stdin once: there is no second read to page",
	"scan wait":       "the stored scan document: page its findings with finding --scan-uuid <uuid> --offset",
}
