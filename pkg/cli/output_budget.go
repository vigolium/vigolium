package cli

import (
	"reflect"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/apicontract"
)

// --max-output-bytes caps the size of a -j result document.
//
// A read command's page size is counted in ROWS (-n/--limit), and rows vary in
// size by three orders of magnitude: twenty findings with no bodies is a few
// kilobytes, twenty traffic records with --full-body is tens of megabytes. A
// caller with a byte budget — an agent with a context window, a CI step with a
// log limit, an HTTP handler piping the result — has no row count that reliably
// stays under it, because the only way to learn the size is to produce it.
//
// So the cap is applied where the size is known: after rendering, before
// emitting. It truncates at a RECORD boundary and reports what it dropped, so
// the document stays valid JSON and the caller learns there is more rather than
// receiving a prefix of a broken one.
//
// It is opt-in and unlimited by default (triage C8: a default has to be
// measured before it is chosen). Nothing changes for a caller that does not
// pass it.
var maxOutputBytes int

// registerOutputBudgetFlag adds --max-output-bytes. Registered alongside the
// other shared -j shaping flags, so finding, traffic and db ls all carry it.
func registerOutputBudgetFlag(flags *pflag.FlagSet) {
	flags.IntVar(&maxOutputBytes, "max-output-bytes", 0,
		"With --json, cap the result document at N bytes by dropping whole trailing items "+
			"(0 = unlimited). The document stays valid JSON and gains an output_budget object "+
			"naming how many items were returned, how many were omitted, and the next --offset")
}

// validateOutputBudgetFlag rejects a budget that cannot mean anything: a
// negative size, or one asked for on a command invocation that is not producing
// a JSON document at all.
//
// The second check is the important one. A silently ignored --max-output-bytes
// is indistinguishable from a budget that happened not to bind, so a caller who
// misspelled the mode would conclude their output fits when nothing enforced it.
func validateOutputBudgetFlag(jsonRequested bool) error {
	if maxOutputBytes == 0 {
		return nil
	}
	if maxOutputBytes < 0 {
		return usageErrorf("--max-output-bytes must be >= 0 (0 = unlimited), got %d", maxOutputBytes)
	}
	if !jsonRequested {
		return usageErrorf("--max-output-bytes applies to the --json result document; pass -j/--json")
	}
	return nil
}

// applyOutputBudget trims an envelope's items so the encoded document fits
// within maxOutputBytes, and records what it dropped.
//
// It measures with the REAL encoder — same indentation, same escaping, same
// legacy-key duplication — because every one of those changes the size, and a
// budget enforced against an estimate is a budget that is sometimes exceeded.
// That makes each measurement a full encode, so the search is a binary one:
// ~log2(n) encodes rather than n.
//
// Total is deliberately left alone. It describes the result set, not the page,
// and leaving it is what makes resultIsPaged and the -o receipt report
// `complete:false` for a budgeted document — the same way they already do for a
// row-limited one.
//
// It returns the document it measured — the exact bytes the budget was enforced
// against — so the caller emits those rather than encoding the same value again.
// A nil document means no budget applied to this value and the caller should
// encode it itself.
//
// Returns an error only when even an empty item list does not fit, which is a
// budget too small to answer at all rather than a result too large to send.
func applyOutputBudget(v any, budget int) ([]byte, error) {
	if budget <= 0 {
		return nil, nil
	}
	// Not a row-list document (db stats emits an object). There is no record
	// boundary to cut on, and silently shipping it oversized is better than
	// failing a command whose output the budget cannot shape.
	env, items, ok := envelopeItemSlice(v)
	if !ok {
		return nil, nil
	}
	n := items.Len()
	original := env.Items
	// Droppable extras emptied so far, with their values for restore.
	var dropped []string
	saved := map[string]any{}

	// restore undoes everything a measurement did, so a trial encode can never
	// leak into the emitted document.
	restore := func() {
		env.Items = original
		delete(env.extra, outputBudgetKey)
		for k, v := range saved {
			env.extra[k] = v
		}
	}

	// apply puts the envelope in the state a k-item answer would be emitted in.
	// Every candidate carries its own output_budget object, so a measurement
	// includes the bytes the report itself costs — measuring without it and
	// attaching it afterwards is how a budget gets exceeded by the very field
	// that announces the budget.
	apply := func(k int) {
		env.Items = items.Slice(0, k).Interface()
		report := map[string]any{
			"max_bytes": budget,
			"returned":  k,
			"omitted":   n - k,
		}
		// A second page of a command that sends would send again, so it gets
		// no offset to follow, only where the whole result can go instead.
		if sendsTrafficCommands[env.Command] {
			report["full_result"] = sendingBudgetHint
		} else {
			report["next_offset"] = env.Offset + k
		}
		if len(dropped) > 0 {
			report["dropped_keys"] = slices.Clone(dropped)
		}
		env.With(outputBudgetKey, report)
	}
	// measure is apply plus the encode that answers "does it fit". Split from
	// apply so the winning state can be restored at the end without paying for
	// one more full encode of a document that has already been measured.
	measure := func(k int) ([]byte, bool, error) {
		apply(k)
		doc, err := encodeAgentJSON(env)
		if err != nil {
			return nil, false, err
		}
		return doc, len(doc) <= budget, nil
	}

	// The whole document, exactly as it would have been emitted. No
	// output_budget key: a result that fits is not a budgeted result.
	doc, err := encodeAgentJSON(env)
	if err != nil {
		return nil, err
	}
	if len(doc) <= budget {
		return doc, nil
	}

	// Bulky context goes before any item does: a scan document's plan and
	// per-target tables are the same on every poll and can be read again
	// (scan status, finding --scan-uuid); its findings are the answer.
	for _, key := range env.droppable {
		v, ok := env.extra[key]
		if !ok || isNilValue(v) {
			continue
		}
		saved[key] = v
		env.extra[key] = nil
		dropped = append(dropped, key)
		doc, fits, err := measure(n)
		if err != nil {
			restore()
			return nil, err
		}
		if fits {
			return doc, nil
		}
	}

	// The empty-item document is the floor: envelope metadata, the budget
	// report, and whatever else the command attached. If that alone is over
	// budget, no prefix can help — this is a budget too small to answer at all.
	best, empty, err := measure(0)
	if err != nil {
		restore()
		return nil, err
	}
	if !empty {
		restore()
		emptied := ""
		if len(dropped) > 0 {
			emptied = " (even with " + strings.Join(dropped, ", ") + " emptied)"
		}
		return nil, codedErrorf(apicontract.CodeOutputTooLarge,
			"result metadata alone exceeds --max-output-bytes %d%s; raise the budget or narrow the result with --fields/--compact",
			budget, emptied)
	}

	// Largest k in [0, n) whose document fits. lo always fits, hi never does —
	// n itself is known not to fit from the full encode above. best tracks lo's
	// document, so the search already holds the bytes it ends up choosing.
	lo, hi := 0, n
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		candidate, ok, err := measure(mid)
		if err != nil {
			restore()
			return nil, err
		}
		if ok {
			lo, best = mid, candidate
		} else {
			hi = mid
		}
	}

	// Rows exist and not even one fits: an empty page with next_offset equal to
	// this offset would send a caller that follows it round the same loop
	// forever. That is a budget too small for this result, said once.
	if lo == 0 && n > 0 {
		restore()
		return nil, codedErrorf(apicontract.CodeOutputTooLarge,
			"the first row alone exceeds --max-output-bytes %d; raise the budget or narrow each row with --fields/--compact",
			budget)
	}

	// Re-apply the winner: the last probe was not necessarily lo. No encode —
	// best is already that document.
	apply(lo)
	return best, nil
}

// inMemoryOffset backs --offset on the commands that build their whole result
// in memory (log ls, scan diff), so the next_offset the output budget reports
// can be followed.
var inMemoryOffset int

// registerInMemoryOffsetFlag adds --offset to such a command.
func registerInMemoryOffsetFlag(flags *pflag.FlagSet) {
	flags.IntVar(&inMemoryOffset, "offset", 0, "Skip the first N rows (follow output_budget.next_offset)")
}

// pageFromOffset returns rows from --offset on; an offset past the end is an
// empty page.
func pageFromOffset[T any](rows []T, offset int) ([]T, error) {
	if offset < 0 {
		return nil, usageErrorf("--offset must be >= 0, got %d", offset)
	}
	if offset >= len(rows) {
		return []T{}, nil
	}
	return rows[offset:], nil
}

// sendingBudgetHint is output_budget.full_result on a command that sends.
const sendingBudgetHint = "this command sends requests: re-running it for the next page would send them again; re-run with -o <file> to keep every row, or narrow each row with --fields/--compact"

// outputBudgetKey names the report the budget pass attaches. A caller reads it
// to learn that the page it holds was cut by bytes rather than by -n/--limit.
const outputBudgetKey = "output_budget"

// isNilValue reports whether v encodes as JSON null.
func isNilValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface:
		return rv.IsNil()
	}
	return false
}
