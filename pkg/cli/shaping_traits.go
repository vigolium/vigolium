package cli

import (
	"reflect"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/contract"
)

// Generic -j shaping, driven by each command's Shape in commandTraits.
//
// applyShapingTraits gives every shaped command the
// --fields/--compact/--max-output-bytes (and paging) flags it is missing, so
// no read is left without a way to narrow a large answer;
// validateGenericShaping checks them before the command runs (so a typo exits
// 2 before anything is sent); applyGenericShaping applies them to the document
// in writeAgentJSON. A command that projects its own rows
// (Shape.Own) keeps doing so: the generic pass registers and applies only what
// that command did not.

// shapingAnnotation lists the shaping flags applyShapingTraits registered on a
// command (comma-separated); those are the ones applyGenericShaping applies.
// Present, possibly empty, once the hook has visited a shaped command.
const shapingAnnotation = "vigolium.io/shaping-generic"

// Backing variables of the generically registered paging flags. Separate from
// the per-command ones (findingLimit, inMemoryOffset, …) so a command that
// pages itself never sees its rows paged a second time.
var (
	shapeLimit  int
	shapeOffset int
)

// Generic shaping operations, by the flag that selects them.
const (
	shapeOpFields  = "fields"
	shapeOpCompact = "compact"
	shapeOpBudget  = "max-output-bytes"
	shapeOpLimit   = "limit"
	shapeOpOffset  = "offset"
)

// applyShapingTraits registers, on a command whose Shape is rows or object,
// the shaping flags it is missing: rows get --fields, --compact and
// --max-output-bytes, plus -n/--limit and --offset when they are paged in
// memory (-n only while the letter is free); objects get --fields. Called from
// prepareCommandTree; safe to call more than once.
func applyShapingTraits(c *cobra.Command, path string) {
	if _, done := c.Annotations[shapingAnnotation]; done {
		return
	}
	t, ok := commandTraits[path]
	if !ok || (t.Shape.Kind != shapeRows && t.Shape.Kind != shapeObject) {
		return
	}
	var added []string
	f := c.Flags()
	if t.Shape.generic() {
		if !hasFlag(c, "fields") {
			f.StringSliceVar(&jsonFields, "fields", nil, "Restrict --json items to these keys (comma-separated). An unknown name is an error, not a silent drop")
			added = append(added, shapeOpFields)
		}
		if t.Shape.Kind == shapeRows || len(t.Shape.CompactDrop) > 0 {
			if !hasFlag(c, "compact") {
				f.BoolVar(&jsonCompact, "compact", false, "With --json, drop the bulky keys of each row and of the envelope (plan, query, generated_at, db_path)")
				added = append(added, shapeOpCompact)
			}
		}
		if t.Shape.Kind == shapeRows {
			if !hasFlag(c, "max-output-bytes") {
				registerOutputBudgetFlag(f)
				added = append(added, shapeOpBudget)
			}
		}
	}
	if t.Shape.Kind == shapeRows && t.Shape.Paging == pagingInMemory {
		if !hasFlag(c, "limit") {
			short := "n"
			if shorthandTaken(c, short) {
				short = ""
			}
			f.IntVarP(&shapeLimit, "limit", short, 0, "With --json, return at most N rows (0 = all; follow output_budget.next_offset with --offset)")
			added = append(added, shapeOpLimit)
		}
		if !hasFlag(c, "offset") {
			f.IntVar(&shapeOffset, "offset", 0, "With --json, skip the first N rows (follow output_budget.next_offset)")
			added = append(added, shapeOpOffset)
		}
	}
	setAnnotation(c, shapingAnnotation, strings.Join(added, ","))
}

// hasFlag reports whether c parses a flag called name: its own, a persistent
// one it declares, or a persistent one of an ancestor. Like shorthandTaken it
// never triggers cobra's persistent-flag merge.
func hasFlag(c *cobra.Command, name string) bool {
	if c.Flags().Lookup(name) != nil || c.PersistentFlags().Lookup(name) != nil {
		return true
	}
	for p := c.Parent(); p != nil; p = p.Parent() {
		if p.PersistentFlags().Lookup(name) != nil {
			return true
		}
	}
	return false
}

// genericShaping is the invocation's generic shaping: the operations the
// running command had registered for it, set by validateGenericShaping.
type genericShaping struct {
	ops []string
}

func (g *genericShaping) has(op string) bool { return g != nil && slices.Contains(g.ops, op) }

var activeShaping *genericShaping

// validateGenericShaping checks the generically registered shaping flags of
// the running command before it runs, and arms applyGenericShaping. Called
// from the root PersistentPreRunE, so a bad --fields exits 2 before a command
// opens a store or sends a request.
func validateGenericShaping(cmd *cobra.Command) error {
	activeShaping = nil
	path := commandPathWithoutRoot(cmd)
	t, ok := commandTraits[path]
	raw, annotated := cmd.Annotations[shapingAnnotation]
	if !ok || !annotated {
		return nil
	}
	g := &genericShaping{}
	if raw != "" {
		g.ops = strings.Split(raw, ",")
	}
	if g.has(shapeOpFields) {
		if vocab := t.Shape.staticVocab(path); vocab != nil {
			if err := validateFieldSelection(normalizeFieldList(jsonFields), vocab); err != nil {
				return err
			}
		}
	}
	if g.has(shapeOpBudget) {
		if err := validateOutputBudgetFlag(globalJSON); err != nil {
			return err
		}
	}
	if g.has(shapeOpLimit) && shapeLimit < 0 {
		return usageErrorf("--limit must be >= 0 (0 = all), got %d", shapeLimit)
	}
	if g.has(shapeOpOffset) && shapeOffset < 0 {
		return usageErrorf("--offset must be >= 0, got %d", shapeOffset)
	}
	activeShaping = g
	return nil
}

// applyGenericShaping applies the running command's generic shaping flags to
// a result document: paging, then --compact, then --fields. A document is
// shaped once (env.shaped); a command that projects its own rows (Own) only
// gets the paging it did not register itself.
func applyGenericShaping(env *agentEnvelope) error {
	g := activeShaping
	if g == nil || env == nil || env.shaped {
		return nil
	}
	env.shaped = true
	t, ok := commandTraits[env.Command]
	if !ok {
		return nil
	}
	if !env.objectResult && t.Shape.Kind == shapeRows && (g.has(shapeOpLimit) || g.has(shapeOpOffset)) {
		pageEnvelopeItems(env, g)
	}
	if !t.Shape.generic() {
		return nil
	}
	fields := normalizeFieldList(jsonFields)
	compact := g.has(shapeOpCompact) && jsonCompact && len(t.Shape.CompactDrop) > 0
	if !g.has(shapeOpFields) {
		fields = nil
	}
	if len(fields) == 0 && !compact {
		return nil
	}
	if len(fields) > 0 && t.Shape.staticVocab(env.Command) == nil {
		if vocab := emittedVocab(env.Items); len(vocab) > 0 {
			if err := validateFieldSelection(fields, vocab); err != nil {
				return err
			}
		}
	}
	rows, err := toRows(env.Items)
	if err != nil {
		return err
	}
	nullable := requiredNullableKeys(env.Command)
	for i, r := range rows {
		if compact {
			for _, k := range t.Shape.CompactDrop {
				if _, ok := r[k]; !ok {
					continue
				}
				// A key the schema requires stays, emptied, so the compact
				// document still validates.
				if slices.Contains(nullable, k) {
					r[k] = nil
				} else {
					delete(r, k)
				}
			}
		}
		rows[i] = projectFields(r, fields)
	}
	env.Items = rows
	return nil
}

// pageEnvelopeItems cuts env.Items to the --offset/--limit window. Total keeps
// describing the whole result, so a cut page reads as incomplete.
func pageEnvelopeItems(env *agentEnvelope, g *genericShaping) {
	items := reflect.ValueOf(env.Items)
	if !items.IsValid() || items.Kind() != reflect.Slice {
		return
	}
	n := items.Len()
	if env.Total < int64(n) {
		env.Total = int64(n)
	}
	lo := 0
	if g.has(shapeOpOffset) {
		lo = min(shapeOffset, n)
		env.Offset += lo
	}
	hi := n
	if g.has(shapeOpLimit) && shapeLimit > 0 {
		hi = min(lo+shapeLimit, n)
	}
	env.Items = items.Slice(lo, hi).Interface()
	env.Limit = hi - lo
}

// emittedVocab is the --fields vocabulary of rows whose command declares none
// statically: the item type's keys, or the keys the rows carry. Empty when
// there are no rows to learn from, which skips the check: nothing is projected.
func emittedVocab(items any) []string {
	rv := reflect.ValueOf(items)
	if !rv.IsValid() || rv.Kind() != reflect.Slice {
		return nil
	}
	if keys := jsonKeysOfType(rv.Type().Elem()); keys != nil {
		return keys
	}
	var vocab []string
	for i := 0; i < rv.Len(); i++ {
		el := rv.Index(i)
		for el.Kind() == reflect.Interface && !el.IsNil() {
			el = el.Elem()
		}
		keys := jsonKeysOfType(el.Type())
		if keys == nil {
			rows, err := toRows([]any{el.Interface()})
			if err != nil || len(rows) != 1 {
				continue
			}
			for k := range rows[0] {
				keys = append(keys, k)
			}
		}
		for _, k := range keys {
			if !slices.Contains(vocab, k) {
				vocab = append(vocab, k)
			}
		}
	}
	slices.Sort(vocab)
	return vocab
}

// requiredNullableKeys are the item keys of path's registered schema that are
// required but may be null.
func requiredNullableKeys(path string) []string {
	c, ok := contract.LookupCommand(path)
	if !ok || c.Item == nil {
		return nil
	}
	return contract.RequiredNullableJSONFields(c.Item)
}

// compactEnvelope is --compact on the envelope itself: the human-readable
// query (query_argv stays), generated_at (generated_at_ms stays), the db_path
// the document names (query_argv repeats it), and a scan document's plan
// (scan status has it).
func compactEnvelope(env *agentEnvelope) {
	env.Query = ""
	env.GeneratedAt = ""
	env.DBPath = ""
	if slices.Contains(env.droppable, "plan") {
		if _, ok := env.extra["plan"]; ok {
			env.extra["plan"] = nil
		}
	}
}
