package cli

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/contract"
)

// machine.go holds the constructors a command uses for its -j result document.
//
// Every runnable command declares what kind of machine output it produces
// (command_traits.go), and every result document is an agentEnvelope built by
// one of the emitters below. The command name always comes from the cobra path
// (commandPathWithoutRoot), never a hand-typed string, so `command` cannot drift
// from what the caller typed.

// machineKind is the shape of a command's -j output. The three kinds a
// document can render share their spelling with the pkg/contract registry;
// stream and interactive exist only as declarations.
type machineKind string

const (
	// kindRead: an envelope of rows, or of one object wrapped as items:[obj].
	kindRead machineKind = contract.KindRead
	// kindMutation: the envelope plus ok/changed/action (and dry_run).
	kindMutation machineKind = contract.KindMutation
	// kindScan: the single scan document.
	kindScan machineKind = contract.KindScan
	// kindStream: a documented stream flag owns stdout; -j still yields an
	// envelope or receipt.
	kindStream machineKind = "stream"
	// kindInteractive: exempt — a TUI, a long-running server, a passthrough shim,
	// help. Allowed only for the fixed list in machine_contract_test.go.
	kindInteractive machineKind = "interactive"
)

// envOpt adjusts an envelope before it is written.
type envOpt func(*agentEnvelope)

// withExtra attaches a command-specific top-level field.
func withExtra(key string, value any) envOpt {
	return func(e *agentEnvelope) { e.With(key, value) }
}

// withRedacted marks the document's credential values as masked when masked
// is true (the envelope's `redacted`). A false never clears a mark another
// view in the same document made.
func withRedacted(masked bool) envOpt {
	return func(e *agentEnvelope) { e.Redacted = e.Redacted || masked }
}

// withDBPath names the database the command actually opened.
func withDBPath(path string) envOpt {
	return func(e *agentEnvelope) { e.DBPath = path }
}

// withDryRun marks the result a dry run (dry_run: true): nothing was sent
// or written.
func withDryRun() envOpt {
	return func(e *agentEnvelope) { e.DryRun = true }
}

// withProjectScope records the project filter that was actually applied.
func withProjectScope(projectUUID string) envOpt {
	return func(e *agentEnvelope) { e.WithProjectScope(projectUUID) }
}

// withQuery attaches the follow-up command (see agentEnvelope.WithQuery).
func withQuery(tail ...string) envOpt {
	return func(e *agentEnvelope) { e.WithQuery(tail...) }
}

// newMachineEnvelope is newAgentEnvelope with the command name taken from cmd
// rather than typed by hand, as a read document; emitMutation (asMutation) and
// the scan documents set their own kind. A group whose bare invocation is the
// documented shorthand for a subcommand (`scope` = `scope view`) passes that
// subcommand: the output is its output, so the document names it and its
// schema applies.
func newMachineEnvelope(cmd *cobra.Command, legacyKey string, items any, total int64, offset, limit int) *agentEnvelope {
	env := newAgentEnvelope(commandPathWithoutRoot(cmd), legacyKey, items, total, offset, limit)
	env.Kind = string(kindRead)
	return env
}

// emitRead writes a row-list result. legacyKey is the pre-envelope name of the
// row array, rendered only under --json-legacy-keys; "" for none.
func emitRead(cmd *cobra.Command, legacyKey string, items any, total int64, offset, limit int, opts ...envOpt) error {
	env := newMachineEnvelope(cmd, legacyKey, items, total, offset, limit)
	return writeAgentJSON(applyEnvOpts(env, opts))
}

// emitObject writes a single-object result as items:[obj], total 1. Under
// --json-legacy-keys a named legacyKey renders the object under that name, and
// "." flattens its keys to the top level (the bare-object shape it replaces).
func emitObject(cmd *cobra.Command, legacyKey string, obj any, opts ...envOpt) error {
	env := newMachineEnvelope(cmd, legacyKey, []any{obj}, 1, 0, 1)
	env.objectResult = true
	return writeAgentJSON(applyEnvOpts(env, opts))
}

// mutationResult is what a state-changing command reports.
type mutationResult struct {
	// Changed is required: did the command change state? A dry run never did.
	Changed bool
	// Action names what was done: "create", "update", "delete", "noop",
	// "import", ….
	Action string
	DryRun bool
	// Items are the affected objects. Always rendered as an array; nil is [].
	Items any
	// Extra carries command-specific counters, rendered at the top level.
	Extra map[string]any
	// Query is the follow-up argv tail (see agentEnvelope.WithQuery).
	Query []string
}

// emitMutation writes a mutation result: the envelope plus changed/action/
// dry_run. total/limit count the affected items.
func emitMutation(cmd *cobra.Command, legacyKey string, r mutationResult, opts ...envOpt) error {
	items, object := normalizeEnvelopeItems(r.Items)
	n := reflect.ValueOf(items).Len()
	env := newMachineEnvelope(cmd, legacyKey, items, int64(n), 0, n)
	env.objectResult = object
	env.asMutation(r.Changed, r.Action, r.DryRun)
	for _, k := range sortedExtraKeys(r.Extra) {
		env.With(k, r.Extra[k])
	}
	if len(r.Query) > 0 {
		env.WithQuery(r.Query...)
	}
	return writeAgentJSON(applyEnvOpts(env, opts))
}

// asMutation turns an envelope into a mutation document. For a command whose
// counts do not fit emitMutation's items-derived total (ingest reports rows
// stored, with no per-row items) and that builds its envelope itself.
func (e *agentEnvelope) asMutation(changed bool, action string, dryRun bool) *agentEnvelope {
	changed = changed && !dryRun // a dry run never changed anything
	e.Kind = string(kindMutation)
	e.Changed = &changed
	e.Action = action
	e.DryRun = dryRun
	return e
}

func applyEnvOpts(env *agentEnvelope, opts []envOpt) *agentEnvelope {
	for _, o := range opts {
		o(env)
	}
	return env
}

// emitStructRead writes a command's existing result struct as a read
// envelope (see envelopeFromStruct): rowsField becomes `items` (legacy alias:
// its old name) and every other field stays at the top level under the name it
// always had.
func emitStructRead(cmd *cobra.Command, v any, rowsField string) error {
	env, err := envelopeFromStruct(cmd, v, rowsField)
	if err != nil {
		return err
	}
	return writeAgentJSON(env)
}

// structFields marshals a result struct once and returns its top-level fields,
// for a command that keeps its old scalar keys as envelope extras (a mutation's
// counters) rather than rows.
func structFields(v any) (map[string]any, error) {
	raw, err := jsonMarshalNoEscape(v)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("structFields: %T is not a JSON object: %w", v, err)
	}
	out := make(map[string]any, len(fields))
	for k, val := range fields {
		out[k] = val
	}
	return out, nil
}

// envelopeFromStruct wraps a command's existing result struct without
// reshaping it ("wrap, don't reshape"): v is marshaled once, its rowsField
// becomes `items` (legacy alias: rowsField), and every other top-level key is
// kept at the top level under the same name. Envelope fields win a collision.
//
// With rowsField "", v is a single-object result: items:[v], and the legacy
// alias "." flattens it back to the top level.
func envelopeFromStruct(cmd *cobra.Command, v any, rowsField string) (*agentEnvelope, error) {
	if rowsField == "" {
		env := newMachineEnvelope(cmd, ".", []any{v}, 1, 0, 1)
		env.objectResult = true
		return env, nil
	}
	raw, err := jsonMarshalNoEscape(v)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("envelopeFromStruct: %T is not a JSON object: %w", v, err)
	}
	rows := []json.RawMessage{}
	if r, ok := fields[rowsField]; ok && string(r) != "null" {
		if err := json.Unmarshal(r, &rows); err != nil {
			return nil, fmt.Errorf("envelopeFromStruct: %s.%s is not an array: %w", reflect.TypeOf(v), rowsField, err)
		}
	}
	delete(fields, rowsField)
	env := newMachineEnvelope(cmd, rowsField, rows, int64(len(rows)), 0, len(rows))
	for k, val := range fields {
		env.With(k, val)
	}
	return env, nil
}
