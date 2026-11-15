package cli

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"time"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// AgentSchemaVersion is the contract version of every -j/--json envelope. A
// consumer gates on it; it is bumped on any breaking field change.
//
// Its absence was the real problem. A driver could not write one parser, because
// different commands (and different vigolium versions) named the same thing
// differently — the row array was `data` or `records` or `traffic` or `results`
// or `http_records` depending on where you asked, and drift was discovered as a
// parse failure in production rather than as a version check at startup. There
// is now one shape, one canonical name per field, and a number to check.
const AgentSchemaVersion = apicontract.SchemaVersion

// agentEnvelope is the single JSON shape every -j command emits.
//
// `items` is canonical and is the only row array rendered by default. Each
// command still DECLARES its historical key (see legacyKey), but that alias is
// rendered only under --json-legacy-keys / $VIGOLIUM_JSON_LEGACY_KEYS — it
// duplicates the rows on the wire, which is the single largest avoidable cost in
// the read path. See json_legacy_keys.go.
type agentEnvelope struct {
	SchemaVersion int    `json:"schema_version"`
	Command       string `json:"command"`
	// Kind names the document's shape — "read", "mutation" or "scan" — so a
	// consumer can tell a row list from a mutation receipt without knowing the
	// command. Set by the builder from the command's machine declaration
	// (newMachineEnvelope, asMutation); empty from the raw newAgentEnvelope.
	Kind string `json:"kind,omitempty"`
	// OK is true exactly when the invocation exits 0, 3 or 4. A result document
	// whose command then failed carries ok:false and Error; the error envelope
	// (agent_error.go) carries ok:false when there was no result at all, so
	// `.ok` is a valid branch on every document a -j invocation prints.
	OK bool `json:"ok"`
	// Error is set, with OK false, when the command wrote this document and then
	// ended with an exit code other than 0, 3 or 4 (json_outcome.go): the
	// document keeps what the work produced and says why it is not a success.
	Error *agentError `json:"error,omitempty"`
	// SoftFail states that --soft-fail forced the process exit status to 0
	// while Error records the code the command concluded.
	SoftFail bool `json:"soft_fail,omitempty"`
	// The mutation spine, set only by emitMutation. Changed is a pointer so a
	// mutation that changed nothing still says `"changed": false` while a read
	// carries no such key.
	Changed *bool  `json:"changed,omitempty"`
	Action  string `json:"action,omitempty"`
	DryRun  bool   `json:"dry_run,omitempty"`

	ProjectUUID string `json:"project_uuid,omitempty"`
	// DBPath names the database this command actually opened. A consumer that
	// pins $VIGOLIUM_DB_PATH and passes --db can then ASSERT the store it read
	// rather than trusting that the pin survived a subprocess chain — the default
	// database is one shared file, so a silent fall-through to it reads every
	// target that ever landed there.
	DBPath string `json:"db_path,omitempty"`

	Total  int64 `json:"total"`
	Offset int   `json:"offset"`
	Limit  int   `json:"limit"`

	Items any `json:"items"`

	// Query is a ready-to-run follow-up command for the obvious next step. It is
	// the cheapest documentation in the surface: a paragraph of consumer guidance
	// that cannot go stale, because it is generated from the same values the
	// envelope reports.
	Query string `json:"query,omitempty"`

	// QueryArgv is the same follow-up as an argv vector. The string form is for
	// a human to read and is shell-quoted; a consumer that wants to RUN it had
	// to either shell out (inheriting the quoting rules of whatever shell it
	// found) or re-split a quoted string, which is where the quoting that made
	// the string safe becomes the thing that breaks the parse. The vector goes
	// straight into exec.
	QueryArgv []string `json:"query_argv,omitempty"`

	// GeneratedAt is stamped in the wire timestamp format (RFC3339, exactly three
	// fractional digits) with an epoch-millisecond sibling. See
	// agentTimestamp for why the precision is fixed.
	GeneratedAt   string `json:"generated_at,omitempty"`
	GeneratedAtMS int64  `json:"generated_at_ms,omitempty"`

	// extra carries command-specific fields. Marshaled by MarshalJSON into the
	// same object.
	extra map[string]any
	// legacyKey is the pre-envelope name this command used for its row array
	// ("records", "findings", …). Rendering it means encoding the rows a second
	// time into the same object, which doubles every -j payload — on a
	// `traffic -j -n 10000` that is tens of MB, and on any agent-driven read it is
	// a doubled token bill for a field deprecated on arrival. So it is emitted
	// only when jsonLegacyKeysEnabled() says a caller is still migrating.
	//
	// The special value "." flattens the single object result into the top
	// level instead, which is the pre-envelope shape of a command that printed
	// one bare object.
	legacyKey string
	// objectResult marks a single-object answer wrapped as items:[obj]. It has no
	// record boundary, so the output budget leaves it whole and a page is never
	// described; and its legacy alias renders the object, not the one-row array.
	objectResult bool
	// shaped marks a document applyGenericShaping already narrowed, so a
	// document written twice is never paged or projected twice.
	shaped bool
}

// newAgentEnvelope builds the standard envelope with no kind; a command emits
// through newMachineEnvelope (or emitRead/emitObject/emitMutation), which names
// it from the cobra path and sets the kind. legacyKey is the pre-envelope
// name this command used for its row array ("records", "findings", "scans", …);
// pass "" for a command that had none.
//
// items is normalised: nil (or a nil slice) becomes [] and a single object
// becomes [obj], because `items` is never null and never an object — a consumer
// iterates it without asking which command produced it.
func newAgentEnvelope(command, legacyKey string, items any, total int64, offset, limit int) *agentEnvelope {
	now := time.Now()
	items, object := normalizeEnvelopeItems(items)
	env := &agentEnvelope{
		SchemaVersion: AgentSchemaVersion,
		Command:       command,
		OK:            true,
		Total:         total,
		Offset:        offset,
		Limit:         limit,
		Items:         items,
		objectResult:  object,
		// One clock read for both: they are two representations of the SAME
		// instant, and a schema whose selling point is that a consumer can compare
		// them must not ship a pair sampled a millisecond apart.
		GeneratedAt:   agentTimestamp(now),
		GeneratedAtMS: scanevents.EpochMillis(now),
		extra:         map[string]any{},
	}
	env.legacyKey = legacyKey
	// Every envelope says where its project came from (project_source.go).
	attachProjectSource(env)
	return env
}

// normalizeEnvelopeItems enforces the `items` invariant: always a JSON array.
// It reports whether the value was a single object that had to be wrapped.
func normalizeEnvelopeItems(items any) (any, bool) {
	if items == nil {
		return []any{}, false
	}
	rv := reflect.ValueOf(items)
	switch rv.Kind() {
	case reflect.Slice:
		if rv.IsNil() {
			return reflect.MakeSlice(rv.Type(), 0, 0).Interface(), false
		}
		return items, false
	case reflect.Array:
		return items, false
	case reflect.Pointer, reflect.Map, reflect.Interface:
		if rv.IsNil() {
			return []any{}, false
		}
	}
	return []any{items}, true
}

// WithProjectScope records the project filter that was ACTUALLY applied.
//
// The envelope used to fill project_uuid from resolveProjectUUID() regardless of
// the read mode, so a `-S` read — where scoping is off and the result spans
// every project in the file — still named one project. A consumer reading that
// field to confirm which engagement it was looking at was being told something
// untrue, which is the opposite of the assertion the envelope exists to support.
// project_scoped states whether a filter was applied at all, so "no project
// filter" is explicit rather than inferred from an absent field.
func (e *agentEnvelope) WithProjectScope(projectUUID string) *agentEnvelope {
	e.ProjectUUID = projectUUID
	return e.With("project_scoped", projectUUID != "")
}

// With attaches a command-specific field to the envelope.
func (e *agentEnvelope) With(key string, value any) *agentEnvelope {
	if e.extra == nil {
		e.extra = map[string]any{}
	}
	e.extra[key] = value
	return e
}

// WithQuery attaches the follow-up command, pinned to the read context.
//
// tail is the command and its own flags — WithQuery("finding", "--id", "5") —
// and followUpQuery prepends the --db/--stateless/--project flags that make the
// result reachable. It takes argv rather than a finished string on purpose: the
// old string form let a caller hand-write "vigolium finding --id 5 --json",
// which resolves that per-database autoincrement id in whatever store the next
// process happens to open. Every call site had that bug, and three survived the
// first sweep. With this signature they cannot.
//
// A read that cannot be reproduced (a --glob-db merge reads through a temporary
// database) yields "", and the field is omitted rather than pointing somewhere
// it does not lead.
func (e *agentEnvelope) WithQuery(tail ...string) *agentEnvelope {
	e.Query = followUpQuery(tail...)
	e.QueryArgv = followUpArgv(tail...)
	return e
}

// envelopeItemSlice reports whether v is a row-list envelope, and hands back the
// `items` slice by reflection.
//
// Reflection rather than a type switch over the two shapes the read commands
// happen to use today: the scan views are typed slices ([]scanRowView and
// friends), and a switch missing them called every paged scan listing complete.
// A single-object answer (db stats) has no record
// boundary, which is the question both callers are really asking — resultIsPaged
// to describe a page, applyOutputBudget to find somewhere to cut. One rule, so
// the two cannot disagree about what counts as a row list.
func envelopeItemSlice(v any) (*agentEnvelope, reflect.Value, bool) {
	env, ok := v.(*agentEnvelope)
	if !ok {
		return nil, reflect.Value{}, false
	}
	// A single object wrapped as items:[obj] (db stats, a receipt) is still one
	// answer, not a page of one row: cutting it would ship an empty result.
	if env.objectResult {
		return env, reflect.Value{}, false
	}
	items := reflect.ValueOf(env.Items)
	if !items.IsValid() || items.Kind() != reflect.Slice {
		return env, reflect.Value{}, false
	}
	return env, items, true
}

// envelopeFields is the struct's own JSON key set. Extra keys colliding with one
// are dropped: `items` and `total` are the contract, and an alias shadowing one
// would reintroduce exactly the ambiguity the envelope removes.
var envelopeFields = map[string]bool{
	"schema_version": true, "command": true, "kind": true, "ok": true,
	"error": true, "soft_fail": true, "changed": true, "action": true, "dry_run": true,
	"project_uuid": true, "db_path": true,
	"total": true, "offset": true, "limit": true, "items": true, "query": true,
	"query_argv": true, "generated_at": true, "generated_at_ms": true,
}

// MarshalJSON merges the struct fields with extra (and the legacy row alias)
// into one flat object. Written by hand because the alias key is dynamic — it
// differs per command — and Go's struct tags cannot express that.
//
// It appends to the encoded struct rather than round-tripping through a
// map[string]any. That round trip decoded the whole result set — request and
// response bodies included — into a generic tree costing several times the
// JSON's size in live heap, purely to answer a key-collision question the fixed
// field set above already answers.
func (e *agentEnvelope) MarshalJSON() ([]byte, error) {
	type alias agentEnvelope
	view := (*alias)(e)
	// Items may have been reassigned after construction (the output budget
	// slices it); a nil there must still render as [], never null.
	if items, _ := normalizeEnvelopeItems(e.Items); !itemsIdentical(items, e.Items) {
		cp := *view
		cp.Items = items
		view = &cp
	}
	base, err := jsonMarshalNoEscape(view)
	if err != nil {
		return nil, err
	}
	renderLegacy := e.legacyKey != "" && jsonLegacyKeysEnabled()
	if len(e.extra) == 0 && !renderLegacy {
		return base, nil
	}

	out := bytes.TrimSuffix(bytes.TrimSpace(base), []byte("}"))
	appendField := func(key string, raw []byte) {
		if envelopeFields[key] {
			return
		}
		out = append(out, ',')
		keyJSON, _ := json.Marshal(key)
		out = append(out, keyJSON...)
		out = append(out, ':')
		out = append(out, raw...)
	}

	if renderLegacy {
		if err := e.appendLegacy(appendField); err != nil {
			return nil, err
		}
	}
	for _, key := range sortedExtraKeys(e.extra) {
		raw, err := jsonMarshalNoEscape(e.extra[key])
		if err != nil {
			return nil, err
		}
		appendField(key, raw)
	}
	return append(out, '}'), nil
}

// appendLegacy renders the --json-legacy-keys alias.
//
//   - a row list: the rows again under the old name;
//   - an object result under a named key: the object itself (not the one-row
//     array), which is the shape that name had before items was an array;
//   - legacyKey ".": the object's own keys flattened to the top level — the
//     pre-envelope shape of a command that printed one bare object. Envelope
//     fields and the command's extras win a collision, so a flattened key can
//     never shadow `items` or a counter the command states itself.
func (e *agentEnvelope) appendLegacy(appendField func(string, []byte)) error {
	single, hasSingle := e.singleItem()
	if e.legacyKey == "." {
		if !hasSingle {
			return nil
		}
		raw, err := jsonMarshalNoEscape(single)
		if err != nil {
			return err
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return nil // not an object: nothing to flatten
		}
		keys := make([]string, 0, len(fields))
		for k := range fields {
			if _, own := e.extra[k]; !own {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			appendField(k, fields[k])
		}
		return nil
	}
	value := e.Items
	if e.objectResult && hasSingle {
		value = single
	}
	raw, err := jsonMarshalNoEscape(value)
	if err != nil {
		return err
	}
	appendField(e.legacyKey, raw)
	return nil
}

// singleItem returns items[0] when items holds exactly one element.
func (e *agentEnvelope) singleItem() (any, bool) {
	rv := reflect.ValueOf(e.Items)
	if !rv.IsValid() || (rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array) || rv.Len() != 1 {
		return nil, false
	}
	return rv.Index(0).Interface(), true
}

// itemsIdentical reports whether normalisation left items untouched, without
// comparing slice contents (which may not be comparable).
func itemsIdentical(normalized, original any) bool {
	if original == nil {
		return false
	}
	a, b := reflect.ValueOf(normalized), reflect.ValueOf(original)
	if a.Kind() != b.Kind() || a.Type() != b.Type() {
		return false
	}
	if a.Kind() == reflect.Slice {
		return a.IsNil() == b.IsNil() && a.Len() == b.Len() && (a.Len() == 0 || a.Pointer() == b.Pointer())
	}
	return true
}

// sortedExtraKeys keeps the appended fields in a stable order — map iteration is
// random, and a payload whose key order changes run to run defeats diffing.
func sortedExtraKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// agentTimestamp renders t for JSON output: RFC3339 UTC with exactly three
// fractional digits.
//
// Go's default renders a variable number of fractional digits, so vigolium
// emitted microseconds (…785113Z) while a consumer comparing against a
// JavaScript toISOString() has milliseconds (…785Z) — and lexically "…785113Z"
// sorts BEFORE "…785Z". The extra precision is not extra information to such a
// consumer, it is a broken comparison that silently drops same-instant rows. The
// epoch-millisecond sibling exists for consumers that would rather compare
// integers than strings; either is correct, and both are always present.
func agentTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return scanevents.FormatTime(t)
}

// jsonMarshalNoEscape keeps HTML escaping off throughout the envelope's own
// marshaling. Payload evidence is full of &, < and >; the
// standard encoder would turn each into a \u00XX escape, which costs tokens and
// makes a hand-read line harder to compare against what the scanner sent.
func jsonMarshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode appends a newline; the caller is assembling a value, not a stream.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
