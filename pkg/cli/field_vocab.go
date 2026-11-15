package cli

import (
	"encoding/json"
	"os"
	"slices"

	"github.com/spf13/cobra"
)

// One field vocabulary across every -j view.
//
// The views grew their key names one command at a time: `traffic` says
// status_code and response_content_length, `fuzz` says status and length,
// `replay` says response_length, and `endpoints` uses status for a histogram
// and top_status for the scalar. A caller that learned one command's names hit
// KeyError on the next, and `--fields` refused names the same command family
// emitted elsewhere.
//
// Renaming every view to one spelling would break every parser written against
// the current names. So the names stay, and each concept below lists every
// spelling it answers to: `--fields` accepts any of them on any view that
// carries the concept, and the projected row carries the key under the name the
// caller ASKED for. A parser that names its own fields always reads back its
// own names.
//
// Resolution order: a key the view really has wins; otherwise the concept's
// members are tried in the order listed, so the first one the view carries is
// the one projected.
var fieldConcepts = [][]string{
	{"status_code", "top_status", "status", "statuscode", "code"},
	{"response_content_length", "length", "response_length", "content_length", "body_size", "response_size", "size"},
	{"response_words", "words"},
	{"response_lines", "lines"},
	{"response_time_ms", "time_ms", "elapsed_ms", "duration_ms", "time"},
	{"response_content_type", "content_type", "mime"},
	{"response_title", "title"},
	{"uuid", "id", "record_uuid"},
	{"uuid_short", "short_uuid"},
	{"host", "hostname"},
	{"response_headers", "headers"},
}

// fieldConceptOf indexes fieldConcepts by every spelling.
var fieldConceptOf = func() map[string][]string {
	m := map[string][]string{}
	for _, c := range fieldConcepts {
		for _, name := range c {
			m[name] = c
		}
	}
	return m
}()

// resolveFieldName returns the key a view actually carries for the requested
// name: the name itself when the view has it, else the first member of its
// concept the view has. ok is false when neither applies.
func resolveFieldName(name string, has func(string) bool) (string, bool) {
	if has(name) {
		return name, true
	}
	for _, member := range fieldConceptOf[name] {
		if has(member) {
			return member, true
		}
	}
	return "", false
}

// wantsField reports whether a --fields list asks for key, under its own name
// or another spelling of its concept.
func wantsField(fields []string, key string) bool {
	for _, f := range fields {
		if f == key || slices.Contains(fieldConceptOf[f], key) {
			return true
		}
	}
	return false
}

// fieldAliasesFor lists the alias spellings a view with these keys accepts on
// top of its own keys, for the error message that names the vocabulary.
func fieldAliasesFor(supported []string) []string {
	var out []string
	for _, key := range supported {
		for _, member := range fieldConceptOf[key] {
			if member != key && !slices.Contains(supported, member) && !slices.Contains(out, member) {
				out = append(out, member)
			}
		}
	}
	slices.Sort(out)
	return out
}

// rowShaping is --fields / --compact for a list command whose rows are structs
// rather than the map views traffic and finding build, and which applies them
// itself (Shape.Own). The vocabulary and the bulky keys --compact removes are
// the ones its commandTraits row declares; defaultTSV are the --format tsv
// columns used when --fields names none.
type rowShaping struct {
	path       string
	defaultTSV []string
}

// shape is the commandTraits shape whose Vocab and CompactDrop apply.
func (s rowShaping) shape() commandShape { return commandTraits[s.path].Shape }

// validate checks the shaping flags before any query runs.
func (s rowShaping) validate() error {
	return validateAgentViewFlags(agentViewOptionsFromFlags(), s.shape().Vocab)
}

// prepare is validate for a command that also renders --format tsv, and
// returns the resolved --format (console or tsv).
func (s rowShaping) prepare(cmd *cobra.Command) (string, error) {
	if err := s.validate(); err != nil {
		return "", err
	}
	return requestedReadFormat(cmd)
}

// apply returns items shaped by the flags; unchanged when neither is set.
func (s rowShaping) apply(items any) (any, error) {
	if len(normalizeFieldList(jsonFields)) == 0 && (!jsonCompact || len(s.shape().CompactDrop) == 0) {
		return items, nil
	}
	return s.applyRows(items)
}

// applyRows is apply that always answers rows as maps.
func (s rowShaping) applyRows(items any) ([]map[string]any, error) {
	rows, err := toRows(items)
	if err != nil {
		return nil, err
	}
	var drop []string
	if jsonCompact {
		drop = s.shape().CompactDrop
	}
	return shapeRowMaps(rows, normalizeFieldList(jsonFields), drop, requiredNullableKeys(s.path)), nil
}

// emitTSV prints items as --format tsv: the --fields columns, or defaultTSV.
func (s rowShaping) emitTSV(items any) error {
	columns := tsvColumns(s.defaultTSV)
	rows, err := toRows(items)
	if err != nil {
		return err
	}
	for i, r := range rows {
		rows[i] = projectFields(r, columns)
	}
	return writeTSV(os.Stdout, columns, rows)
}

// toRows converts struct rows to maps through their JSON form, so a key is
// spelled exactly as -j spells it.
func toRows(items any) ([]map[string]any, error) {
	raw, err := jsonMarshalNoEscape(items)
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	return rows, nil
}
