package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// --format tsv: one header line, then one line per row and nothing else — no
// banner, no colour, no envelope. It is the cheapest survey a reader can ask
// for: a caller that only wants status, method, size and URL for a few hundred
// records used to drop to sqlite3 for exactly this, because -j costs an
// envelope and a parser.
//
// The columns are the --fields names (aliases included), so TSV and -j share
// one vocabulary, and the rows are rendered from the same map views -j prints:
// a value cannot differ between the two.

// tsvNoHeader backs --no-header.
var tsvNoHeader bool

// registerTSVFlags adds --no-header to a command that renders --format tsv.
func registerTSVFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&tsvNoHeader, "no-header", false, "With --format tsv, omit the header line")
}

// requestedReadFormat reads --format on a read command that renders the
// console table by default and TSV on request. Any other format is a usage
// error: these commands render neither html nor jsonl, and a silent fall-back
// to the table hands a parser something it cannot read.
func requestedReadFormat(cmd *cobra.Command) (string, error) {
	if !flagChanged(cmd, "format") {
		return "console", nil
	}
	v := strings.ToLower(strings.TrimSpace(globalFormat))
	switch v {
	case "console", "tsv":
	default:
		return "", usageErrorf("%s supports --format console (the table, default) or tsv (one line per row), not %q; use -j for JSON",
			commandPathWithoutRoot(cmd), strings.TrimSpace(globalFormat))
	}
	if v == "tsv" && globalJSON {
		return "", usageErrorf("--format tsv and -j/--json both choose stdout's format; pass one")
	}
	return v, nil
}

// tsvColumns returns the --fields list, or def when none was given.
func tsvColumns(def []string) []string {
	if f := normalizeFieldList(jsonFields); len(f) > 0 {
		return f
	}
	return def
}

// writeTSV renders rows (already projected to columns) as TSV.
func writeTSV(w io.Writer, columns []string, rows []map[string]any) error {
	var sb strings.Builder
	if !tsvNoHeader {
		sb.WriteString(strings.Join(columns, "\t"))
		sb.WriteByte('\n')
	}
	for _, row := range rows {
		for i, c := range columns {
			if i > 0 {
				sb.WriteByte('\t')
			}
			sb.WriteString(tsvValue(row[c]))
		}
		sb.WriteByte('\n')
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// tsvValue renders one cell. Tabs, newlines and backslashes are escaped so a
// row is always one line with len(columns) cells; a list joins with commas and
// an object is compact JSON.
func tsvValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return tsvEscape(x)
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case []string:
		parts := make([]string, len(x))
		for i, s := range x {
			parts[i] = tsvEscape(s)
		}
		return strings.Join(parts, ",")
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = tsvValue(e)
		}
		return strings.Join(parts, ",")
	case fmt.Stringer:
		return tsvEscape(x.String())
	}
	b, err := json.Marshal(v)
	if err != nil {
		return tsvEscape(fmt.Sprint(v))
	}
	return tsvEscape(string(b))
}

var tsvEscaper = strings.NewReplacer(`\`, `\\`, "\t", `\t`, "\n", `\n`, "\r", `\r`)

func tsvEscape(s string) string { return tsvEscaper.Replace(s) }

// readTSV makes writeAgentJSON print a document's items as TSV instead of the
// document. It is set by the read commands whose --format tsv renders exactly
// the rows their -j document carries (db list, db stats, scan diff), so the
// two outputs cannot drift.
var readTSV bool

// enableReadTSV resolves --format on such a command: tsv sets readTSV and
// reports true, so the caller takes its -j branch; console reports false; any
// other format is a usage error.
func enableReadTSV(cmd *cobra.Command) (bool, error) {
	format, err := requestedReadFormat(cmd)
	if err != nil {
		return false, err
	}
	readTSV = format == "tsv"
	return readTSV, nil
}

// writeEnvelopeTSV prints a document's items as TSV: the --fields columns,
// else every scalar key of the rows (nested objects flattened to dotted keys,
// lists JSON-encoded), sorted.
func writeEnvelopeTSV(env *agentEnvelope) error {
	rows, err := toRows(env.Items)
	if err != nil {
		// Items that are not objects (a list of table names) print one per line.
		raw, merr := jsonMarshalNoEscape(env.Items)
		if merr != nil {
			return err
		}
		var values []any
		if json.Unmarshal(raw, &values) != nil {
			return err
		}
		rows = make([]map[string]any, 0, len(values))
		for _, v := range values {
			rows = append(rows, map[string]any{"value": v})
		}
	}
	flat := make([]map[string]any, 0, len(rows))
	keys := map[string]bool{}
	for _, r := range rows {
		f := map[string]any{}
		flattenTSVRow("", r, f)
		for k := range f {
			keys[k] = true
		}
		flat = append(flat, f)
	}
	columns := normalizeFieldList(jsonFields)
	if len(columns) == 0 {
		columns = slices.Sorted(maps.Keys(keys))
	}
	for i, r := range flat {
		flat[i] = projectFields(r, columns)
	}
	return writeTSV(os.Stdout, columns, flat)
}

// flattenTSVRow copies a JSON object into out with nested objects flattened
// to dotted keys.
func flattenTSVRow(prefix string, in map[string]any, out map[string]any) {
	for k, v := range in {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if m, ok := v.(map[string]any); ok {
			flattenTSVRow(key, m, out)
			continue
		}
		out[key] = v
	}
}
