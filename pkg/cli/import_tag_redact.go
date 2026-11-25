package cli

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `import --tag k=v` and `import --redact credentials`: what a caller composing
// stores needs from the import itself. The tag labels the records the import
// wrote (record_tags), so they can be read back (`traffic --tag`) and taken back
// out (`db clean --tag`) without the caller writing vigolium's tables. The
// redaction masks the credentials of every record and finding the import
// writes before they are stored, so a store handed to another run does not
// carry this run's sessions. Both apply to every path source (SQLite merge,
// JSONL, audit folder, archive) and to the records the import writes only: a
// record the destination already held is neither tagged nor rewritten.

var (
	importTags          []string
	importRedact        string
	importRedactHeaders []string
)

// importRedactCredentials is the one --redact value: credential headers,
// cookie values and sensitive query parameters (database.RedactRecordCredentials).
const importRedactCredentials = "credentials"

func registerImportTagRedactFlags(flags *pflag.FlagSet) {
	flags.StringArrayVar(&importTags, "tag", nil,
		"Label every HTTP record this import writes with key=value (repeatable); read them back with 'traffic --tag', delete them with 'db clean --tag'. Records already in the database are not written, so not tagged")
	flags.StringVar(&importRedact, "redact", "",
		"Mask what the imported rows carry before they are stored: 'credentials' blanks Authorization, Proxy-Authorization and other credential headers, Cookie/Set-Cookie values and sensitive query parameters in each written record's raw request and response and each finding's evidence (the -j document's records_redacted / findings_redacted count them)")
	flags.StringArrayVar(&importRedactHeaders, "redact-header", nil,
		"With --redact credentials: one more header name to mask as a credential (repeatable, case-insensitive), beside the ones vigolium recognizes itself")
}

// importTagRedact is the parsed --tag / --redact pair.
type importTagRedact struct {
	tags    []database.RecordTag
	redact  bool
	headers []string
}

// active reports whether either flag was given.
func (o importTagRedact) active() bool { return len(o.tags) > 0 || o.redact }

// resolveImportTagRedact validates --tag and --redact before any import work.
func resolveImportTagRedact() (importTagRedact, error) {
	var out importTagRedact
	tags, err := database.ParseRecordTags(importTags)
	if err != nil {
		return out, usageErrorf("--tag: %v", err)
	}
	out.tags = tags
	switch v := strings.TrimSpace(importRedact); v {
	case "":
	case importRedactCredentials:
		out.redact = true
	default:
		return out, usageErrorf("--redact %q is not a redaction; the one value is %q", v, importRedactCredentials)
	}
	for _, h := range importRedactHeaders {
		h = strings.TrimSpace(h)
		if h == "" || strings.ContainsAny(h, ": \t\r\n") {
			return out, usageErrorf("--redact-header %q is not a header name", h)
		}
		out.headers = append(out.headers, h)
	}
	if len(out.headers) > 0 && !out.redact {
		return out, usageErrorf("--redact-header needs --redact %s", importRedactCredentials)
	}
	return out, nil
}

// apply copies the pair onto an import's options.
func (o importTagRedact) apply(opts *dbimport.Options) {
	opts.Tags = o.tags
	opts.RedactCredentials = o.redact
	opts.RedactHeaders = o.headers
}

// addJSON adds the tag and redaction counters to the -j document, present
// whenever the flag was given so a 0 reads as "none needed", not as an older
// vigolium.
func (o importTagRedact) addJSON(out map[string]any, r *dbimport.Result) {
	if out == nil || r == nil {
		return
	}
	if len(o.tags) > 0 {
		tags := make(map[string]string, len(o.tags))
		for _, t := range o.tags {
			tags[t.Key] = t.Value
		}
		out["tags"] = tags
		out["records_tagged"] = r.RecordsTagged
	}
	if o.redact {
		out["redaction"] = importRedactCredentials
		if len(o.headers) > 0 {
			out["redact_headers"] = o.headers
		}
		out["records_redacted"] = r.RecordsRedacted
		out["findings_redacted"] = r.FindingsRedacted
	}
}

// print renders the human lines for the pair.
func (o importTagRedact) print(r *dbimport.Result) {
	if r == nil {
		return
	}
	if len(o.tags) > 0 {
		names := make([]string, 0, len(o.tags))
		for _, t := range o.tags {
			names = append(names, t.String())
		}
		fmt.Printf("  Tagged:       %d records (%s)\n", r.RecordsTagged, terminal.Cyan(strings.Join(names, ", ")))
	}
	if o.redact {
		fmt.Printf("  Redacted:     credentials in %d records, %d findings\n", r.RecordsRedacted, r.FindingsRedacted)
	}
}

// importTagRedactFlagNames names the set flags, for a refusal message.
func importTagRedactFlagNames(o importTagRedact) []string {
	set := map[string]bool{"--tag": len(o.tags) > 0, "--redact": o.redact}
	var out []string
	for _, name := range slices.Sorted(maps.Keys(set)) {
		if set[name] {
			out = append(out, name)
		}
	}
	return out
}
