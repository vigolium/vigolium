package cli

import (
	"slices"
	"strings"
)

// exportRecordType is one kind of record an export can carry. The table below
// is the one vocabulary for --only, --exclude and the scan's --export-only:
// every spelling a user may type resolves to a canonical name here, so the
// three flags cannot disagree about what "http" means. (They did: --exclude
// matched envelope names, so `--exclude http` excluded nothing.)
type exportRecordType struct {
	// Name is the canonical --only name.
	Name string
	// Aliases are the other accepted spellings; the first is the JSONL
	// envelope "type" these records carry.
	Aliases []string
	// ImplicitlyExcluded types are left out unless --only names them.
	ImplicitlyExcluded bool
	// Formats lists the export formats that render this type; empty means
	// every format. jsonl and bundle carry every envelope, html embeds every
	// envelope in its data island, the document reports read findings, scans,
	// modules and record counts, and the findings-only formats (csv, sarif,
	// junit, github) read nothing else.
	Formats []string
}

// Format groups for the Formats column.
var (
	exportFormatsDocument = []string{"jsonl", "bundle", "html", "report", "pdf", "markdown"}
	exportFormatsArchive  = []string{"jsonl", "bundle", "html"}
)

var exportRecordTypes = []exportRecordType{
	{Name: "http", Aliases: []string{"http_record", "http_records", "record", "records", "traffic"},
		Formats: append(slices.Clone(exportFormatsDocument), "fs")},
	{Name: "findings", Aliases: []string{"finding"}},
	{Name: "scans", Aliases: []string{"scan"}, Formats: exportFormatsDocument},
	// The module registry is the binary's, not the store's; it rides along
	// only when asked for.
	{Name: "modules", Aliases: []string{"module"}, ImplicitlyExcluded: true, Formats: exportFormatsDocument},
	{Name: "oast", Aliases: []string{"oast_interaction", "oast_interactions", "oast-interactions"}, Formats: exportFormatsArchive},
	{Name: "source-repos", Aliases: []string{"source_repo", "source_repos", "source-repo"}, Formats: exportFormatsArchive},
	// Scope rows are enabled scan rules: import stores them only into a
	// stateless database or under --include-scopes.
	{Name: "scopes", Aliases: []string{"scope"}, Formats: exportFormatsArchive},
}

// supportsFormat reports whether the given canonical export format renders
// this record type.
func (t exportRecordType) supportsFormat(format string) bool {
	return len(t.Formats) == 0 || slices.Contains(t.Formats, format)
}

// exportTypesForFormat lists the canonical record types a format renders.
func exportTypesForFormat(format string) []string {
	var out []string
	for _, t := range exportRecordTypes {
		if t.supportsFormat(format) {
			out = append(out, t.Name)
		}
	}
	return out
}

// exportTypeNames lists the canonical names, for help and errors.
func exportTypeNames() []string {
	names := make([]string, 0, len(exportRecordTypes))
	for _, t := range exportRecordTypes {
		names = append(names, t.Name)
	}
	return names
}

// lookupExportType resolves a canonical name or alias, case-insensitively.
func lookupExportType(name string) (exportRecordType, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, t := range exportRecordTypes {
		if t.Name == n || slices.Contains(t.Aliases, n) {
			return t, true
		}
	}
	return exportRecordType{}, false
}

// canonicalExportTypes resolves a flag's values to canonical names, dropping
// blanks and duplicates; an unknown name is a usage error naming the flag.
func canonicalExportTypes(flagName string, values []string) ([]string, error) {
	var out []string
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			continue
		}
		t, ok := lookupExportType(v)
		if !ok {
			return nil, usageErrorf("invalid %s value %q; valid values: %s (aliases such as http_record, finding, scan are accepted)",
				flagName, strings.TrimSpace(v), strings.Join(exportTypeNames(), ", "))
		}
		if !slices.Contains(out, t.Name) {
			out = append(out, t.Name)
		}
	}
	return out, nil
}
