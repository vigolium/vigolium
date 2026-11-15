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
	// Envelope is the JSONL envelope "type" these records carry.
	Envelope string
	// Aliases are the other accepted spellings, envelope name included.
	Aliases []string
	// Importable reports whether `vigolium import` reads it back.
	Importable bool
	// ImplicitlyExcluded types are left out unless --only names them.
	ImplicitlyExcluded bool
}

var exportRecordTypes = []exportRecordType{
	{Name: "http", Envelope: "http_record", Aliases: []string{"http_record", "http_records", "record", "records", "traffic"}, Importable: true},
	{Name: "findings", Envelope: "finding", Aliases: []string{"finding"}, Importable: true},
	{Name: "scans", Envelope: "scan", Aliases: []string{"scan"}},
	// The module registry is the binary's, not the store's; it rides along
	// only when asked for.
	{Name: "modules", Envelope: "module", Aliases: []string{"module"}, ImplicitlyExcluded: true},
	{Name: "oast", Envelope: "oast_interaction", Aliases: []string{"oast_interaction", "oast_interactions", "oast-interactions"}},
	{Name: "source-repos", Envelope: "source_repo", Aliases: []string{"source_repo", "source_repos", "source-repo"}},
	{Name: "scopes", Envelope: "scope", Aliases: []string{"scope"}},
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
