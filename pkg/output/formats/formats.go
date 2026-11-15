// Package formats is the single table of output formats: every name, alias,
// file extension, kind and the command surfaces that accept it. The scan
// commands' --format, `vigolium export`, `vigolium import --format`, the REST
// output_formats field and `db export --format` all validate and name files
// through this table, so a format (or an alias) cannot exist on one surface and
// be unknown on another by accident.
//
// It is a leaf package on purpose: pkg/types derives FormatOutputPath from it,
// and pkg/output (which imports pkg/types) binds the report renderers to these
// names in formats_registry.go.
package formats

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// Kind classifies what a format produces.
type Kind int

const (
	// KindStream is a live or streamed document: console, jsonl, and the
	// db-export record dumps (json, raw).
	KindStream Kind = iota
	// KindReport is a document rendered from the finished result set (html,
	// report, pdf, markdown, sarif, csv, junit, github).
	KindReport
	// KindStore is a standalone database file (sqlite).
	KindStore
	// KindDir is a directory tree or an archive of one (fs, bundle).
	KindDir
)

// Surface is the set of commands that accept a format, as a bitmask.
type Surface uint

const (
	// SurfaceScan: the scan commands' --format (scan, run, scan-url,
	// scan-request) and the agentic -S export.
	SurfaceScan Surface = 1 << iota
	// SurfaceExport: `vigolium export --format`.
	SurfaceExport
	// SurfaceImport: `vigolium import --format` (the post-import report).
	SurfaceImport
	// SurfaceREST: the REST scan request's output_formats.
	SurfaceREST
	// SurfaceDBExport: `vigolium db export --format` (records, not findings).
	SurfaceDBExport
)

// String names a surface for error messages.
func (s Surface) String() string {
	switch s {
	case SurfaceScan:
		return "scan"
	case SurfaceExport:
		return "export"
	case SurfaceImport:
		return "import"
	case SurfaceREST:
		return "REST output_formats"
	case SurfaceDBExport:
		return "db export"
	}
	return "output"
}

// Format describes one output format.
type Format struct {
	// Name is the canonical spelling every downstream switch and path helper
	// sees; Aliases resolve onto it (case-insensitively, like Name).
	Name    string
	Aliases []string
	// Ext is the suffix FormatOutputPath appends to a base path. Empty means the
	// base is used verbatim (console's transcript, fs's directory base).
	Ext      string
	Kind     Kind
	Surfaces Surface
	// NeedsChrome marks formats rendered through headless Chrome.
	NeedsChrome bool
	// NeedsOutputPath marks formats that write a file the command cannot name
	// on its own, so `--format X` without -o is a usage error rather than a
	// silent no-op. console writes to the terminal, jsonl and github stream to
	// stdout, and fs defaults its base to the cwd.
	NeedsOutputPath bool
	// Label is the human name used in progress and summary lines.
	Label string
	// Note is a short qualifier appended to the name in --format help text.
	Note string
}

// table is the one list. Order is the order help text and error messages list
// the formats in.
var table = []Format{
	{Name: "console", Kind: KindStream, Surfaces: SurfaceScan, Label: "Console transcript"},
	{Name: "jsonl", Ext: ".jsonl", Kind: KindStream, Surfaces: SurfaceScan | SurfaceExport | SurfaceREST | SurfaceDBExport, Label: "JSONL"},
	{Name: "json", Ext: ".json", Kind: KindStream, Surfaces: SurfaceDBExport, Label: "JSON"},
	{Name: "raw", Kind: KindStream, Surfaces: SurfaceDBExport, Label: "Raw HTTP"},
	{Name: "html", Ext: ".html", Kind: KindReport, Surfaces: SurfaceScan | SurfaceExport | SurfaceImport | SurfaceREST, NeedsOutputPath: true, Label: "HTML report"},
	{Name: "report", Ext: ".report.html", Kind: KindReport, Surfaces: SurfaceScan | SurfaceExport | SurfaceImport | SurfaceREST, NeedsOutputPath: true, Label: "Document report"},
	{Name: "pdf", Ext: ".pdf", Kind: KindReport, Surfaces: SurfaceScan | SurfaceExport | SurfaceImport | SurfaceREST, NeedsChrome: true, NeedsOutputPath: true, Label: "PDF report", Note: "headless Chrome"},
	{Name: "markdown", Aliases: []string{"md"}, Ext: ".md", Kind: KindReport, Surfaces: SurfaceScan | SurfaceExport | SurfaceImport | SurfaceREST | SurfaceDBExport, NeedsOutputPath: true, Label: "Markdown report"},
	{Name: "markdown-table", Aliases: []string{"md-table"}, Ext: ".md", Kind: KindStream, Surfaces: SurfaceDBExport, Label: "Markdown table"},
	{Name: "sarif", Ext: ".sarif", Kind: KindReport, Surfaces: SurfaceScan | SurfaceExport | SurfaceImport | SurfaceREST, NeedsOutputPath: true, Label: "SARIF report", Note: "SARIF 2.1.0"},
	{Name: "csv", Ext: ".csv", Kind: KindReport, Surfaces: SurfaceScan | SurfaceExport | SurfaceImport | SurfaceREST | SurfaceDBExport, NeedsOutputPath: true, Label: "CSV findings"},
	{Name: "junit", Ext: ".junit.xml", Kind: KindReport, Surfaces: SurfaceScan | SurfaceExport | SurfaceImport | SurfaceREST, NeedsOutputPath: true, Label: "JUnit report", Note: "failures at/above --fail-on"},
	{Name: "github", Ext: ".github.txt", Kind: KindReport, Surfaces: SurfaceScan | SurfaceExport | SurfaceImport, Label: "GitHub annotations", Note: "workflow commands; stdout without -o"},
	{Name: "sqlite", Aliases: []string{"sqlite3", "db"}, Ext: ".sqlite", Kind: KindStore, Surfaces: SurfaceScan, NeedsOutputPath: true, Label: "SQLite database", Note: "needs -S"},
	{Name: "bundle", Aliases: []string{"gz"}, Ext: ".tar.gz", Kind: KindDir, Surfaces: SurfaceExport | SurfaceDBExport, NeedsOutputPath: true, Label: "Bundle archive"},
	{Name: "fs", Aliases: []string{"file-system"}, Kind: KindDir, Surfaces: SurfaceScan | SurfaceExport | SurfaceDBExport, Label: "File tree", Note: "flat traffic/finding tree"},
}

// All returns every format in table order. The slice is a copy.
func All() []Format { return slices.Clone(table) }

// Canonical resolves one --format token to its canonical name: trimmed,
// case-folded, aliases mapped. An unknown token comes back lowercased so the
// caller's own validity check rejects it.
func Canonical(token string) string {
	lower := strings.ToLower(strings.TrimSpace(token))
	for _, f := range table {
		if f.Name == lower || slices.Contains(f.Aliases, lower) {
			return f.Name
		}
	}
	return lower
}

// Get returns the format a token names, regardless of surface.
func Get(token string) (Format, bool) {
	name := Canonical(token)
	for _, f := range table {
		if f.Name == name {
			return f, true
		}
	}
	return Format{}, false
}

// UnknownFormatError is a token no format on the surface answers to. Its
// message lists the valid names, so a caller can wrap it as a usage error as-is.
type UnknownFormatError struct {
	Token   string
	Surface Surface
	Valid   []string
}

func (e *UnknownFormatError) Error() string {
	return fmt.Sprintf("unsupported format %q for %s; valid formats: %s",
		e.Token, e.Surface, strings.Join(e.Valid, ", "))
}

// Lookup resolves token (alias-aware, case-insensitive) to a format the surface
// accepts. A token that is unknown, or names a format the surface does not
// accept, returns an *UnknownFormatError listing Names(s).
func Lookup(token string, s Surface) (Format, error) {
	if f, ok := Get(token); ok && f.Surfaces&s != 0 {
		return f, nil
	}
	return Format{}, &UnknownFormatError{Token: strings.TrimSpace(token), Surface: s, Valid: Names(s)}
}

// Names lists the canonical names a surface accepts, in table order.
func Names(s Surface) []string {
	var out []string
	for _, f := range table {
		if f.Surfaces&s != 0 {
			out = append(out, f.Name)
		}
	}
	return out
}

// Help renders the format list for a surface's --format help text: each name
// with its aliases and note, e.g. "markdown (alias: md)". Every name Names(s)
// returns appears exactly once, in the same order.
func Help(s Surface) string {
	parts := make([]string, 0, len(table))
	for _, f := range table {
		if f.Surfaces&s == 0 {
			continue
		}
		var quals []string
		if len(f.Aliases) > 0 {
			quals = append(quals, "alias: "+strings.Join(f.Aliases, ", "))
		}
		if f.Note != "" {
			quals = append(quals, f.Note)
		}
		if len(quals) > 0 {
			parts = append(parts, f.Name+" ("+strings.Join(quals, "; ")+")")
		} else {
			parts = append(parts, f.Name)
		}
	}
	return strings.Join(parts, ", ")
}

// OutputPath appends the format's extension to base. An empty base stays empty;
// an unknown format or one without an extension returns base unchanged.
func OutputPath(base, token string) string {
	if base == "" {
		return ""
	}
	f, ok := Get(token)
	if !ok {
		return base
	}
	return base + f.Ext
}

// legacyExtensions are suffixes StripExtension also removes though no format
// writes them: spellings an operator may type for a format (out.sqlite3,
// out.markdown) that must not leak into derived sibling paths.
var legacyExtensions = []string{".sqlite3", ".db", ".markdown"}

// keptExtensions are format suffixes StripExtension leaves alone: ".txt" is the
// last segment of github's ".github.txt", but console names its transcript
// with -o verbatim, so `-o scan.txt --format console` must keep the ".txt".
var keptExtensions = []string{".txt"}

// multiPartExtensions are suffixes filepath.Ext cannot recover on its own (it
// sees only ".gz" of ".tar.gz", so stripping through it would derive sibling
// paths like "out.tar.html"). Checked first.
//
// ".report.html" and ".junit.xml" are deliberately absent: StripExtension strips
// only the last extension by contract, so a base that already ends in ".report"
// keeps it.
var multiPartExtensions = []string{".tar.gz", ".tgz"}

// StripExtension removes a known format extension (.jsonl, .html, .md,
// .tar.gz, …) from path, returning the base to append another one to.
func StripExtension(path string) string {
	if path == "" {
		return ""
	}
	lower := strings.ToLower(path)
	for _, ext := range multiPartExtensions {
		if strings.HasSuffix(lower, ext) {
			return path[:len(path)-len(ext)]
		}
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" || slices.Contains(keptExtensions, ext) {
		return path
	}
	if slices.Contains(legacyExtensions, ext) {
		return strings.TrimSuffix(path, filepath.Ext(path))
	}
	for _, f := range table {
		if f.Ext != "" && strings.ToLower(filepath.Ext(f.Ext)) == ext {
			return strings.TrimSuffix(path, filepath.Ext(path))
		}
	}
	return path
}

// extensionAliases are suffixes ByExtension maps onto a format although the
// format writes a different one: spellings an operator types for it.
var extensionAliases = map[string]string{
	".sqlite3":  "sqlite",
	".db":       "sqlite",
	".markdown": "markdown",
	".tgz":      "bundle",
}

// ByExtension returns the format a file name's extension names on surface s:
// the longest matching format extension wins, so "r.report.html" is report and
// "r.junit.xml" is junit, not html or nothing. A path with no recognised
// extension, or one naming a format the surface does not accept, is not found.
func ByExtension(path string, s Surface) (Format, bool) {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" {
		return Format{}, false
	}
	var best Format
	found := false
	for _, f := range table {
		if f.Ext == "" || f.Surfaces&s == 0 || !strings.HasSuffix(lower, f.Ext) {
			continue
		}
		if !found || len(f.Ext) > len(best.Ext) {
			best, found = f, true
		}
	}
	if found {
		return best, true
	}
	if name, ok := extensionAliases[strings.ToLower(filepath.Ext(lower))]; ok {
		if f, ok := Get(name); ok && f.Surfaces&s != 0 {
			return f, true
		}
	}
	return Format{}, false
}
