package formats

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var allSurfaces = []Surface{SurfaceScan, SurfaceExport, SurfaceImport, SurfaceREST, SurfaceDBExport}

func TestTableNamesAndAliasesAreUnique(t *testing.T) {
	seen := map[string]string{}
	for _, f := range table {
		for _, token := range append([]string{f.Name}, f.Aliases...) {
			require.Equal(t, strings.ToLower(token), token, "tokens are stored lowercase")
			prev, dup := seen[token]
			require.False(t, dup, "%q is claimed by both %s and %s", token, prev, f.Name)
			seen[token] = f.Name
		}
		assert.NotZero(t, f.Surfaces, "%s is on no surface", f.Name)
		assert.NotEmpty(t, f.Label, "%s has no label", f.Name)
	}
}

func TestLookupAliasesAndCase(t *testing.T) {
	cases := map[string]string{
		"md":          "markdown",
		" MD ":        "markdown",
		"HTML":        "html",
		"gz":          "bundle",
		"sqlite3":     "sqlite",
		"db":          "sqlite",
		"file-system": "fs",
		"md-table":    "markdown-table",
	}
	for token, want := range cases {
		f, ok := Get(token)
		require.True(t, ok, token)
		assert.Equal(t, want, f.Name, token)
		assert.Equal(t, want, Canonical(token), token)
	}
	assert.Equal(t, "nope", Canonical(" NOPE "), "unknown tokens come back lowercased")
}

// TestLookupRejectsOffSurface: every surface rejects a format it does not
// accept with an error listing exactly Names(surface).
func TestLookupRejectsOffSurface(t *testing.T) {
	for _, s := range allSurfaces {
		for _, f := range table {
			_, err := Lookup(f.Name, s)
			if f.Surfaces&s != 0 {
				assert.NoError(t, err, "%s on %s", f.Name, s)
				continue
			}
			var unknown *UnknownFormatError
			require.True(t, errors.As(err, &unknown), "%s on %s must be rejected", f.Name, s)
			assert.Equal(t, Names(s), unknown.Valid)
			assert.Contains(t, err.Error(), strings.Join(Names(s), ", "))
		}
		_, err := Lookup("bogus", s)
		assert.Error(t, err)
	}
}

func TestSurfaceMembership(t *testing.T) {
	assert.Equal(t, []string{"console", "jsonl", "html", "report", "pdf", "markdown", "sarif", "csv", "junit", "github", "sqlite", "fs"}, Names(SurfaceScan))
	assert.Equal(t, []string{"jsonl", "html", "report", "pdf", "markdown", "sarif", "csv", "junit", "github", "bundle", "fs"}, Names(SurfaceExport))
	assert.Equal(t, []string{"html", "report", "pdf", "markdown", "sarif", "csv", "junit", "github"}, Names(SurfaceImport))
	assert.Equal(t, []string{"jsonl", "html", "report", "pdf", "markdown", "sarif", "csv", "junit"}, Names(SurfaceREST))
	assert.Equal(t, []string{"jsonl", "json", "raw", "nuclei", "markdown", "markdown-table", "csv", "bundle", "fs"}, Names(SurfaceDBExport))
}

// TestHelpListsExactlyNames: the help string names every format of the surface
// once, in Names order, and nothing else.
func TestHelpListsExactlyNames(t *testing.T) {
	for _, s := range allSurfaces {
		assert.Equal(t, Names(s), helpNames(Help(s)), s.String())
	}
	assert.Contains(t, Help(SurfaceScan), "markdown (alias: md)")
	assert.Contains(t, Help(SurfaceScan), "sqlite (alias: sqlite3, db; needs -S)")
}

func TestOutputPath(t *testing.T) {
	cases := []struct{ format, want string }{
		{"jsonl", "out.jsonl"},
		{"report", "out.report.html"},
		{"md", "out.md"},
		{"csv", "out.csv"},
		{"junit", "out.junit.xml"},
		{"github", "out.github.txt"},
		{"gz", "out.tar.gz"},
		{"fs", "out"},
		{"console", "out"},
		{"unknown", "out"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, OutputPath("out", c.format), c.format)
	}
	assert.Empty(t, OutputPath("", "html"))
}

func TestStripExtension(t *testing.T) {
	cases := map[string]string{
		"r.csv":         "r",
		"r.xml":         "r",
		"r.junit.xml":   "r.junit",
		"r.txt":         "r.txt", // console names its transcript with -o verbatim
		"r.github.txt":  "r.github.txt",
		"r.sqlite3":     "r",
		"r.markdown":    "r",
		"r.TAR.GZ":      "r",
		"r.log":         "r.log",
		"dir.v1/report": "dir.v1/report",
	}
	for in, want := range cases {
		assert.Equal(t, want, StripExtension(in), in)
	}
}

// helpNames parses the format names back out of a Help string: the leading
// word of each top-level comma-separated entry (commas inside a parenthesized
// qualifier do not split).
func helpNames(help string) []string {
	var names []string
	depth, start := 0, 0
	flush := func(end int) {
		entry := strings.TrimSpace(help[start:end])
		if name, _, _ := strings.Cut(entry, " "); name != "" {
			names = append(names, name)
		}
	}
	for i, r := range help {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				flush(i)
				start = i + 1
			}
		}
	}
	flush(len(help))
	return names
}

func TestByExtension(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"out.jsonl", "jsonl"},
		{"out.html", "html"},
		{"out.report.html", "report"},
		{"OUT.MD", "markdown"},
		{"out.markdown", "markdown"},
		{"out.sarif", "sarif"},
		{"dir/out.csv", "csv"},
		{"out.junit.xml", "junit"},
		{"out.github.txt", "github"},
		{"out.sqlite", "sqlite"},
		{"out.sqlite3", "sqlite"},
		{"out.db", "sqlite"},
		{"out.pdf", "pdf"},
		{"out.json", ""},
		{"out.xml", ""},
		{"out.txt", ""},
		{"out", ""},
		{"out.tar.gz", ""},
	}
	for _, c := range cases {
		f, ok := ByExtension(c.path, SurfaceScan)
		got := ""
		if ok {
			got = f.Name
		}
		if got != c.want {
			t.Errorf("ByExtension(%q) = %q, want %q", c.path, got, c.want)
		}
	}
	if f, ok := ByExtension("out.tar.gz", SurfaceExport); !ok || f.Name != "bundle" {
		t.Errorf("ByExtension(out.tar.gz, export) = %v %v, want bundle", f.Name, ok)
	}
}
