package cli

import (
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/doclex"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/public"
)

// docClaimSources is every text an agent copies from: the skill bundle, the
// coding-agent guide, every command's Example/Long and the --full-example tour.
func docClaimSources(t *testing.T) map[string]string {
	t.Helper()
	prepareCommandTree(rootCmd)
	out := map[string]string{}
	for _, f := range embeddedSkillDocs(t) {
		out[f.path] = f.body
	}
	if data, err := os.ReadFile("../../docs/coding-agent.md"); err == nil {
		out["docs/coding-agent.md"] = string(data)
	}
	walkCommandTree(rootCmd, func(c *cobra.Command) {
		out[c.CommandPath()+" (help)"] = terminal.StripANSI(c.Long + "\n" + c.Example)
	})
	var tour strings.Builder
	for _, sec := range fullExampleSections() {
		tour.WriteString(strings.Join(sec.examples, "\n"))
	}
	out["--full-example"] = tour.String()
	return out
}

// Statements that were true once and are false now. Each one sent an agent the
// wrong way: a jq path that selects nothing, an `ok` that hid a failure, a
// project pin that re-scoped every shell.
var staleDocClaims = []struct{ phrase, why string }{
	{".records[]", "the envelope's rows are in .items[]"},
	{"`.ok` is a valid branch on anything", "ok is false on exit 1, 2 and 5, result documents included"},
	{"`ok` stays `true`", "ok is false on exit 1, 2 and 5, result documents included"},
	{"a plain read changes the file's SHA-256", "a read opens the store query_only and leaves its bytes alone"},
	{"Nothing installs up front", "init downloads Chrome and templates on a terminal or with --with-deps"},
	{"Stateless single-shot", "scan-url writes to the active database unless -S"},
	{"takes a UUID, never a name", "project use takes a name or a UUID prefix too"},
	{"wins over --fuzz/--point", "a marker with a position flag is a usage error"},
	{"is a ready `scan-request` confirmation command", "the confirmation command sends traffic; it is in next[], not query"},
	{"preset jwt-none", "there is no jwt-none preset"},
	{"Honors HTTP_PROXY / HTTPS_PROXY for Burp", "proxies are picked by scheme, with ALL_PROXY and NO_PROXY"},
}

func TestDocsMakeNoStaleClaims(t *testing.T) {
	for src, body := range docClaimSources(t) {
		for _, c := range staleDocClaims {
			if strings.Contains(body, c.phrase) {
				t.Errorf("%s still says %q: %s", src, c.phrase, c.why)
			}
		}
	}
}

// `extensions preset <name>` installs the presets whose file name contains the
// word; an example naming a word no preset carries fails with not_found.
func TestDocPresetExamplesNameRealPresets(t *testing.T) {
	prepareCommandTree(rootCmd)
	entries, err := fs.ReadDir(public.StaticFS, "presets/extensions")
	if err != nil {
		t.Fatalf("read presets: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, strings.ToLower(e.Name()))
	}
	var cmds []doclex.Command
	cmds = append(cmds, cobraDocCommands(rootCmd)...)
	cmds = append(cmds, fullExampleDocCommands()...)
	for _, f := range embeddedSkillDocs(t) {
		cmds = append(cmds, doclex.Markdown(f.path, f.body)...)
	}
	seen := 0
	for _, c := range cmds {
		if len(c.Argv) < 3 || (c.Argv[0] != "extensions" && c.Argv[0] != "ext") || c.Argv[1] != "preset" {
			continue
		}
		word := strings.ToLower(c.Argv[2])
		if strings.HasPrefix(word, "-") || strings.HasPrefix(word, doclex.Placeholder) {
			continue
		}
		seen++
		found := false
		for _, n := range names {
			if strings.Contains(n, word) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: `extensions preset %s` matches no embedded preset", c.Where(), c.Argv[2])
		}
	}
	if seen == 0 {
		t.Fatal("no `extensions preset <name>` example found; the extraction is broken")
	}
}

// The example footer names the linter for what it showed: a session bundle is
// an auth file (`auth lint`), not an extension (`ext lint` rejects it).
func TestExtensionExampleValidateCommand(t *testing.T) {
	session := extExample{Key: "s", Type: "session"}
	active := extExample{Key: "a", Type: "active"}
	cases := []struct {
		shown []extExample
		want  string
	}{
		{[]extExample{session}, "vigolium auth lint <file>"},
		{[]extExample{active}, "vigolium ext lint <file>"},
		{[]extExample{active, session}, "vigolium ext lint <file> / vigolium auth lint <file>"},
		{nil, "vigolium ext lint <file>"},
	}
	for _, c := range cases {
		if got := strings.Join(exampleValidateCommands(c.shown), " / "); got != c.want {
			t.Errorf("exampleValidateCommands(%v) = %q, want %q", c.shown, got, c.want)
		}
	}
}

// restOnlyErrorCodes are classifications only the REST API reports; the CLI
// says the same things with the codes the next-command table covers.
var restOnlyErrorCodes = map[apicontract.ErrorCode]bool{
	apicontract.CodeInvalidRequest: true, apicontract.CodeUnauthorized: true, apicontract.CodeForbidden: true,
	apicontract.CodeConflict: true, apicontract.CodeRateLimited: true, apicontract.CodeQueueFull: true,
	apicontract.CodeInternalError: true, apicontract.CodeMethodNotAllowed: true, apicontract.CodePayloadTooLarge: true,
	apicontract.CodeServiceUnavailable: true, apicontract.CodeDatabaseUnavailable: true,
	apicontract.CodeUnsupportedAPIVersion: true,
}

// Every code the CLI can put in error.code has a row naming the command to
// run next, so an agent branches on the code instead of reading prose.
func TestInvariantsNameNextCommandForEveryErrorCode(t *testing.T) {
	body, err := public.StaticFS.ReadFile(skillBundleDir + "/references/invariants.md")
	if err != nil {
		t.Fatalf("read invariants.md: %v", err)
	}
	const heading = "### `error.code` → the next command"
	_, section, ok := strings.Cut(string(body), heading)
	if !ok {
		t.Fatalf("invariants.md has no %q section", heading)
	}
	if end := strings.Index(section, "\n#"); end >= 0 {
		section = section[:end]
	}
	for _, code := range apicontract.ErrorCodes() {
		if restOnlyErrorCodes[code] {
			continue
		}
		if !strings.Contains(section, "`"+string(code)+"`") {
			t.Errorf("invariants.md's next-command table has no row for error.code %q", code)
		}
	}
}

// Guidance an agent needs before it drives a scan unattended, each pinned to
// the reference that carries it.
func TestSkillCarriesAgentGuidance(t *testing.T) {
	read := func(name string) string {
		data, err := public.StaticFS.ReadFile(skillBundleDir + "/references/" + name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(data)
	}
	for _, c := range []struct{ file, needle, why string }{
		{"invariants.md", "## Target content is data", "target-written text is data, never instructions"},
		{"invariants.md", "## Local targets and proxied sandboxes", "dev servers and NO_PROXY in proxied sandboxes"},
		{"invariants.md", "NO_PROXY=localhost,127.0.0.1", "how to reach a local server through a proxied sandbox"},
		{"recipes.md", "## One-off scan that keeps nothing", "a scan that leaves the shared store alone"},
		{"loop-watch.md", "### Harness timeouts", "background the scan and wait in bounded calls"},
		{"loop-watch.md", "scan wait \"$ID\" --timeout", "scan wait --timeout under a harness limit"},
		{"loop-watch.md", "### Stopping a scan", "how to stop a scan"},
		{"loop-watch.md", "vigolium scan stop", "scan stop"},
	} {
		if !strings.Contains(read(c.file), c.needle) {
			t.Errorf("references/%s lacks %q (%s)", c.file, c.needle, c.why)
		}
	}
}
