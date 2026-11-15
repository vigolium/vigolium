//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/itchyny/gojq"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/cli"
)

// The documentation runs. Every example in the skill bundle, the help text,
// the --full-example tour and docs/coding-agent.md that is a read — by the
// commandTraits table: kind read, read database intent, sends no traffic, and
// no flag in the invocation that writes, sends or streams — is executed
// against the seeded store with its placeholders replaced by seeded ids. Each
// must exit 0 and print exactly one JSON document, and every jq filter the
// example pipes that document into must evaluate against the real output and
// yield something other than null: `.records[]` on an envelope whose rows are
// in `items` fails here. Network: none (the reads send nothing; OAST is off).

// docExampleSkips are documented reads that cannot run here, each with why.
// Keep it short: a skip is an example nobody checks.
var docExampleSkips = map[string]string{
	"vigolium auth show admin --host app.example.com":                                                                 "the fixture stores no auth session",
	"vigolium ext run --ext check.js --record-uuid 3f2a9c1e":                                                          "needs the extension file it names",
	"vigolium ext run --ext check.js --record-uuid 3f2a9c1e --handler scanPerInsertionPoint --insertion URL_PARAM:id": "needs the extension file it names",
	"vigolium ext run --ext probe.js --record-uuid 3f2a9c1e --handler scanPerInsertionPoint --insertion URL_PARAM:id": "needs the extension file it names",
	"vigolium ext run --ext probe.js --record-uuid 3f2a9c1e --allow-network   # really send its requests":             "needs the extension file it names",
	"vigolium traffic -j --fields '?' 2>&1 | head -3":                                                                 "shows the usage error that lists the fields",
	"vigolium traffic tree": "the tree is a human view",
}

// docHumanFlags select a rendering for a person (a table, markdown, a tree)
// or need inputs the fixture does not have; -j is refused with them, so such
// an example documents human output and is not run here.
var docHumanFlags = []string{"--markdown", "--tree", "--burp", "--raw", "--sans", "--no-header", "--glob-db", "--follow", "-f"}

// docStdinCommands read their input from stdin, which a documented example
// pipes in from a producer this test does not have.
var docStdinCommands = map[string]bool{"match-not-found": true}

// humanOnlyDocExample reports whether argv asks for a human rendering.
func humanOnlyDocExample(argv []string) bool {
	for i, a := range argv {
		if slices.Contains(docHumanFlags, a) {
			return true
		}
		if a == "--format" && i+1 < len(argv) && argv[i+1] != "json" {
			return true
		}
		if strings.HasPrefix(a, "--format=") && a != "--format=json" {
			return true
		}
	}
	return false
}

// docLiteralByFlag rewrites an illustrative literal value on one command to
// the fixture's: a documented scan diff of app.example compares two scans of a
// target the fixture stores.
var docLiteralByFlag = map[string]map[string]string{
	"scan diff": {"--target": "https://example.com"},
}

// docIDLike matches an illustrative identifier: a UUID or an 8+ character
// hex prefix of one.
var docIDLike = regexp.MustCompile(`^[0-9a-f]{8}[0-9a-f-]*$`)

// docPlaceholderByFlag replaces a placeholder value by the flag it follows.
var docPlaceholderByFlag = map[string]string{
	"--uuid": seedRecord, "-u": seedRecord, "--record-uuid": seedRecord, "--record": seedRecord,
	"--scan-uuid": seedScan1, "--new-since": seedScan1,
	"--id": seedFinding, "--finding-id": seedFinding,
	"--agentic-scan": seedAgenticScan,
	"--project-uuid": seedProject,
}

// docPlaceholderByCommand replaces a positional placeholder (or illustrative
// id) by the command that takes it, in order: `scan diff <a> <b>` compares
// two different seeded scans.
var docPlaceholderByCommand = map[string][]string{
	"traffic body": {seedRecord}, "traffic headers": {seedRecord},
	"finding": {seedFinding}, "finding show": {seedFinding},
	"scan status": {seedScan1}, "scan diff": {seedScan1, seedScan2},
	"log": {seedScan1}, "agent session": {seedAgenticScan},
}

const seedAgenticScan = "agent-0010-aaaa-bbbb-cccc-ddddeeee0010"

// docDryRunCommands are the scan commands whose documented --dry-run examples
// run too: a dry run resolves the plan and sends nothing, and its plan
// document is what most documented jq paths read.
var docDryRunCommands = map[string]bool{"scan": true, "run": true, "scan-url": true, "scan-request": true, "fuzz": true}

// substituteDocExample turns a documented argv into one that runs against the
// fixture: placeholders become seeded ids, an elision is dropped, the
// example's own --db is replaced by the fixture's, and -j is added. ok is false
// when a placeholder has no seeded stand-in.
func substituteDocExample(path string, argv []string) (out []string, ok bool) {
	positional := 0
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		prev := ""
		if i > 0 {
			prev = argv[i-1]
		}
		switch {
		case a == "--db":
			i++
			continue
		case strings.HasPrefix(a, "--db="), a == cli.DocEllipsis, a == "--json", a == "-j", a == "--pretty":
			continue
		case docLiteralByFlag[path][prev] != "":
			a = docLiteralByFlag[path][prev]
		case strings.Contains(a, cli.DocPlaceholder) || docIDLike.MatchString(a) ||
			(path == "finding show" || path == "finding") && isDigits(a) && !strings.HasPrefix(prev, "-"):
			if v, known := docPlaceholderByFlag[prev]; known {
				a = v
				break
			}
			if strings.HasPrefix(prev, "-") && !docIDLike.MatchString(a) {
				return nil, false // a placeholder for a value this test has no stand-in for
			}
			if strings.HasPrefix(prev, "-") {
				break // an id-like literal value of some other flag: leave it
			}
			ids := docPlaceholderByCommand[path]
			if positional >= len(ids) {
				if strings.Contains(a, cli.DocPlaceholder) {
					return nil, false
				}
				break
			}
			a = ids[positional]
			positional++
		}
		out = append(out, a)
	}
	return append(out, "-j"), true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// jqFilter returns the filter and variables of a `jq` pipe stage; ok is false
// for a stage that is not jq or uses an option this test does not model.
func jqFilter(stage []string) (filter string, vars map[string]any, ok bool) {
	if len(stage) == 0 || stage[0] != "jq" {
		return "", nil, false
	}
	vars = map[string]any{}
	for i := 1; i < len(stage); i++ {
		a := stage[i]
		switch {
		case a == "--arg" || a == "--argjson":
			if i+2 >= len(stage) {
				return "", nil, false
			}
			vars["$"+stage[i+1]] = stage[i+2]
			i += 2
		case a == "-s" || a == "--slurp" || a == "-n" || a == "--null-input" || a == "--stream":
			return "", nil, false
		case strings.HasPrefix(a, "-") && filter == "":
			// -r, -c, -e, -S, -M, --tab: output formatting only.
		case filter == "":
			filter = a
		}
	}
	return filter, vars, filter != "" && !strings.Contains(filter, cli.DocPlaceholder)
}

func TestDocExamplesRun(t *testing.T) {
	fx := newContractFixture(t)
	examples, err := cli.DocExamples()
	require.NoError(t, err)
	if data, readErr := os.ReadFile("../../docs/coding-agent.md"); readErr == nil {
		examples = append(examples, cli.MarkdownDocExamples("docs/coding-agent.md", string(data))...)
	}
	require.NotEmpty(t, examples)

	// One copy of the seeded install serves every example: they are reads,
	// and a read leaves the store's bytes alone.
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	require.NoError(t, copyTree(filepath.Join(fx.tmpl, "home"), home))
	db := filepath.Join(dir, "db.sqlite")
	require.NoError(t, copyTree(filepath.Join(fx.tmpl, "db.sqlite"), db))
	work := filepath.Join(dir, "cwd") // where an example's -o lands
	require.NoError(t, os.MkdirAll(work, 0o755))

	// A second finished scan of https://example.com, so the documented
	// `scan diff --target … --last 2` has two scans to compare.
	prev := filepath.Join(dir, "prev-scan.jsonl")
	require.NoError(t, os.WriteFile(prev, []byte(`{"type":"scan","data":{"uuid":"scan-0099-aaaa-bbbb-cccc-ddddeeee0099",`+
		`"name":"Earlier scan","status":"completed","target":"https://example.com","scan_source":"cli",`+
		`"started_at":"2026-01-01T08:00:00Z","finished_at":"2026-01-01T08:15:00Z",`+
		`"created_at":"2026-01-01T08:00:00Z","updated_at":"2026-01-01T08:15:00Z"}}`+"\n"), 0o600))
	r := runDocExample(t, fx.bin, home, work, []string{"--db", db, "import", prev, "-j"})
	require.Equalf(t, 0, r.code, "import the earlier scan\n%s", r)

	ran, jqChecked := 0, 0
	seen := map[string]bool{}
	for _, ex := range examples {
		path, why := cli.ReadOnlyDocExample(ex)
		dryRun := why != "" && slices.Contains(ex.Argv, "--dry-run") && docDryRunCommands[path]
		if (why != "" && !dryRun) || docStdinCommands[path] || humanOnlyDocExample(ex.Argv) {
			continue
		}
		argv, ok := substituteDocExample(path, ex.Argv)
		if !ok {
			continue
		}
		// A stateless dry run has no store to point at (-S and --db exclude
		// each other on a scan); everything else reads the seeded one.
		if stateless := slices.Contains(argv, "-S") || slices.Contains(argv, "--stateless"); !(dryRun && stateless) {
			argv = append([]string{"--db", db}, argv...)
		}
		key := strings.Join(argv, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		where := fmt.Sprintf("%s:%d: %s", ex.Source, ex.Line, ex.Text)
		if reason, skip := docExampleSkips[ex.Text]; skip {
			t.Logf("skip %s (%s)", where, reason)
			continue
		}
		ran++
		r := runDocExample(t, fx.bin, home, work, argv)
		if !assert0AndOneDocument(t, where, r) {
			continue
		}
		for _, stage := range ex.Pipe {
			filter, vars, ok := jqFilter(stage)
			if !ok {
				break
			}
			jqChecked++
			if err := evalDocJQ(filter, vars, r.stdout); err != nil {
				t.Errorf("%s\njq %q against the real document: %v\n%s", where, filter, err, r)
			}
			break // later stages read jq's output, not the document
		}
	}
	t.Logf("ran %d documented read examples, evaluated %d jq filters", ran, jqChecked)
	require.Greater(t, ran, 40, "the selection is broken: too few documented reads ran")
	require.GreaterOrEqual(t, jqChecked, 3, "the pipe extraction is broken: too few jq filters were checked")
	for text := range docExampleSkips {
		found := slices.ContainsFunc(examples, func(ex cli.DocExample) bool { return ex.Text == text })
		require.Truef(t, found, "docExampleSkips names %q, which no longer appears in the docs", text)
	}
}

func runDocExample(t *testing.T, bin, home, work string, argv []string) contractRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, argv...)
	cmd.Env = contractEnv(home, nil)
	cmd.Dir = work
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run %q: %v", argv, err)
	}
	return contractRun{argv: argv, code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// assert0AndOneDocument checks exit 0 and exactly one JSON object on stdout.
func assert0AndOneDocument(t *testing.T, where string, r contractRun) bool {
	t.Helper()
	if r.code != 0 {
		t.Errorf("%s\nexits %d against the seeded store, want 0\n%s", where, r.code, r)
		return false
	}
	dec := json.NewDecoder(strings.NewReader(r.stdout))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Errorf("%s\nstdout is not one JSON document: %v\n%s", where, err, r)
		return false
	}
	if dec.More() {
		t.Errorf("%s\nstdout holds more than one JSON document\n%s", where, r)
		return false
	}
	return true
}

// evalDocJQ runs filter over the document and requires it to succeed and to
// yield at least one value that is not null.
func evalDocJQ(filter string, vars map[string]any, stdout string) error {
	q, err := gojq.Parse(filter)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	names := make([]string, 0, len(vars))
	values := make([]any, 0, len(vars))
	for n, v := range vars {
		names = append(names, n)
		values = append(values, v)
	}
	code, err := gojq.Compile(q, gojq.WithVariables(names))
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	var doc any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		return err
	}
	iter := code.Run(doc, values...)
	nonNull := false
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if e, isErr := v.(error); isErr {
			var halt *gojq.HaltError
			if errors.As(e, &halt) && halt.Value() == nil {
				break
			}
			return e
		}
		if v != nil {
			nonNull = true
		}
	}
	if !nonNull {
		return errors.New("yields only null: the path names nothing in the document")
	}
	return nil
}

// The jq check fails the paths that rotted: rows that moved to `items`, a key
// that never existed. It needs no fixture.
func TestDocJQCatchesStalePaths(t *testing.T) {
	doc := `{"schema_version":2,"ok":true,"items":[{"uuid":"a"}],"plan":{"estimate":{"low":1}}}`
	require.NoError(t, evalDocJQ(".items[].uuid", nil, doc))
	require.NoError(t, evalDocJQ(".plan.estimate", nil, doc))
	require.NoError(t, evalDocJQ(`.items[] | select(.uuid == $u)`, map[string]any{"$u": "a"}, doc))
	require.Error(t, evalDocJQ(".records[].uuid", nil, doc), "iterating a missing row key fails")
	require.Error(t, evalDocJQ(".plan.estimat", nil, doc), "a misspelt key yields only null")
}
