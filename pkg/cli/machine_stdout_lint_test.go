package cli

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// machineStdoutBaseline lists today's raw stdout writers in pkg/cli, one
// `<file> <func> <count>` line each. It may only shrink: a writer migrated to
// the envelope (emitRead/emitObject/emitMutation → writeAgentJSON) deletes its
// line. Regenerate after a removal with VIGOLIUM_UPDATE_STDOUT_BASELINE=1.
const machineStdoutBaseline = "testdata/machine_stdout_baseline.txt"

// stdoutStreamWriters are the writers that legitimately own stdout outside the
// envelope: the one JSON writer every document funnels through, and documented
// streams. Keyed `<file> <func>`.
var stdoutStreamWriters = map[string]string{
	"agentview.go writeAgentJSONDoc":       "the single -j document writer",
	"replay_bulk.go runReplayBulk":         "bulk replay per-record human tables",
	"replay_output.go openStreamEncoder":   "replay --format jsonl per-record stream",
	"skills.go writeBody":                  "skills get: raw SKILL.md markdown; kit wordlist: the list bytes; schema: the bare JSON Schema; kit cookies --stdout: the export (all human mode; -j is an envelope)",
	"server_ca.go runServerCAPrint":        "server ca print: the PEM certificate is the output (the -j path is an envelope)",
	"traffic_extract.go deliverBody":       "traffic body: the body bytes are the output",
	"traffic_extract.go runTrafficHeaders": "traffic headers: human header block (the -j path is an envelope)",
	"traffic_request.go runTrafficRequest": "traffic request: the raw stored request is the output (the -j path is an envelope)",
}

// TestMachineStdoutLint keeps raw JSON off stdout.
//
// A command that hand-rolls json.NewEncoder(os.Stdout), writes os.Stdout
// directly, or fmt.Print*s a json.Marshal result skips the envelope, the
// one-document latch, -o and --max-output-bytes. Every such writer in pkg/cli
// is either a documented stream (stdoutStreamWriters) or on the shrink-only
// baseline; anything new fails here.
func TestMachineStdoutLint(t *testing.T) {
	found := map[string]int{}
	var where = map[string][]string{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		for _, hit := range stdoutLintFile(t, path) {
			key := filepath.ToSlash(path) + " " + hit.fn
			if _, ok := stdoutStreamWriters[key]; ok {
				continue
			}
			found[key]++
			where[key] = append(where[key], hit.pos+": "+hit.what)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if os.Getenv("VIGOLIUM_UPDATE_STDOUT_BASELINE") == "1" {
		writeStdoutBaseline(t, found)
		return
	}

	baseline := readStdoutBaseline(t)
	for _, key := range sortedMapKeys(found) {
		if n, allowed := found[key], baseline[key]; n > allowed {
			t.Errorf("%s writes raw output to stdout %d time(s) (baseline %d); emit through emitRead/emitObject/emitMutation instead:\n    %s",
				key, n, allowed, strings.Join(where[key], "\n    "))
		}
	}
	for _, key := range sortedMapKeys(baseline) {
		if found[key] < baseline[key] {
			t.Errorf("%s now has %d raw stdout writer(s), below its baseline of %d: lower %s (VIGOLIUM_UPDATE_STDOUT_BASELINE=1) so it cannot grow back",
				key, found[key], baseline[key], machineStdoutBaseline)
		}
	}
}

type stdoutHit struct{ fn, pos, what string }

// stdoutLintFile reports the raw stdout writers in one file, with the
// enclosing top-level function (methods as Type.Method).
func stdoutLintFile(t *testing.T, path string) []stdoutHit {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []stdoutHit
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		name := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			name = recvTypeName(fn.Recv.List[0].Type) + "." + name
		}
		for _, h := range stdoutWritesIn(fn.Body) {
			out = append(out, stdoutHit{fn: name, pos: fset.Position(h.pos).String(), what: h.what})
		}
	}
	return out
}

type rawWrite struct {
	pos  token.Pos
	what string
}

// stdoutWritesIn finds the three raw-writer shapes in a function body.
func stdoutWritesIn(body *ast.BlockStmt) []rawWrite {
	// Names bound to a json.Marshal result anywhere in the function.
	marshaled := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || len(as.Lhs) == 0 {
			return true
		}
		if call, ok := as.Rhs[0].(*ast.CallExpr); ok && isJSONMarshalCall(call) {
			if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
				marshaled[id.Name] = true
			}
		}
		return true
	})

	var out []rawWrite
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch {
		case isPkgCall(call, "json", "NewEncoder") && len(call.Args) == 1 && isOSStdout(call.Args[0]):
			out = append(out, rawWrite{call.Pos(), "json.NewEncoder(os.Stdout)"})
		case isOSStdoutMethod(call, "Write", "WriteString"):
			out = append(out, rawWrite{call.Pos(), "os.Stdout." + call.Fun.(*ast.SelectorExpr).Sel.Name})
		case isPkgCall(call, "fmt", "Print", "Println", "Printf"):
			if mentionsMarshaled(call.Args, marshaled) {
				out = append(out, rawWrite{call.Pos(), "fmt.Print* of a json.Marshal result"})
			}
		case isPkgCall(call, "fmt", "Fprint", "Fprintln", "Fprintf"):
			if len(call.Args) > 1 && isOSStdout(call.Args[0]) && mentionsMarshaled(call.Args[1:], marshaled) {
				out = append(out, rawWrite{call.Pos(), "fmt.Fprint*(os.Stdout) of a json.Marshal result"})
			}
		}
		return true
	})
	return out
}

func isJSONMarshalCall(call *ast.CallExpr) bool {
	return isPkgCall(call, "json", "Marshal", "MarshalIndent")
}

func isPkgCall(call *ast.CallExpr, pkg string, names ...string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != pkg {
		return false
	}
	for _, n := range names {
		if sel.Sel.Name == n {
			return true
		}
	}
	return false
}

func isOSStdout(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "os" && sel.Sel.Name == "Stdout"
}

func isOSStdoutMethod(call *ast.CallExpr, names ...string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !isOSStdout(sel.X) {
		return false
	}
	for _, n := range names {
		if sel.Sel.Name == n {
			return true
		}
	}
	return false
}

// mentionsMarshaled reports whether any argument is (or wraps, as string(b))
// a name bound to a json.Marshal result, or is a json.Marshal call itself.
func mentionsMarshaled(args []ast.Expr, marshaled map[string]bool) bool {
	hit := false
	for _, a := range args {
		ast.Inspect(a, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.Ident:
				if marshaled[v.Name] {
					hit = true
				}
			case *ast.CallExpr:
				if isJSONMarshalCall(v) {
					hit = true
				}
			}
			return !hit
		})
	}
	return hit
}

func recvTypeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(v.X)
	case *ast.Ident:
		return v.Name
	case *ast.IndexExpr:
		return recvTypeName(v.X)
	}
	return "?"
}

func readStdoutBaseline(t *testing.T) map[string]int {
	t.Helper()
	f, err := os.Open(machineStdoutBaseline)
	if err != nil {
		t.Fatalf("open %s: %v", machineStdoutBaseline, err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("%s: malformed line %q (want `<file> <func> <count>`)", machineStdoutBaseline, line)
		}
		n, err := strconv.Atoi(fields[2])
		if err != nil {
			t.Fatalf("%s: bad count in %q", machineStdoutBaseline, line)
		}
		out[fields[0]+" "+fields[1]] = n
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func writeStdoutBaseline(t *testing.T, found map[string]int) {
	t.Helper()
	var b strings.Builder
	b.WriteString("# Raw stdout writers in pkg/cli that bypass the -j envelope (machine_stdout_lint_test.go).\n")
	b.WriteString("# Shrink-only: delete a line when its writer moves to emitRead/emitObject/emitMutation.\n")
	b.WriteString("# <file> <func> <count>\n")
	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s %d\n", k, found[k])
	}
	if err := os.MkdirAll(filepath.Dir(machineStdoutBaseline), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(machineStdoutBaseline, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s with %d entries", machineStdoutBaseline, len(keys))
}

// The detector itself, so a refactor of the walk cannot quietly stop flagging.
func TestMachineStdoutLintDetector(t *testing.T) {
	src := `package x
func f() {
	enc := json.NewEncoder(os.Stdout)
	_ = enc
	os.Stdout.Write(nil)
	b, _ := json.Marshal(1)
	fmt.Println(string(b))
	fmt.Fprintf(os.Stdout, "%s\n", b)
	fmt.Fprintln(os.Stderr, string(b))
	fmt.Println("plain text")
	json.NewEncoder(os.Stderr)
}`
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := stdoutWritesIn(f.Decls[0].(*ast.FuncDecl).Body)
	if len(got) != 4 {
		t.Fatalf("detected %d raw writers, want 4: %+v", len(got), got)
	}
}
