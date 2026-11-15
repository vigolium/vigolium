package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestUsageErrorsAreClassified keeps command-line mistakes on exit 2.
//
// A rejected flag combination returned as a plain fmt.Errorf exits 1 with
// error.code "failed", which tells a driver the work broke when in fact it
// never started and the fix is a different command line. This walks every
// non-test file under pkg/cli and flags a fmt.Errorf / errors.New whose message
// reads like a usage error unless it is built (or wrapped) as one.
//
// Exempt:
//   - methods named Set or Type (pflag.Value): cobra reports those errors as
//     "invalid argument", which flagErrorFunc already maps to 2;
//   - a call on a line carrying, or directly below, a
//     `//vigolium:not-usage <reason>` comment, for messages that only look like
//     usage errors (a missing field in a stored record, say).
func TestUsageErrorsAreClassified(t *testing.T) {
	var violations []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		violations = append(violations, usageLintFile(t, path)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) > 0 {
		t.Errorf("%d usage-shaped errors are not usage errors (wrap with usageErrorf/asUsageError, "+
			"clicommon.UsageErrorf outside package cli, or annotate //vigolium:not-usage <reason>):\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
}

var (
	// usageMessagePrefix: a message about a flag (`--x …`, `-S …`) or a usage line.
	usageMessagePrefix = regexp.MustCompile(`^(--[a-zA-Z]|-[a-zA-Z] |usage:)`)
	usageMessagePhrase = []string{"mutually exclusive", "cannot be combined", "requires -", "is required"}
)

func isUsageShapedMessage(msg string) bool {
	if usageMessagePrefix.MatchString(msg) {
		return true
	}
	for _, p := range usageMessagePhrase {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

// usageWrapperNames are the calls whose direct argument may be a plain error:
// the wrapper is what classifies it.
var usageWrapperNames = map[string]bool{
	"asUsageError": true, "usageErrorf": true,
	"AsUsageError": true, "UsageErrorf": true,
}

func usageLintFile(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	annotated := map[int]bool{}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//vigolium:not-usage") {
				line := fset.Position(c.Slash).Line
				annotated[line] = true
				annotated[line+1] = true
			}
		}
	}

	var out []string
	var visit func(n ast.Node, wrapped bool) bool
	inspect := func(root ast.Node) {
		ast.Inspect(root, func(n ast.Node) bool { return visit(n, false) })
	}
	visit = func(n ast.Node, wrapped bool) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := callName(call)
		if usageWrapperNames[name] {
			// The wrapper's direct arguments are classified by it; anything
			// nested deeper (an fmt.Errorf inside a helper call) is not.
			for _, arg := range call.Args {
				if inner, ok := arg.(*ast.CallExpr); ok && isErrorConstructor(inner) {
					for _, a := range inner.Args {
						ast.Inspect(a, func(n ast.Node) bool { return visit(n, false) })
					}
					continue
				}
				ast.Inspect(arg, func(n ast.Node) bool { return visit(n, false) })
			}
			return false
		}
		if !isErrorConstructor(call) || len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		msg, err := strconv.Unquote(lit.Value)
		if err != nil || !isUsageShapedMessage(msg) {
			return true
		}
		pos := fset.Position(call.Pos())
		if annotated[pos.Line] {
			return true
		}
		out = append(out, pos.String()+": "+strconv.Quote(msg))
		return true
	}

	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil &&
			(fn.Name.Name == "Set" || fn.Name.Name == "Type") {
			continue
		}
		inspect(decl)
	}
	return out
}

func isErrorConstructor(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return (pkg.Name == "fmt" && sel.Sel.Name == "Errorf") ||
		(pkg.Name == "errors" && sel.Sel.Name == "New")
}

func callName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// The detector itself, so a refactor of the walk cannot quietly stop flagging.
func TestUsageLintDetector(t *testing.T) {
	for msg, want := range map[string]bool{
		"--format sqlite requires -S":         true,
		"-S cannot be used with --db":         true,
		"usage: config set <key> <value>":     true,
		"--a and --b are mutually exclusive":  true,
		"a target is required":                true,
		"failed to open database: locked":     false,
		"record %q has no response bytes":     false,
		"-1 is not a port":                    false,
		"scan requires an http(s) target URL": false,
	} {
		if got := isUsageShapedMessage(msg); got != want {
			t.Errorf("isUsageShapedMessage(%q) = %v, want %v", msg, got, want)
		}
	}
}
