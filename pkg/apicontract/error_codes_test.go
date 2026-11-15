package apicontract

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestErrorCodesClosedSet parses this package's source and checks that every
// ErrorCode constant is listed in knownErrorCodes. A constant declared but not
// listed is invisible to `vigolium schema` and to Valid(), which is how a
// "closed set" quietly stops being one.
func TestErrorCodesClosedSet(t *testing.T) {
	fset := token.NewFileSet()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	declared := map[ErrorCode]string{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				ident, ok := vs.Type.(*ast.Ident)
				if !ok || ident.Name != "ErrorCode" {
					continue
				}
				for i, name := range vs.Names {
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok {
						t.Fatalf("%s: value is not a string literal", name.Name)
					}
					v, _ := strconv.Unquote(lit.Value)
					if prev, dup := declared[ErrorCode(v)]; dup {
						t.Errorf("%q declared twice (%s, %s)", v, prev, name.Name)
					}
					declared[ErrorCode(v)] = name.Name
				}
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("found no ErrorCode constants; the parser walk is broken")
	}
	snake := regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
	for code, name := range declared {
		if !code.Valid() {
			t.Errorf("%s (%q) is declared but missing from knownErrorCodes", name, code)
		}
		if !snake.MatchString(string(code)) {
			t.Errorf("%s (%q) is not snake_case", name, code)
		}
	}
	if len(knownErrorCodes) != len(declared) {
		t.Errorf("knownErrorCodes has %d entries, %d constants declared", len(knownErrorCodes), len(declared))
	}
}

func TestErrorCodesSortedCopy(t *testing.T) {
	got := ErrorCodes()
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("ErrorCodes not strictly sorted at %d: %q, %q", i, got[i-1], got[i])
		}
	}
	got[0] = "mutated"
	if ErrorCodes()[0] == "mutated" {
		t.Fatal("ErrorCodes returned the backing slice")
	}
}

func TestIncompleteCodes(t *testing.T) {
	for _, c := range ErrorCodes() {
		want := c == CodeTimedOut || c == CodeBudgetExhausted || c == CodePartial || c == CodeInterrupted
		if c.IsIncomplete() != want {
			t.Errorf("%q.IsIncomplete() = %v, want %v", c, !want, want)
		}
	}
	if ErrorCode("bogus").Valid() {
		t.Error("an unknown code reported Valid")
	}
}

func TestErrorCodeExit(t *testing.T) {
	for code, want := range map[ErrorCode]int{
		CodeUsageError:    ExitUsageError,
		CodeOutOfScope:    ExitUsageError,
		CodeGateTripped:   ExitFailOnGate,
		CodeTimedOut:      ExitIncomplete,
		CodePartial:       ExitIncomplete,
		CodeInterrupted:   ExitIncomplete,
		CodeAmbiguousID:   ExitError,
		CodeFailed:        ExitError,
		CodeSourceMissing: ExitError,
	} {
		if got := code.Exit(); got != want {
			t.Errorf("%s.Exit() = %d, want %d", code, got, want)
		}
	}
}
