package database

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// createSchemaAllowed is the ratchet of production call sites outside
// pkg/database that still call CreateSchema directly, with how many each may
// keep. It only shrinks: route a site through EnsureSchemaReady (direct opens)
// or the CLI's write-intent opener (getDBFor(clicommon.IntentWrite)) and delete
// its entry.
//
// agent_input.go's call runs on a handle getDB already made ready.
var createSchemaAllowed = map[string]int{
	"pkg/cli/agent_input.go": 1,
}

// TestNoNewCreateSchemaCallSites keeps schema DDL inside pkg/database.
//
// CreateSchema unconditionally issues ~150 DDL statements, every one of which
// takes SQLite's write lock: a read command calling it on open queued behind any
// concurrent scan for up to busy_timeout, and an older binary calling it against
// a newer store rewrote that store. EnsureSchemaReady (checks first, guards
// schema_too_new) and the CLI's intent-aware opener are the supported entry
// points; Migrate is the explicit one.
func TestNoNewCreateSchemaCallSites(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skipf("repository root not found from %s: %v", root, err)
	}

	got := map[string]int{}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch rel {
			case "platform", "vendor", "node_modules", ".git", "pkg/database":
				return filepath.SkipDir
			}
			if strings.HasPrefix(d.Name(), ".") && rel != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil // a file another change has mid-edit is not this test's concern
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "CreateSchema" {
				got[rel]++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	for file, n := range got {
		if allowed := createSchemaAllowed[file]; n > allowed {
			t.Errorf("%s calls CreateSchema %d time(s) (allowed %d): use db.EnsureSchemaReady(ctx) "+
				"for a direct open, or the CLI's write-intent opener, instead of unconditional schema DDL",
				file, n, allowed)
		}
	}
	for file, allowed := range createSchemaAllowed {
		if got[file] < allowed {
			t.Errorf("%s now calls CreateSchema %d time(s), below its allowance of %d: lower the ratchet in createSchemaAllowed",
				file, got[file], allowed)
		}
	}
}
