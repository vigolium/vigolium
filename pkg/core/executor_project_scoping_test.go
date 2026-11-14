package core

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/work"
)

// coreRepoRoot walks up from this file to the module root.
func coreRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate module root (no go.mod found)")
		}
		dir = parent
	}
}

// TestExecutorConfigAlwaysSetsProjectUUID is the structural guard for a
// multi-tenancy data-integrity bug that shipped in the 0.3 line: every
// ExecutorConfig literal in the tree omitted ProjectUUID.
//
// The field is declared on ExecutorConfig and consumed on every executor write
// path — saveToDatabase's recordWriter.Write/repo.SaveRecord, and
// executor_results.go's finding-evidence record + SaveFinding calls — but not
// one of its seven construction sites ever populated it. defaultProjectUUID("")
// then silently rewrote the empty value to the DEFAULT project, so a scan run
// under `--project`/`--project-name` wrote its records and ALL of its findings
// into a project nobody was reading. The scan summary, the JSONL export and the
// DBInputSource feed all filter by the scan's own project, so a perfectly
// healthy scan reported "no issues found".
//
// That failure is invisible in a unit test of any single call site — the bug is
// precisely the absence of a line — so it is asserted structurally instead: any
// new ExecutorConfig literal must name ProjectUUID. Pass the empty string
// explicitly (with a comment saying why) if a call site genuinely has no
// project, so that "unscoped" is a decision on the record rather than an
// oversight.
//
// Known limitation: this sees keyed composite literals only. A site that builds
// the config and then assigns cfg.Repository = repo afterwards is not covered —
// the executor's own nil-checks are the backstop there.
func TestExecutorConfigAlwaysSetsProjectUUID(t *testing.T) {
	root := coreRepoRoot(t)

	// One FileSet for the whole walk: positions stay correct across files and
	// we avoid allocating one per source file.
	fset := token.NewFileSet()
	var offenders []string

	for _, top := range []string{"pkg", "internal", "cmd"} {
		base := filepath.Join(root, top)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
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

			// Cheap prefilter: ~2000 non-test files live under these trees and
			// only a handful mention ExecutorConfig, so parsing every one costs
			// an order of magnitude more than the byte scan that rules them out
			// (and ~25x under -race). A keyed literal of this type must spell
			// the type name in the file, so the filter cannot hide an offender.
			src, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Contains(src, []byte("ExecutorConfig")) {
				return nil
			}

			// SkipObjectResolution: this walk reads only composite literals and
			// identifiers, never the (expensive to build) Obj graph.
			f, parseErr := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
			if parseErr != nil {
				return nil
			}

			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || !isExecutorConfigType(lit.Type) {
					return true
				}

				// Collect the field names this literal sets. A positional
				// literal (no keys) is not something we can check by field
				// name, and nobody writes one for a struct this wide.
				fields := make(map[string]bool, len(lit.Elts))
				for _, elt := range lit.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if ident, ok := kv.Key.(*ast.Ident); ok {
							fields[ident.Name] = true
						}
					}
				}

				// Only a config that can WRITE needs to declare its project.
				// Repository / RecordWriter / FindingWriter are the executor's
				// only persistence paths and all three are nil-guarded, so a
				// literal carrying none of them (e.g. ExecutorConfig{})
				// has nothing to misfile. Adding any of them to a literal
				// brings it under this check.
				if !fields["Repository"] && !fields["RecordWriter"] && !fields["FindingWriter"] {
					return true
				}
				if fields["ProjectUUID"] {
					return true
				}

				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders, fmt.Sprintf("%s:%d", rel, fset.Position(lit.Pos()).Line))
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}

	if len(offenders) > 0 {
		// WalkDir visits lexically and ast.Inspect walks in source order, so
		// this list is already deterministic.
		t.Fatalf("core.ExecutorConfig literal(s) do not set ProjectUUID.\n"+
			"Records and findings written by these executors will fall through to the\n"+
			"DEFAULT project and become invisible to every project-scoped read:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// isExecutorConfigType reports whether a composite-literal type is
// ExecutorConfig, spelled either bare (inside package core) or qualified as
// core.ExecutorConfig from another package.
func isExecutorConfigType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name == "ExecutorConfig"
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		return ok && pkg.Name == "core" && t.Sel.Name == "ExecutorConfig"
	}
	return false
}

// TestNewExecutorPropagatesProjectUUID pins the config → field hop that the
// write paths read. Without it every assertion below would pass against an
// executor that still writes to the default project.
func TestNewExecutorPropagatesProjectUUID(t *testing.T) {
	const project = "11111111-2222-3333-4444-555555555555"

	e := NewExecutor(ExecutorConfig{
		Workers:     1,
		ProjectUUID: project,
	}, nil, nil, nil)

	if e.projectUUID != project {
		t.Fatalf("executor projectUUID = %q, want %q", e.projectUUID, project)
	}
}

// TestSaveToDatabase_StampsConfiguredProject proves the record write path
// honors the scan's project rather than silently defaulting. This is the exact
// row that went missing: with an empty projectUUID the record landed under
// DefaultProjectUUID, so the DBInputSource feed (which pins
// project_uuid = <scan's project>) had nothing to hand the modules and
// DynamicAssessment reported "0 items".
func TestSaveToDatabase_StampsConfiguredProject(t *testing.T) {
	const project = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	e, db := newRepoExecutor(t)
	e.projectUUID = project
	ctx := context.Background()

	req := newStubRecord("api.example.com", "/api/users").WithResponse(
		httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}")))

	e.saveToDatabase(ctx, work.NewWithModules(req, nil), req, nil)

	var records []*database.HTTPRecord
	if err := db.NewSelect().Model(&records).Scan(ctx); err != nil {
		t.Fatalf("select records: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("http_records = %d, want 1", len(records))
	}
	if records[0].ProjectUUID != project {
		t.Errorf("record project_uuid = %q, want %q (a record stamped with the default project is invisible to a project-scoped scan)",
			records[0].ProjectUUID, project)
	}
}

// TestProcessResults_StampsConfiguredProjectOnFindings is the other half of the
// bug: findings were written to the default project while the scan summary
// counted only the scan's own project, which is what produced the reported
// "Findings: no issues found" on a scan that had just streamed dozens of them.
func TestProcessResults_StampsConfiguredProjectOnFindings(t *testing.T) {
	const project = "99999999-8888-7777-6666-555555555555"

	e, db := newRepoExecutor(t)
	e.projectUUID = project
	ctx := context.Background()

	result := &output.ResultEvent{
		ModuleID: "sqli-scanner",
		Info: output.Info{
			Name:       "SQL Injection",
			Severity:   severity.High,
			Confidence: severity.Firm,
		},
		Host:    "example.com",
		URL:     "https://example.com/item?id=1",
		Matched: "https://example.com/item?id=1",
	}

	e.processResults(ctx, []*output.ResultEvent{result}, &trackingPassiveModule{id: "sqli-scanner"}, nil, nil)

	findings := loadFindings(t, db)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].ProjectUUID != project {
		t.Errorf("finding project_uuid = %q, want %q (a finding stamped with the default project is invisible to the scan that produced it)",
			findings[0].ProjectUUID, project)
	}
}
