//go:build sast

package sast

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/toolexec/astgrep"
	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestExtraction_All loads all extraction definitions and runs each.
func TestExtraction_All(t *testing.T) {
	dir := filepath.Join(definitionsDir(), "extraction")
	defs, err := harness.LoadSASTExtractionDefinitionsFromDir(dir)
	require.NoError(t, err, "failed to load extraction definitions")
	require.NotEmpty(t, defs, "no extraction definitions found in %s", dir)

	for _, def := range defs {
		t.Run(def.Framework, func(t *testing.T) {
			runExtractionDefinition(t, def)
		})
	}
}

func TestExtraction_Gin_Routes(t *testing.T) {
	runExtractionForFramework(t, "gin-extraction.yaml")
}

func TestExtraction_FastAPI_Routes(t *testing.T) {
	runExtractionForFramework(t, "fastapi-extraction.yaml")
}

func TestExtraction_Express_Routes(t *testing.T) {
	runExtractionForFramework(t, "express-extraction.yaml")
}

func TestExtraction_Django_Routes(t *testing.T) {
	runExtractionForFramework(t, "django-extraction.yaml")
}

func TestExtraction_Flask_Routes(t *testing.T) {
	runExtractionForFramework(t, "flask-extraction.yaml")
}

func TestExtraction_NextJS_Routes(t *testing.T) {
	runExtractionForFramework(t, "nextjs-extraction.yaml")
}

func TestExtraction_GoHTTP_Routes(t *testing.T) {
	runExtractionForFramework(t, "gohttp-extraction.yaml")
}

func TestExtraction_NextJS_Oopssec_Routes(t *testing.T) {
	runExtractionForFramework(t, "nextjs-oopssec-extraction.yaml")
}

func TestExtraction_NextJS_VulnExamples_Routes(t *testing.T) {
	runExtractionForFramework(t, "nextjs-vulnexamples-extraction.yaml")
}

// TestExtraction_DetectFramework validates DetectFramework for all stubs.
func TestExtraction_DetectFramework(t *testing.T) {
	dir := filepath.Join(definitionsDir(), "extraction")
	defs, err := harness.LoadSASTExtractionDefinitionsFromDir(dir)
	require.NoError(t, err)

	for _, def := range defs {
		if !def.DetectFramework {
			continue
		}
		t.Run(def.Framework, func(t *testing.T) {
			stubDir := stubPath(def.SourceDir)
			detected := astgrep.DetectFramework(stubDir)
			assert.Equal(t, def.Framework, detected,
				"DetectFramework(%s) should return %q, got %q", stubDir, def.Framework, detected)
		})
	}
}

func runExtractionForFramework(t *testing.T, filename string) {
	t.Helper()
	defPath := filepath.Join(definitionsDir(), "extraction", filename)
	def, err := harness.LoadSASTExtractionDefinition(defPath)
	require.NoError(t, err, "failed to load definition %s", filename)
	runExtractionDefinition(t, def)
}

func runExtractionDefinition(t *testing.T, def *harness.SASTExtractionDefinition) {
	t.Helper()

	stubDir := stubPath(def.SourceDir)
	ctx := context.Background()

	scanner, err := astgrep.NewScanner(nil)
	require.NoError(t, err, "failed to create scanner")

	result, err := scanner.ScanDirWithFramework(ctx, stubDir, def.Framework)
	require.NoError(t, err, "ScanDirWithFramework(%s, %s) failed", stubDir, def.Framework)

	routes := astgrep.MatchesToRoutes(result.Matches)
	t.Logf("[%s] Found %d matches, %d routes", def.Framework, len(result.Matches), len(routes))

	for _, r := range routes {
		t.Logf("  Route: %s %s (file=%s, line=%d, params=%v)", r.Method, r.Path, r.File, r.Line, r.Params)
	}

	// Validate match count bounds
	if def.ExpectedMatchCount.Min > 0 {
		assert.GreaterOrEqual(t, len(result.Matches), def.ExpectedMatchCount.Min,
			"[%s] expected >= %d matches, got %d", def.Framework, def.ExpectedMatchCount.Min, len(result.Matches))
	}
	if def.ExpectedMatchCount.Max > 0 {
		assert.LessOrEqual(t, len(result.Matches), def.ExpectedMatchCount.Max,
			"[%s] expected <= %d matches, got %d", def.Framework, def.ExpectedMatchCount.Max, len(result.Matches))
	}

	// Validate expected routes
	for _, er := range def.ExpectedRoutes {
		found := findRouteFlexible(routes, er.Method, er.Path, er.File)
		switch er.Assertion {
		case "strict":
			if !assert.NotNil(t, found, "[%s] expected route %s %s in %s not found", def.Framework, er.Method, er.Path, er.File) {
				continue
			}
			if len(er.Params) > 0 {
				assert.ElementsMatch(t, er.Params, found.Params,
					"[%s] route %s %s params mismatch", def.Framework, er.Method, er.Path)
			}
		case "soft":
			if found == nil {
				t.Logf("[%s] soft: expected route %s %s in %s not found (non-fatal)", def.Framework, er.Method, er.Path, er.File)
			}
		}
	}

	// Validate negative routes (must NOT appear)
	for _, nr := range def.NegativeRoutes {
		found := findRouteFlexible(routes, nr.Method, nr.Path, "")
		assert.Nil(t, found, "[%s] negative route %s %s should NOT be found", def.Framework, nr.Method, nr.Path)
	}
}

// findRouteFlexible searches routes with flexible matching:
// - Empty method or path means "match any"
// - File matching uses suffix matching for absolute paths
func findRouteFlexible(routes []astgrep.Route, method, path, file string) *astgrep.Route {
	for i := range routes {
		r := &routes[i]

		// Method match: empty means any, case-insensitive
		if method != "" && !strings.EqualFold(r.Method, method) {
			continue
		}

		// Path match: empty means any
		if path != "" && r.Path != path {
			continue
		}

		// File match: use suffix matching for absolute paths
		if file != "" && !strings.HasSuffix(r.File, file) {
			continue
		}

		return r
	}
	return nil
}
