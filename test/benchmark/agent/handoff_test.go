//go:build agent_benchmark

package agent

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentpkg "github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestHandoff_All loads all handoff definitions and runs each.
func TestHandoff_All(t *testing.T) {
	dir := filepath.Join(definitionsDir(), "handoff")
	defs, err := harness.LoadAgentHandoffDefinitionsFromDir(dir)
	require.NoError(t, err, "failed to load handoff definitions")
	require.NotEmpty(t, defs, "no handoff definitions found in %s", dir)

	for _, def := range defs {
		t.Run(def.Fixture, func(t *testing.T) {
			runHandoffDefinition(t, def)
		})
	}
}

func TestHandoff_GinEndpoints(t *testing.T) {
	runHandoffForFixture(t, "gin-endpoint-handoff.yaml")
}

func TestHandoff_FlaskEndpoints(t *testing.T) {
	runHandoffForFixture(t, "flask-endpoint-handoff.yaml")
}

func TestHandoff_ExpressEndpoints(t *testing.T) {
	runHandoffForFixture(t, "express-endpoint-handoff.yaml")
}

func TestHandoff_FastAPIEndpoints(t *testing.T) {
	runHandoffForFixture(t, "fastapi-endpoint-handoff.yaml")
}

// TestHandoff_EmptyURL validates that records with empty URLs are skipped.
func TestHandoff_EmptyURL(t *testing.T) {
	rec := agentpkg.AgentHTTPRecord{
		Method: "GET",
		URL:    "",
	}
	_, err := agentpkg.ToHTTPRequestResponse(rec)
	assert.Error(t, err, "expected error for empty URL")
}

// TestHandoff_DefaultMethod validates that empty method defaults to GET.
func TestHandoff_DefaultMethod(t *testing.T) {
	rec := agentpkg.AgentHTTPRecord{
		Method:  "",
		URL:     "http://localhost:8080/test",
		Headers: map[string]string{"Host": "localhost:8080"},
	}
	hrr, err := agentpkg.ToHTTPRequestResponse(rec)
	require.NoError(t, err)
	assert.Equal(t, "GET", hrr.Request().Method(), "empty method should default to GET")
}

func runHandoffForFixture(t *testing.T, filename string) {
	t.Helper()
	defPath := filepath.Join(definitionsDir(), "handoff", filename)
	def, err := harness.LoadAgentHandoffDefinition(defPath)
	require.NoError(t, err, "failed to load handoff definition %s", filename)
	runHandoffDefinition(t, def)
}

func runHandoffDefinition(t *testing.T, def *harness.AgentHandoffDefinition) {
	t.Helper()

	fPath := fixturePath(def.Fixture)
	fixture, err := harness.LoadAgentFixture(fPath)
	require.NoError(t, err, "failed to load fixture %s", fPath)

	records, parseErr := agentpkg.ParseHTTPRecords(fixture.RawOutput)
	require.NoError(t, parseErr, "[%s] failed to parse HTTP records", def.Fixture)

	t.Logf("[%s] Parsed %d records, expecting %d convertible, %d skipped",
		def.Fixture, len(records), def.Expected.ConvertibleCount, def.Expected.SkippedCount)

	// Convert all records and count successes/skips
	var converted, skipped int
	for _, rec := range records {
		hrr, convErr := agentpkg.ToHTTPRequestResponse(rec)
		if convErr != nil {
			t.Logf("[%s] Skipped: %s %s (error: %v)", def.Fixture, rec.Method, rec.URL, convErr)
			skipped++
			continue
		}
		converted++
		t.Logf("[%s] Converted: %s %s → method=%s host=%s",
			def.Fixture, rec.Method, rec.URL, hrr.Request().Method(), hrr.Request().Header("Host"))
	}

	assert.Equal(t, def.Expected.ConvertibleCount, converted,
		"[%s] expected %d convertible records, got %d", def.Fixture, def.Expected.ConvertibleCount, converted)
	assert.Equal(t, def.Expected.SkippedCount, skipped,
		"[%s] expected %d skipped records, got %d", def.Fixture, def.Expected.SkippedCount, skipped)

	// Validate specific expected records
	for _, er := range def.Expected.Records {
		found := findRecordByMethod(records, er.Method, er.URLPrefix)
		if er.Assertion == "strict" {
			require.NotNil(t, found,
				"[%s] expected record %s %s* not found", def.Fixture, er.Method, er.URLPrefix)
		} else if found == nil {
			t.Logf("[%s] SOFT: expected record %s %s* not found", def.Fixture, er.Method, er.URLPrefix)
			continue
		}

		// Convert and validate
		hrr, convErr := agentpkg.ToHTTPRequestResponse(*found)
		require.NoError(t, convErr, "[%s] failed to convert record %s %s", def.Fixture, found.Method, found.URL)

		// Validate method
		assert.Equal(t, strings.ToUpper(er.Method), hrr.Request().Method(),
			"[%s] method mismatch for %s", def.Fixture, er.URLPrefix)

		// Validate host header
		if er.HasHost {
			parsedURL, _ := url.Parse(found.URL)
			if parsedURL != nil {
				host := hrr.Request().Header("Host")
				assert.NotEmpty(t, host,
					"[%s] expected Host header for %s %s", def.Fixture, er.Method, er.URLPrefix)
			}
		}
	}
}
