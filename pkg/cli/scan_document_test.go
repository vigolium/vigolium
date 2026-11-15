package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// scanDocJSON is the scan document as a consumer decodes it.
type scanDocJSON struct {
	SchemaVersion     int                     `json:"schema_version"`
	Command           string                  `json:"command"`
	Kind              string                  `json:"kind"`
	OK                bool                    `json:"ok"`
	Error             *agentError             `json:"error"`
	ScanUUID          string                  `json:"scan_uuid"`
	ScanUUIDs         []string                `json:"scan_uuids"`
	ProjectUUID       string                  `json:"project_uuid"`
	DBPath            string                  `json:"db_path"`
	Persisted         bool                    `json:"persisted"`
	Stateless         bool                    `json:"stateless"`
	Status            string                  `json:"status"`
	Completeness      string                  `json:"completeness"`
	StopReason        string                  `json:"stop_reason"`
	Reasons           []string                `json:"reasons"`
	Targets           []scanDocTarget         `json:"targets"`
	TargetsNotScanned []string                `json:"targets_not_scanned"`
	PhaseOutcomes     []database.PhaseOutcome `json:"phase_outcomes"`
	Modules           scanDocModules          `json:"modules"`
	CountsBySeverity  map[string]int          `json:"counts_by_severity"`
	Candidates        int64                   `json:"candidates"`
	Observations      int64                   `json:"observations"`
	Errors            []scanDocError          `json:"errors"`
	Total             int64                   `json:"total"`
	Limit             int                     `json:"limit"`
	Items             []map[string]any        `json:"items"`
	ItemsTruncated    bool                    `json:"items_truncated"`
	Query             string                  `json:"query"`
	QueryArgv         []string                `json:"query_argv"`
}

// decodeOneScanDoc asserts stdout is exactly ONE JSON document and decodes it
// as the scan document.
func decodeOneScanDoc(t *testing.T, stdout string) scanDocJSON {
	t.Helper()
	docs := decodeStdoutDocuments(t, stdout)
	require.Len(t, docs, 1, "exactly one document on stdout:\n%s", stdout)
	var doc scanDocJSON
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(stdout)), &doc), stdout)
	assert.Equal(t, AgentSchemaVersion, doc.SchemaVersion)
	assert.Equal(t, "scan", doc.Kind)
	// A failed scan still prints its document; ok and error then say it failed.
	assert.Equal(t, doc.OK, doc.Error == nil, "error is present exactly when ok is false")
	return doc
}

// nucleiKeys matches the output.ResultEvent JSON shape (an import and legacy
// format): none of it may appear in a scan document.
var nucleiKeys = regexp.MustCompile(`"template-id"|"matched-at"|"extracted-results"|"info":\{`)

func assertNoNucleiKeys(t *testing.T, stdout string) {
	t.Helper()
	assert.Falsef(t, nucleiKeys.MatchString(stdout), "nuclei-shaped keys in the scan document:\n%s", stdout)
}

// A result rendered in memory (an unpersisted direct scan) must have the shape
// the scan document gives the same result once stored and read back by
// scan_uuid (`finding -j`'s view plus the evidence columns): same keys, same
// values, except the store-assigned ones.
func TestFindingViewFromEventMatchesStoredView(t *testing.T) {
	cfg := config.DefaultSettings().Database
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "view.sqlite")
	db, err := database.NewDB(&cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.EnsureSchemaReady(context.Background()))
	repo := database.NewRepository(db)

	const scanUUID = "11111111-0000-0000-0000-000000000001"
	newEvent := func() *output.ResultEvent {
		ev := &output.ResultEvent{
			ModuleID:         "sqli-error-based",
			ModuleType:       "active",
			URL:              "http://app.test/item?id=1",
			Matched:          "http://app.test/item?id=1%27",
			Host:             "app.test",
			ExtractedResults: []string{"You have an error in your SQL syntax"},
			Request:          "GET /item?id=1%27 HTTP/1.1\r\nHost: app.test\r\n\r\n",
			Response:         "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<p>You have an error in your SQL syntax near '1''</p>",
			Metadata:         map[string]interface{}{"cwe": "CWE-89"},
		}
		ev.Info.Name = "SQL injection (error-based)"
		ev.Info.Description = "The id parameter reaches a SQL query unescaped."
		ev.Info.Severity = severity.High
		ev.Info.Tags = []string{"sqli", "injection"}
		return ev
	}

	w := database.NewFindingWriter(repo, database.FindingWriterConfig{})
	require.NoError(t, w.Save(context.Background(), newEvent(), nil, scanUUID, database.DefaultProjectUUID))
	w.Close()

	stored, total, err := repo.ListFindings(context.Background(), database.QueryFilters{ProjectUUID: database.DefaultProjectUUID, ScanUUID: scanUUID})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)

	opts := agentViewOptions{}
	hydrateFindingEvidence(context.Background(), repo, stored)
	fromStore := compactFindingView(stored[0], nil, opts)
	fromEvent := findingViewFromEvent(newEvent(), scanUUID, database.DefaultProjectUUID, opts)
	require.NotNil(t, fromEvent)

	assert.NotContains(t, fromEvent, "id", "an unpersisted finding has no id; finding_hash is its identity")
	assert.NotEmpty(t, fromEvent["finding_hash"])
	for _, k := range []string{"id", "found_at", "status"} {
		delete(fromStore, k)
		delete(fromEvent, k)
	}
	assert.Equal(t, fromStore, fromEvent)
}

// The builder folds several inputs into ONE document: items are finding views,
// targets[] names each input, and the not-scanned list is always an array.
func TestScanDocumentBuilderMultiInput(t *testing.T) {
	withMachineDocumentState(t)
	globalJSON = true

	ev := &output.ResultEvent{ModuleID: "security-headers-missing", ModuleType: "passive", URL: "http://a.example/", Matched: "http://a.example/"}
	ev.Info.Name = "Missing security headers"
	ev.Info.Severity = severity.Low

	b := newScanDocBuilder("scan-url")
	b.AddDirect(&scanResult{Target: "http://a.example/", Method: "GET", ScanUUID: "uuid-a", Reachable: true,
		ModulesLoaded: 3, ModulesRun: 1, Findings: []*output.ResultEvent{ev}}, nil)
	b.AddDirect(&scanResult{Target: "http://b.example/", Method: "GET", ScanUUID: "uuid-b", Reachable: true,
		ModulesLoaded: 3, ModulesRun: 2}, nil)
	b.NoteNotScanned([]string{"http://c.example/"})

	out := captureStdout(t, func() { require.NoError(t, b.Emit()) })
	require.NoError(t, b.Emit(), "a second Emit is a no-op")
	doc := decodeOneScanDoc(t, out)
	assertNoNucleiKeys(t, out)

	assert.Equal(t, "scan-url", doc.Command)
	assert.Empty(t, doc.ScanUUID, "two rows: no single scan_uuid")
	assert.Equal(t, []string{"uuid-a", "uuid-b"}, doc.ScanUUIDs)
	assert.False(t, doc.Persisted)
	assert.Empty(t, doc.Query, "nothing persisted: no follow-up to point at")
	assert.EqualValues(t, 1, doc.Total)
	require.Len(t, doc.Items, 1)
	assert.Equal(t, "security-headers-missing", doc.Items[0]["module_id"])
	assert.NotContains(t, doc.Items[0], "id")
	assert.Equal(t, "uuid-a", doc.Items[0]["scan_uuid"])
	assert.Equal(t, 1, doc.CountsBySeverity["low"])
	assert.Equal(t, 0, doc.CountsBySeverity["critical"], "every severity is present, zeros included")
	require.Len(t, doc.Targets, 2)
	assert.Equal(t, scanDocModules{Selected: 3, Executed: 2}, doc.Modules)
	assert.Equal(t, []string{"http://c.example/"}, doc.TargetsNotScanned)
	assert.Equal(t, "interrupted", doc.Status, "an input never started: the run was cut short")
	assert.Equal(t, database.CompletenessPartial, doc.Completeness)

	withMachineDocumentState(t)
	globalJSON = true
	b = newScanDocBuilder("scan-url")
	b.AddDirect(&scanResult{Target: "http://a.example/", ScanUUID: "uuid-a", Reachable: true}, nil)
	out = captureStdout(t, func() { require.NoError(t, b.Emit()) })
	var raw map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &raw))
	assert.Equal(t, []any{}, raw["targets_not_scanned"])
	assert.Equal(t, []any{}, raw["items"])
	assert.Equal(t, "completed", raw["status"])
	assert.Equal(t, "uuid-a", raw["scan_uuid"])
}

// Items are capped at --limit, highest severity first; total and the counts
// stay exact.
func TestScanDocumentItemsCap(t *testing.T) {
	withMachineDocumentState(t)
	globalJSON = true
	prev := scanDocLimit
	t.Cleanup(func() { scanDocLimit = prev })
	scanDocLimit = 2

	var events []*output.ResultEvent
	for i, sev := range []severity.Severity{severity.Info, severity.Critical, severity.Low, severity.High} {
		ev := &output.ResultEvent{ModuleID: "m" + string(rune('a'+i)), URL: "http://a.example/"}
		ev.Info.Severity = sev
		events = append(events, ev)
	}
	b := newScanDocBuilder("scan-url")
	b.AddDirect(&scanResult{Target: "http://a.example/", ScanUUID: "u", Reachable: true, Findings: events}, nil)
	doc := decodeOneScanDoc(t, captureStdout(t, func() { require.NoError(t, b.Emit()) }))
	assert.EqualValues(t, 4, doc.Total)
	assert.True(t, doc.ItemsTruncated)
	assert.Equal(t, 2, doc.Limit)
	require.Len(t, doc.Items, 2)
	assert.Equal(t, "critical", doc.Items[0]["severity"])
	assert.Equal(t, "high", doc.Items[1]["severity"])
}

// A failure before anything ran leaves no document: the root's error envelope
// is the answer, and the latch is not taken.
func TestScanDocumentNothingRanLeavesErrorEnvelope(t *testing.T) {
	withMachineDocumentState(t)
	globalJSON = true
	b := newScanDocBuilder("scan")
	b.AddError(assertErr("database unavailable"), "")
	out := captureStdout(t, func() { require.NoError(t, b.Emit()) })
	assert.Empty(t, out)
	assert.False(t, jsonResultEmitted)
}

type assertErr string

func (e assertErr) Error() string { return string(e) }

// Every scan command and path prints ONE scan document with finding-view items
// and no nuclei-shaped keys: scan-url direct, scan-url -S (Runner path),
// scan-request, scan -j, and a multi-target scan-url.
func TestScanDocumentHasNoNucleiKeys(t *testing.T) {
	srv, _ := countingServer(t)
	home := a3Home(t, "127.0.0.1")
	dbPath := filepath.Join(home, "b6.sqlite")
	reqFile := filepath.Join(home, "req.txt")
	require.NoError(t, os.WriteFile(reqFile, []byte("GET /r HTTP/1.1\r\nHost: "+strings.TrimPrefix(srv.URL, "http://")+"\r\n\r\n"), 0o600))

	cases := map[string]struct {
		args      []string
		persisted bool
		targets   int
	}{
		"scan-url direct":   {[]string{"scan-url", srv.URL + "/", "-j", "--db", dbPath}, true, 1},
		"scan-url -S":       {[]string{"scan-url", srv.URL + "/", "-j", "-S"}, false, 1},
		"scan-url multi":    {[]string{"scan-url", "-t", srv.URL + "/a", "-t", srv.URL + "/b", "-j", "--db", dbPath}, true, 2},
		"scan-request":      {[]string{"scan-request", "-i", reqFile, "-t", srv.URL, "-j", "--db", dbPath}, true, 1},
		"scan -j":           {[]string{"scan", "-t", srv.URL + "/", "-j", "--db", dbPath, "--only", "ingestion,dynamic-assessment", "--skip-heuristics"}, true, 1},
		"scan -j --compact": {[]string{"scan", "-t", srv.URL + "/", "-j", "--db", dbPath, "--only", "ingestion,dynamic-assessment", "--skip-heuristics", "--compact", "-n", "1"}, true, 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			args := append(append([]string{}, tc.args...), "-m", "security-headers-missing")
			// A store of its own per case: a later run against records an
			// earlier case stored would have nothing new to assess.
			for i, a := range args {
				if a == dbPath {
					args[i] = filepath.Join(t.TempDir(), "b6.sqlite")
				}
			}
			code, stdout, stderr := runA3(t, home, args...)
			require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
			doc := decodeOneScanDoc(t, stdout)
			assertNoNucleiKeys(t, stdout)
			contracttest.Validate(t, args[0], []byte(stdout))
			assert.Equal(t, args[0], doc.Command)
			assert.Equal(t, "completed", doc.Status, stderr)
			assert.Equal(t, tc.persisted, doc.Persisted)
			require.Len(t, doc.Targets, tc.targets)
			for _, tgt := range doc.Targets {
				assert.True(t, tgt.Admitted)
			}
			assert.Positive(t, doc.Total, "the passive module fires on a bare response")
			require.NotEmpty(t, doc.Items)
			assert.NotEmpty(t, doc.Items[0]["module_id"])
			assert.NotEmpty(t, doc.Items[0]["finding_hash"])
			assert.Positive(t, doc.Modules.Selected)
			if tc.persisted {
				assert.NotNil(t, doc.Items[0]["id"], "stored rows are read back by scan_uuid")
				if tc.targets == 1 {
					require.NotEmpty(t, doc.ScanUUID)
					require.NotEmpty(t, doc.QueryArgv)
					assert.Contains(t, doc.Query, "finding --scan-uuid "+doc.ScanUUID)
					assert.Contains(t, doc.QueryArgv, "--db")
				}
			} else {
				assert.Empty(t, doc.Query, "a -S store is gone after the run")
				assert.NotContains(t, doc.Items[0], "id")
			}
			if strings.Contains(name, "--compact") {
				assert.Len(t, doc.Items, 1)
				assert.NotContains(t, doc.Items[0], "request")
			}
		})
	}
}

// A scan that fails still prints its document: status failed, errors[] with
// the code, exactly one document, exit 1.
func TestScanDocumentFailurePath(t *testing.T) {
	srv, hits := countingServer(t)
	home := a3Home(t, "nomatch.example")
	code, stdout, stderr := runA3(t, home, "scan", "-t", srv.URL+"/", "-j", "--db", filepath.Join(home, "fail.sqlite"))
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Zero(t, hits.Load())
	doc := decodeOneScanDoc(t, stdout)
	contracttest.Validate(t, "scan", []byte(stdout))
	assert.False(t, doc.OK, "exit 1: the document is kept and says it failed")
	require.NotNil(t, doc.Error)
	assert.Equal(t, 1, doc.Error.ExitCode)
	assert.Equal(t, "failed", doc.Status)
	assert.Equal(t, database.ReasonNoTargetsInScope, doc.StopReason)
	require.NotEmpty(t, doc.Errors)
	assert.Equal(t, apicontract.CodeNoTargetsInScope, doc.Errors[0].Code)
	require.Len(t, doc.Targets, 1)
	assert.False(t, doc.Targets[0].Admitted)
	assert.Equal(t, scanDocReasonOutOfScope, doc.Targets[0].Reason)
	assert.NotEmpty(t, doc.PhaseOutcomes)
}

// -j with a second stdout writer is a usage error before anything runs.
func TestScanDocumentStdoutConflicts(t *testing.T) {
	home := a3Home(t, "127.0.0.1")
	for name, args := range map[string][]string{
		"scan --events":       {"scan", "-t", "http://127.0.0.1:1/", "-j", "--events", "ndjson"},
		"scan --format jsonl": {"scan", "-t", "http://127.0.0.1:1/", "-j", "--format", "jsonl"},
		"scan-url --ci":       {"scan-url", "http://127.0.0.1:1/", "-j", "--ci-output-format"},
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			code, stdout, stderr := runA3(t, home, args...)
			require.Equal(t, ExitUsageError, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
			assert.Equal(t, string(apicontract.CodeUsageError), errorCode(t, stdout))
			assert.Less(t, time.Since(start), 30*time.Second)
		})
	}
}

// The documented scan document (docs/coding-agent.md) may only show keys the
// builder emits, and must show the ones a consumer branches on.
func TestCodingAgentDocScanDocumentExample(t *testing.T) {
	doc := readCodingAgentDoc(t)
	var documented map[string]any
	require.NoError(t, json.Unmarshal([]byte(fencedJSONUnder(t, doc, "### The scan document")), &documented))

	withMachineDocumentState(t)
	globalJSON = true
	b := newScanDocBuilder("scan-url")
	b.AddDirect(&scanResult{Target: "http://a.example/", ScanUUID: "u", Reachable: true, Persisted: true}, nil)
	b.scans[0].dbPath = "/tmp/x.sqlite"
	b.scans[0].stopReason = "x"
	raw, err := encodeAgentJSON(b.envelope())
	require.NoError(t, err)
	var produced map[string]any
	require.NoError(t, json.Unmarshal(raw, &produced))
	produced["project_uuid"], produced["db_path"], produced["query"], produced["query_argv"] = "", "", "", nil

	for key := range documented {
		assert.Contains(t, produced, key, "docs/coding-agent.md documents scan-document key %q, which the builder never emits", key)
	}
	for _, must := range []string{"schema_version", "kind", "ok", "status", "targets", "items", "total", "errors", "counts_by_severity", "modules"} {
		assert.Contains(t, documented, must)
	}
	assert.EqualValues(t, AgentSchemaVersion, documented["schema_version"])
}

// A -S document embeds each finding's evidence record and drops the record
// UUIDs the throwaway store takes with it, unless a sqlite artifact keeps
// them resolvable.
func TestStatelessScanDocumentEmbedsEvidence(t *testing.T) {
	srv, _ := countingServer(t)
	home := a3Home(t, "127.0.0.1")
	base := []string{"scan", "-S", "-t", srv.URL + "/", "-j", "--only", "ingestion,dynamic-assessment", "--skip-heuristics", "-m", "security-headers-missing"}

	code, stdout, stderr := runA3(t, home, base...)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	contracttest.Validate(t, "scan", []byte(stdout))
	doc := decodeOneScanDoc(t, stdout)
	require.NotEmpty(t, doc.Items)
	item := doc.Items[0]
	assert.NotContains(t, item, "http_record_uuids", "no store resolves them after a -S run")
	assert.NotContains(t, item, "origin_record_uuid")
	recs, ok := item["records"].([]any)
	require.True(t, ok, "the evidence record is embedded: %v", item)
	require.NotEmpty(t, recs)

	sqlitePath := filepath.Join(t.TempDir(), "run.sqlite")
	args := append(append([]string{}, base...), "--format", "sqlite", "-o", sqlitePath)
	code, stdout, stderr = runA3(t, home, args...)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc = decodeOneScanDoc(t, stdout)
	require.NotEmpty(t, doc.Items)
	assert.Contains(t, doc.Items[0], "http_record_uuids", "the sqlite artifact keeps them resolvable")
}
