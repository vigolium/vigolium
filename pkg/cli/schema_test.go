package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
	"github.com/vigolium/vigolium/pkg/database"
)

// schemaGoldenDir holds the published schemas (`make schema`). The golden test
// regenerates them in memory and fails on any difference, so a field rename in
// a registered view is a reviewed diff rather than a silent contract break.
const schemaGoldenDir = "../../docs/schema"

// schemaGoldenFiles renders every published schema file, keyed by its path
// under docs/schema.
func schemaGoldenFiles(t *testing.T) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	put := func(name string, v any) {
		raw, err := marshalSchemaJSON(v)
		require.NoError(t, err, name)
		files[name] = raw
	}
	index, err := schemaEntries(false)
	require.NoError(t, err)
	put("index.json", index)
	for _, name := range contract.CommandNames() {
		s, err := contract.CommandSchema(name)
		require.NoError(t, err, name)
		put("commands/"+strings.ReplaceAll(name, " ", "-")+".json", s)
	}
	events, err := contract.EventsSchema()
	require.NoError(t, err)
	put("events.json", events)
	put("error.json", contract.ErrorSchema())
	for _, name := range contract.DocumentNames() {
		s, err := contract.DocumentSchema(name)
		require.NoError(t, err, name)
		put("documents/"+name+".json", s)
	}
	return files
}

// TestSchemaGolden: docs/schema matches what this build publishes. Regenerate
// with `make schema` (VIGOLIUM_UPDATE_SCHEMA=1).
func TestSchemaGolden(t *testing.T) {
	want := schemaGoldenFiles(t)
	if os.Getenv("VIGOLIUM_UPDATE_SCHEMA") == "1" {
		require.NoError(t, os.RemoveAll(schemaGoldenDir))
		for name, raw := range want {
			path := filepath.Join(schemaGoldenDir, name)
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
			require.NoError(t, os.WriteFile(path, raw, 0o644))
		}
		return
	}
	have := map[string]bool{}
	err := filepath.WalkDir(schemaGoldenDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(schemaGoldenDir, path)
		have[filepath.ToSlash(rel)] = true
		return nil
	})
	require.NoError(t, err, "docs/schema is missing: run `make schema`")
	for name, raw := range want {
		got, err := os.ReadFile(filepath.Join(schemaGoldenDir, name))
		if err != nil {
			t.Errorf("docs/schema/%s is missing: run `make schema`", name)
			continue
		}
		if string(got) != string(raw) {
			t.Errorf("docs/schema/%s is stale: run `make schema` and review the diff", name)
		}
	}
	for name := range have {
		if _, ok := want[name]; !ok {
			t.Errorf("docs/schema/%s is no longer published: run `make schema`", name)
		}
	}
}

// TestSchemaRegisteredCommandsAreRealCommands: every registered name is a
// runnable cobra path whose declared kind matches the registered envelope kind.
func TestSchemaRegisteredCommandsAreRealCommands(t *testing.T) {
	root := preparedMachineTree(t)
	runnable := map[string]bool{}
	walkCommandTree(root, func(c *cobra.Command) {
		if c.Runnable() {
			runnable[commandPathWithoutRoot(c)] = true
		}
	})
	for _, name := range contract.CommandNames() {
		require.True(t, runnable[name], "registered schema %q is not a runnable command", name)
		c, _ := contract.LookupCommand(name)
		require.Equal(t, envelopeKindForDeclared(machineKinds[name]), c.Kind, name)
		_, err := contract.CommandSchema(name)
		require.NoError(t, err, name)
	}
}

// TestEnvelopeMirrorMatchesSpine: contract.Envelope is the public mirror of
// agentEnvelope; the key sets must be identical.
func TestEnvelopeMirrorMatchesSpine(t *testing.T) {
	mirror := contract.JSONFieldNames(contract.Envelope{})
	require.Equal(t, mirror, contract.JSONFieldNames(agentEnvelope{}), "contract.Envelope drifted from agentEnvelope")
	require.ElementsMatch(t, mirror, sortedMapKeys(envelopeFields), "envelopeFields drifted from the mirror")

	require.Equal(t, contract.JSONFieldNames(contract.ErrorEnvelope{}), contract.JSONFieldNames(agentErrorEnvelope{}),
		"contract.ErrorEnvelope drifted from agentErrorEnvelope")
	require.Equal(t, contract.JSONFieldNames(contract.ErrorBody{}), contract.JSONFieldNames(agentError{}),
		"contract.ErrorBody drifted from agentError")
	require.Equal(t, contract.JSONFieldNames(contract.GlobSkipped{}), contract.JSONFieldNames(globSkippedFile{}))
}

// TestEnvelopeCommonExtrasMatchEmitters: the common extras the mirror declares
// are what the shared emitters attach.
func TestEnvelopeCommonExtrasMatchEmitters(t *testing.T) {
	swapGlobal(t, &globalGlobDB, "scans/*.sqlite")
	env := newAgentEnvelope("traffic", "", []string{strings.Repeat("a", 200), strings.Repeat("b", 200)}, 2, 0, 2)
	env.WithProjectScope("p1")
	attachGlobSources(env)
	full, err := encodeAgentJSON(env)
	require.NoError(t, err)
	doc, err := applyOutputBudget(env, len(full)-100) // room for one row and output_budget
	require.NoError(t, err)
	require.NotNil(t, doc, "the budget must cut this page")

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc, &got))
	keysOf := func(raw json.RawMessage) []string {
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		return sortedMapKeys(m)
	}
	sorted := func(v []string) []string { v = slices.Clone(v); sort.Strings(v); return v }
	require.Equal(t, sorted(contract.JSONFieldNames(contract.GlobSources{})), keysOf(got["glob_sources"]))
	// dropped_keys appears only when a droppable key was emptied.
	budgetKeys := slices.DeleteFunc(contract.JSONFieldNames(contract.OutputBudget{}), func(k string) bool { return k == "dropped_keys" })
	require.Equal(t, sorted(budgetKeys), keysOf(got[outputBudgetKey]))

	// Every project source the CLI can report is in the schema's enum.
	s, err := contract.CommandSchema("traffic")
	require.NoError(t, err)
	src, _ := s.Properties.Get("project_source")
	require.ElementsMatch(t, []any{projectSourceFlag, projectSourceEnv, projectSourceActiveFile, projectSourceDefault}, src.Enum)
}

// TestFindingViewMirror: the finding view's mirror carries exactly the
// selectable --fields vocabulary, and a fully populated view validates.
func TestFindingViewMirror(t *testing.T) {
	require.ElementsMatch(t, findingViewFields, contract.JSONFieldNames(findingViewSchema{}),
		"findingViewSchema (schema_registry.go) must list exactly findingViewFields")
	require.ElementsMatch(t, trafficViewFields, contract.JSONFieldNames(recordViewSchema{}),
		"recordViewSchema (schema_registry.go) must list exactly trafficViewFields")

	verified := time.Now()
	f := fullFinding(verified)
	rec := fullRecord()
	views := []map[string]any{compactFindingView(f, []*database.HTTPRecord{rec}, agentViewOptions{fullBody: true})}
	// The evidence snippet replaces request/response when a needle matches;
	// render once without the needle so request/response are covered too.
	f2 := fullFinding(verified)
	f2.MatchedAt, f2.ExtractedResults = nil, nil
	views = append(views, compactFindingView(f2, nil, agentViewOptions{fullBody: true}))
	views[0]["records_error"] = "x"

	schemaKeys := contract.JSONFieldNames(findingViewSchema{})
	for _, v := range views {
		for k := range v {
			require.Contains(t, schemaKeys, k, "compactFindingView emits %q, which findingViewSchema lacks", k)
		}
	}

	env := newMachineEnvelope(findingCmd, kindRead, "findings", views, 2, 0, 2)
	env.WithProjectScope("p1")
	raw, err := jsonMarshalNoEscape(env)
	require.NoError(t, err)
	contracttest.Validate(t, "finding", raw)

	recViews := recordViews([]*database.HTTPRecord{rec}, agentViewOptions{})
	for k := range recViews[0] {
		require.Contains(t, contract.JSONFieldNames(recordViewSchema{}), k)
	}
	env = newMachineEnvelope(trafficCmd, kindRead, "records", recViews, 1, 0, 1)
	raw, err = jsonMarshalNoEscape(env)
	require.NoError(t, err)
	contracttest.Validate(t, "traffic", raw)
}

// TestBodyViewMirror: every key bodyView can emit is in bodyViewSchema.
func TestBodyViewMirror(t *testing.T) {
	keys := contract.JSONFieldNames(bodyViewSchema{})
	cases := [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + strings.Repeat("a", agentRespBodyPreviewMax+10)),
		[]byte("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\x89PNG\x00\x01"),
	}
	for _, raw := range cases {
		v := bodyView(raw, "", agentRespBodyPreviewMax, agentViewOptions{})
		for k := range v {
			require.Contains(t, keys, k, "bodyView emits %q, which bodyViewSchema lacks", k)
		}
	}
}

// TestDisplayFindingsJSONMatchesSchema runs the real `finding -j` writer.
func TestDisplayFindingsJSONMatchesSchema(t *testing.T) {
	db := newInventoryTestDB(t)
	withJSON(t)
	out := captureStdout(t, func() {
		require.NoError(t, displayFindingsJSON(context.Background(), findingCmd, db,
			[]*database.Finding{fullFinding(time.Now())}, 1, "p1"))
	})
	contracttest.Validate(t, "finding", []byte(out))
}

// TestSchemaCommandsCLI drives `vigolium schema` end to end in a child.
func TestSchemaCommandsCLI(t *testing.T) {
	e := newB5Env(t)

	code, stdout, stderr := e.run(t, nil, "schema", "command", "scan", "status")
	require.Equal(t, 0, code, stderr)
	var bare map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &bare), stdout)
	require.Equal(t, "https://json-schema.org/draft/2020-12/schema", bare["$schema"])
	require.Equal(t, "vigolium scan status -j", bare["title"])

	code, stdout, stderr = e.run(t, nil, "schema", "event", "phase.progress", "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	items := requireEnvelope(t, doc, "schema event", "read")
	require.Len(t, items, 1)
	item := items[0].(map[string]any)
	require.Equal(t, "phase.progress", item["name"])
	require.NotNil(t, item["schema"])

	code, stdout, stderr = e.run(t, nil, "schema", "-j")
	require.Equal(t, 0, code, stderr)
	items = requireEnvelope(t, oneDoc(t, stdout, stderr), "schema", "read")
	require.Len(t, items, len(contract.CommandNames())+len(contract.EventTypes())+1+len(contract.DocumentNames()))

	code, stdout, _ = e.run(t, nil, "schema", "error")
	require.Equal(t, 0, code)
	require.Contains(t, stdout, string(apicontract.CodeScanAbandoned), "error.code enumerates the vocabulary")

	code, _, _ = e.run(t, nil, "schema", "command", "no-such-command")
	require.Equal(t, apicontract.ExitUsageError, code)
	code, _, _ = e.run(t, nil, "schema", "event", "no.such")
	require.Equal(t, apicontract.ExitUsageError, code)

	// A schema subcommand never creates the store or the config tree.
	_, err := os.Stat(e.db)
	require.True(t, os.IsNotExist(err), "schema must not open --db")
}

func fullFinding(verified time.Time) *database.Finding {
	return &database.Finding{
		ID: 7, FindingHash: "abc123", Severity: "high", Confidence: "firm",
		ModuleID: "xss-reflected", ModuleName: "Reflected XSS", ModuleType: "active", ModuleShort: "short",
		FindingSource: "native", RecordKind: "finding", EvidenceGrade: "confirmed",
		Description: "d", URL: "https://shop.test/?q=1", Hostname: "shop.test",
		MatchedAt: []string{"https://shop.test/?q=1"}, ExtractedResults: []string{"<script>"},
		AdditionalEvidence: []string{"e"}, Tags: []string{"xss"}, CWEID: "CWE-79", CVSSScore: 6.1,
		Remediation: "encode", Status: "confirmed", StatusNote: "n", StatusActor: "me",
		ScanUUID: "s1", AgenticScanUUID: "a1", RepoName: "r", SourceFile: "f.go",
		FoundAt: time.Now(), HTTPRecordUUIDs: []string{"r1", "r2"}, OriginRecordUUID: "r1",
		InsertionPoint: &database.FindingInsertionPoint{}, Payload: "<script>",
		Verification: &database.FindingVerification{}, VerifiedAt: &verified,
		Request:  "GET /?q=1 HTTP/1.1\r\nHost: shop.test\r\n\r\n",
		Response: "HTTP/1.1 200 OK\r\n\r\n<html><script></html>",
	}
}

func fullRecord() *database.HTTPRecord {
	return &database.HTTPRecord{
		UUID: "r1", Method: "GET", URL: "https://shop.test/?q=1", Scheme: "https", Hostname: "shop.test", Port: 443,
		StatusCode: 200, ResponseContentType: "text/html", ResponseContentLength: 10, ResponseTimeMs: 5,
		ResponseWords: 2, Source: "scanner", ScanUUID: "s1", ResponseTitle: "t", IP: "127.0.0.1",
		RiskScore: 3, SurfaceScore: 4, IsAuthenticated: true, Technology: []string{"nginx"}, Remarks: []string{"x"},
		BodyCompaction: &database.BodyCompaction{Version: 1},
		RawRequest:     []byte("GET /?q=1 HTTP/1.1\r\nHost: shop.test\r\n\r\n"),
		RawResponse:    []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"),
		HasResponse:    true,
	}
}

// validateRegisteredDoc validates one -j document against its contract when
// the command has a registered schema (an error envelope against the error
// schema). Shared by the envelope helpers of the existing -j tests, so every
// document they capture is checked without each test naming its command.
// --json-legacy-keys adds the pre-envelope aliases, which are outside the
// contract, so such a document is not checked.
func validateRegisteredDoc(t *testing.T, raw []byte) {
	t.Helper()
	if globalJSONLegacyKeys {
		return
	}
	var head struct {
		Command string          `json:"command"`
		OK      *bool           `json:"ok"`
		Items   json.RawMessage `json:"items"`
	}
	if json.Unmarshal(raw, &head) != nil || head.OK == nil {
		return
	}
	// ok:false with items is a result document whose command then failed: it
	// still matches the command's schema. Without items it is the error envelope.
	if !*head.OK && head.Items == nil {
		contracttest.ValidateError(t, raw)
		return
	}
	if _, ok := contract.LookupCommand(head.Command); ok {
		contracttest.Validate(t, head.Command, raw)
	}
}

// validateRegisteredMap is validateRegisteredDoc for an already-decoded doc.
func validateRegisteredMap(t *testing.T, doc map[string]any) {
	t.Helper()
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	validateRegisteredDoc(t, raw)
}

// Why a command with a -j document has no registered schema yet.
const (
	pendingTypedItems   = "envelope whose items/extras are not mirrored by a typed view yet"
	pendingAgentRun     = "agent run document (B7, agent_run_document.go): not mirrored yet"
	pendingStream       = "stream command: its own --format output owns stdout; the -j receipt is not mirrored yet"
	pendingSelfDescribe = "items embed JSON Schema documents; describing the schema of a schema adds nothing"
)

// schemaPending lists every non-interactive command that has no registered
// schema, with the reason. TestSchemaCoverageRatchet keeps it exact: a new
// command must be registered (schema_registry.go) or listed here, and the
// list may only shrink.
var schemaPending = map[string]string{
	"agent autopilot": pendingAgentRun, "agent swarm": pendingAgentRun, "agent audit": pendingAgentRun,
	"audit": pendingAgentRun,
	"agent": pendingTypedItems, "agent query": pendingTypedItems, "agent session": pendingTypedItems,
	"agent triage": pendingTypedItems,
	"auth check":   pendingTypedItems, "auth lint": pendingTypedItems, "auth list": pendingTypedItems,
	"auth load": pendingTypedItems, "auth totp": pendingTypedItems,
	"config clean": pendingTypedItems, "config set": pendingTypedItems,
	"config validate":  pendingTypedItems,
	"storage download": pendingStream,
	"doctor":           pendingTypedItems,
	"extensions":       pendingTypedItems, "extensions docs": pendingTypedItems, "extensions ls": pendingTypedItems,
	"finding verify": pendingTypedItems,
	"init":           pendingTypedItems,
	"kit harvest":    pendingTypedItems, "kit js-beautify": pendingTypedItems, "kit jwt-crack": pendingTypedItems,
	"kit oast new": pendingTypedItems, "kit oast poll": pendingTypedItems, "kit param-mine": pendingTypedItems,
	"kit payload": pendingTypedItems, "kit secret-scan": pendingTypedItems, "kit tmp-clean": pendingTypedItems,
	"kit wordlist": pendingTypedItems,
	"module":       pendingTypedItems, "module ls": pendingTypedItems,
	"project config": pendingTypedItems,
	"scope":          pendingTypedItems, "scope set": pendingTypedItems, "scope view": pendingTypedItems,
	"server ca install": pendingTypedItems, "server ca path": pendingTypedItems,
	"server ca print": pendingTypedItems, "server ca uninstall": pendingTypedItems,
	"skills": pendingTypedItems, "skills get": pendingTypedItems, "skills install": pendingTypedItems,
	"skills list": pendingTypedItems,
	"storage ls":  pendingTypedItems, "storage presign": pendingTypedItems, "storage results": pendingTypedItems,
	"storage rm": pendingTypedItems, "storage upload": pendingTypedItems,
	"schema": pendingSelfDescribe, "schema list": pendingSelfDescribe, "schema command": pendingSelfDescribe,
	"schema event": pendingSelfDescribe, "schema error": pendingSelfDescribe, "schema plan": pendingSelfDescribe,
	"schema all": pendingSelfDescribe,
	"strategy":   pendingTypedItems, "update": pendingTypedItems, "version": pendingTypedItems,
}

// schemaPendingCeiling pins the ratchet's size: lower it when a command gets
// a schema; never raise it.
const schemaPendingCeiling = 62

// TestSchemaCoverageRatchet: every runnable non-interactive command either has
// a registered schema or a reason in schemaPending, never both.
func TestSchemaCoverageRatchet(t *testing.T) {
	root := preparedMachineTree(t)
	walkCommandTree(root, func(c *cobra.Command) {
		if !c.Runnable() {
			return
		}
		path := commandPathWithoutRoot(c)
		if machineKindOf(c) == kindInteractive || isInteractiveAllowed(path) {
			return
		}
		_, registered := contract.LookupCommand(path)
		_, pending := schemaPending[path]
		switch {
		case registered && pending:
			t.Errorf("%q has a schema; delete it from schemaPending and lower schemaPendingCeiling", path)
		case !registered && !pending:
			t.Errorf("%q emits a -j document but has no schema: register it in schema_registry.go "+
				"(or, with a reason, add it to schemaPending)", path)
		}
	})
	for path := range schemaPending {
		if _, ok := machineKinds[path]; !ok {
			t.Errorf("schemaPending lists %q, which is not a command", path)
		}
	}
	if n := len(schemaPending); n > schemaPendingCeiling {
		t.Errorf("schemaPending has %d entries, over the ceiling of %d: register the new command's schema instead", n, schemaPendingCeiling)
	} else if n < schemaPendingCeiling {
		t.Errorf("schemaPending shrank to %d: lower schemaPendingCeiling to %d", n, n)
	}
}

// The stream a --watch read writes is declared, and `run fingerprint`'s host
// rows are a declared variant of `run`.
func TestSchemaDeclaresStreamsAndRunFingerprint(t *testing.T) {
	for _, name := range []string{"db list", "db stats"} {
		s, err := contract.CommandSchema(name)
		require.NoError(t, err)
		raw, err := json.Marshal(s)
		require.NoError(t, err)
		require.Contains(t, string(raw), "NDJSON", "%s --watch streams documents", name)
	}
	s, err := contract.CommandSchema("run")
	require.NoError(t, err)
	raw, err := json.Marshal(s)
	require.NoError(t, err)
	require.Contains(t, string(raw), "run fingerprint")
	require.Contains(t, string(raw), "not_found", "the host view (with its not-found baseline) is an item shape of run")
}
