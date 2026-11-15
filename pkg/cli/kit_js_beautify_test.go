package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
)

// kitBeautifyGoldenInput is the raw script the fake backend "analyzes". Its
// string literals are what the Go linkfinder pass sees: one path the fake's
// pathLiteral also reports (→ source both) and one only linkfinder finds.
const kitBeautifyGoldenInput = `const cfg={profile:"/api/v2/profile"};` +
	`fetch("/admin/settings/export.json");`

// kitFakeBeautifyService stands in for *jstangle.Service.
type kitFakeBeautifyService struct {
	result *jstangle.ScanResult
	opts   jstangle.ScanOptions
}

func (f *kitFakeBeautifyService) ScanWithOptions(_ context.Context, _ []byte, opts jstangle.ScanOptions) (*jstangle.ScanResult, error) {
	f.opts = opts
	return f.result, nil
}

func kitProv(extractor, confidence, module string, line, column int) jstangle.Provenance {
	return jstangle.Provenance{
		Extractor: extractor, Confidence: confidence, ModulePath: module,
		Start: &jstangle.SourceLocation{Line: line, Column: column},
	}
}

func kitStatic(v string) jstangle.ValueTemplate {
	return jstangle.ValueTemplate{Rendered: v, Static: true}
}

func kitVariable(v string) jstangle.ValueTemplate {
	return jstangle.ValueTemplate{Rendered: v, Variables: []jstangle.TemplateVariable{{Name: "id", Placeholder: v}}}
}

// kitAllKindsResult carries exactly one fact of every kind jstangle emits.
func kitAllKindsResult() *jstangle.ScanResult {
	parentRoute := jstangle.ClientRouteFact{
		Kind: "clientRoute", ID: "route-2", Path: kitStatic("users/:id"), RouteType: "angular",
		Guards: []string{"AuthGuard"}, LazyAsset: &jstangle.ValueTemplate{Rendered: "./users.chunk.js"},
		FullPath: &jstangle.ValueTemplate{Rendered: "/admin/users/:id"}, ParentID: "route-1",
		Provenance: kitProv("angular-router", "high", "./src/app.routes.ts", 12, 4),
	}
	completion := &jstangle.ScanCompletion{Status: "partial", ReasonCode: "request_cap"}
	completion.Counts.Truncated = map[string]int{"httpRequest": 7}
	return &jstangle.ScanResult{
		Completion: completion,
		RequestFacts: []jstangle.HTTPRequestFact{{
			Kind: "httpRequest", ID: "req-1",
			URL: kitStatic("/api/v2/orders"), Method: kitStatic("POST"),
			Query:   []jstangle.FieldTemplate{{Name: kitStatic("page"), Value: kitVariable("${page}")}},
			Headers: []jstangle.HeaderTemplate{{Name: kitStatic("Authorization"), Value: kitVariable("Bearer ${token}"), Sensitive: true}},
			Body:    &jstangle.BodyTemplate{Kind: "json", Value: kitStatic(`{"sku":"x"}`), ContentType: "application/json"},
			Client:  "fetch",
			Auth: &jstangle.AuthContext{
				Kind: "bearer", Header: "Authorization", Scheme: "Bearer",
				Source: "localStorage:jwt", SourceKind: "localStorage",
			},
			Provenance: kitProv("fetch-call", "high", "./src/api.js", 3, 17),
		}},
		ClientRoutes: []jstangle.ClientRouteFact{parentRoute},
		AssetFacts: []jstangle.AssetReferenceFact{{
			Kind: "assetReference", ID: "asset-1", AssetType: "chunk", URL: kitStatic("/static/js/42.abc.chunk.js"),
			Loader: "webpack-chunk", ParentSourceURL: "https://acme.test/main.js",
			Provenance: kitProv("webpack-runtime", "medium", "", 1, 900),
		}},
		GraphQLOperations: []jstangle.GraphQLOperationFact{{
			Kind: "graphqlOperation", ID: "gql-1", Endpoint: &jstangle.ValueTemplate{Rendered: "/graphql"},
			OperationType: "query", OperationName: "Me", Document: "query Me { me { id } }",
			Variables: []jstangle.GraphQLVariableTemplate{{Name: "id", Type: "ID!", Required: true}},
			Transport: "http-post", Provenance: kitProv("apollo-gql", "high", "./src/me.graphql.js", 2, 1),
		}},
		WebSockets: []jstangle.WebSocketFact{{
			Kind: "websocket", ID: "ws-1", URL: kitStatic("wss://acme.test/live"), Subprotocols: []string{"v1.live"},
			InboundEventNames: []string{"tick"}, Library: "native",
			Provenance: kitProv("websocket-ctor", "high", "", 9, 2),
		}},
		EventSources: []jstangle.EventSourceFact{{
			Kind: "eventSource", ID: "sse-1", URL: kitStatic("/events"), WithCredentials: true,
			EventNames: []string{"update"}, Library: "native",
			Provenance: kitProv("eventsource-ctor", "medium", "", 10, 2),
		}},
		DomFlowFacts: []jstangle.DomFlowFact{{
			Kind: "domFlow", ID: "flow-1", FlowType: "dom-xss", Source: "location.hash", Sink: "innerHTML",
			Snippet: "el.innerHTML = location.hash", Line: 20, Confidence: "high",
			Provenance: jstangle.Provenance{Extractor: "taint"},
		}},
		BrowserFlows: []jstangle.BrowserSecurityFlowFact{{
			Kind: "browserSecurityFlow", ID: "bflow-1", FlowType: "open-redirect", Source: "URLSearchParams.get",
			Sink: "location.assign", Confidence: "medium", Evidence: "location.assign(q.get('next'))",
			Provenance: kitProv("browser-flow", "", "", 22, 5),
		}},
		PathLiterals: []jstangle.PathLiteralFact{{
			Kind: "pathLiteral", ID: "path-1", Value: kitStatic("/api/v2/profile"), Reason: "object-value", Key: "profile",
			Provenance: kitProv("path-literal", "low", "", 1, 20),
		}, {
			Kind: "pathLiteral", ID: "path-2", Value: kitStatic("/internal/debug"), Reason: "const-init",
			Provenance: kitProv("path-literal", "low", "", 1, 60),
		}},
	}
}

// resetKitBeautifyFlags restores every package-level flag the command reads,
// so tests do not leak state into each other.
func resetKitBeautifyFlags(t *testing.T) {
	t.Helper()
	prevJSON := globalJSON
	prevService := kitBeautifyService
	reset := func() {
		kitBeautifyExtract, kitBeautifyUnpackModules = false, false
		kitBeautifyOutput, kitBeautifyModulesDir, kitBeautifyProfile = "", "", ""
		kitBeautifyMaxASTNodes, kitBeautifyMaxInputMB, kitBeautifyDeadline = 0, 0, 0
		kitBeautifyKindsFlag = nil
		kitBeautifyScanSecrets, kitBeautifyShowSecrets = false, false
	}
	reset()
	t.Cleanup(func() {
		reset()
		globalJSON = prevJSON
		kitBeautifyService = prevService
	})
}

func runKitBeautifyWithFake(t *testing.T, input string, res *jstangle.ScanResult) (stdout, stderr string, fake *kitFakeBeautifyService) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.js")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	fake = &kitFakeBeautifyService{result: res}
	kitBeautifyService = func() (kitBeautifyScanner, error) { return fake, nil }
	var runErr error
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, func() { runErr = runKitJSBeautify(kitJSBeautifyCmd, []string{path}) })
	})
	if runErr != nil {
		t.Fatalf("runKitJSBeautify: %v", runErr)
	}
	// The temp path differs per run; the golden pins it to a stable label.
	stdout = strings.ReplaceAll(stdout, path, "bundle.js")
	return stdout, stderr, fake
}

// kitBeautifyItem returns the result object of a `kit js-beautify -j` run:
// items[0] of the one envelope on stdout.
func kitBeautifyItem(t *testing.T, stdout string) []byte {
	t.Helper()
	var env struct {
		Command string            `json:"command"`
		Kind    string            `json:"kind"`
		Items   []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("output is not one JSON document: %v\n%s", err, stdout)
	}
	if env.Command != "kit js-beautify" || env.Kind != "read" || len(env.Items) != 1 {
		t.Fatalf("want a kit js-beautify read envelope with one item, got command=%q kind=%q items=%d",
			env.Command, env.Kind, len(env.Items))
	}
	return env.Items[0]
}

// One fact of every kind must come out of -j --extract with its provenance
// flattened onto the item. The golden is the item-schema contract (plan D6);
// regenerate with UPDATE_GOLDEN=1 only for a deliberate schema change.
func TestKitBeautifyExtractAllKindsGolden(t *testing.T) {
	resetKitBeautifyFlags(t)
	globalJSON = true
	kitBeautifyExtract = true

	stdout, _, fake := runKitBeautifyWithFake(t, kitBeautifyGoldenInput, kitAllKindsResult())
	if fake.opts.Profile != jstangle.ProfileFull {
		t.Errorf("--extract should request the full profile, got %q", fake.opts.Profile)
	}

	// The golden pins the result object itself — items[0] of the envelope —
	// so the envelope's per-run fields (generated_at) stay out of it.
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, kitBeautifyItem(t, stdout), "", "  "); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, stdout)
	}
	pretty.WriteByte('\n')
	golden := filepath.Join("testdata", "kit_js_beautify_extract.golden.json")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, pretty.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("reading golden (run with UPDATE_GOLDEN=1 to create): %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(pretty.Bytes())) {
		t.Errorf("-j --extract output drifted from %s (UPDATE_GOLDEN=1 to accept)\n--- got ---\n%s", golden, pretty.String())
	}
}

// --kinds narrows the document and the counts map together, implies
// --extract, and rejects a kind it does not know.
func TestKitBeautifyKindsFilter(t *testing.T) {
	resetKitBeautifyFlags(t)
	globalJSON = true
	kitBeautifyKindsFlag = []string{"routes", "dom-flows"}

	stdout, _, fake := runKitBeautifyWithFake(t, kitBeautifyGoldenInput, kitAllKindsResult())
	if fake.opts.Profile != jstangle.ProfileFull {
		t.Errorf("--kinds should imply --extract, got profile %q", fake.opts.Profile)
	}
	var doc map[string]any
	if err := json.Unmarshal(kitBeautifyItem(t, stdout), &doc); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"endpoints", "assets", "graphql", "realtime", "paths"} {
		if _, ok := doc[absent]; ok {
			t.Errorf("%s should be filtered out", absent)
		}
	}
	counts, _ := doc["counts"].(map[string]any)
	if len(counts) != 2 || counts["routes"] != float64(1) || counts["dom_flows"] != float64(2) {
		t.Errorf("counts should cover only the selected kinds: %v", counts)
	}

	if _, err := kitBeautifyKindSet([]string{"bogus"}); err == nil {
		t.Error("an unknown --kinds value must be a usage error")
	}
}

// Human mode keeps stdout the source and puts the per-kind summary on stderr.
func TestKitBeautifyHumanSummaryOnStderr(t *testing.T) {
	resetKitBeautifyFlags(t)
	globalJSON = false
	kitBeautifyExtract = true

	stdout, stderr, _ := runKitBeautifyWithFake(t, kitBeautifyGoldenInput, kitAllKindsResult())
	if strings.TrimSpace(stdout) != kitBeautifyGoldenInput {
		t.Errorf("stdout must stay the source, got %q", stdout)
	}
	for _, want := range []string{
		"1 endpoints, 1 routes, 1 assets, 1 graphql, 2 realtime, 2 dom_flows, 3 paths",
		"httpRequest capped: 7",
		"POST   /api/v2/orders  auth=bearer:localStorage:jwt",
		"/admin/users/:id  <angular>",
		"loader=webpack-chunk",
		"/admin/settings/export.json  {linkfinder}",
		"/api/v2/profile  {both}",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr summary missing %q:\n%s", want, stderr)
		}
	}
}

// A literal both extractors saw is one item tagged "both", keyed through the
// same template normalization linkfinder applies; each side's extras survive.
func TestKitBeautifyPathsMergeLinkfinder(t *testing.T) {
	res := &jstangle.ScanResult{PathLiterals: []jstangle.PathLiteralFact{{
		Kind: "pathLiteral", ID: "p1", Value: kitVariable("/api/users/${id}/"), Reason: "return",
		Provenance: kitProv("path-literal", "low", "./src/users.js", 4, 9),
	}, {
		Kind: "pathLiteral", ID: "p2", Value: kitStatic("/only/jstangle"), Reason: "const-init",
		Provenance: kitProv("path-literal", "low", "", 5, 1),
	}}}
	content := []byte("const a = `/api/users/${id}`; const b = '/reports/monthly.csv';")

	paths := kitBeautifyPaths(res, content)
	byPath := map[string]kitPath{}
	for _, p := range paths {
		byPath[p.Path] = p
	}
	merged, ok := byPath["/api/users/${id}/"]
	if !ok || merged.Source != kitPathSourceBoth {
		t.Fatalf("templated literal should merge with linkfinder's normalized hit as both: %+v", paths)
	}
	if merged.ModulePath != "./src/users.js" || merged.Line != 4 || merged.Extractor != "path-literal" {
		t.Errorf("merged item should keep the jstangle provenance: %+v", merged)
	}
	if p := byPath["/only/jstangle"]; p.Source != kitPathSourceJSTangle {
		t.Errorf("jstangle-only literal should stay source jstangle: %+v", p)
	}
	lf, ok := byPath["/reports/monthly.csv"]
	if !ok || lf.Source != kitPathSourceLinkfinder || lf.Extractor != "linkfinder" || lf.Confidence != "low" {
		t.Errorf("linkfinder-only path should be reported at low confidence: %+v", paths)
	}
	if len(paths) != 3 {
		t.Errorf("expected 3 merged paths (no duplicates), got %d: %+v", len(paths), paths)
	}
}

// --secrets scans the beautified modules, attributes a hit to its module and
// line, dedupes a repeated value, and redacts unless --show-secrets.
func TestKitBeautifySecrets(t *testing.T) {
	token := "ghp_R8vKq2" + "LmZ7xTn4Wp" + "C9sYb3HjD6" + "fGa1QeUo5N"
	beautified := "// ===== ./src/a.js (entry) =====\nconst x = 1;\nconst gh = \"" + token + "\";\n" +
		"// ===== ./src/b.js =====\nconst again = \"" + token + "\";\n"
	res := &jstangle.ScanResult{Beautified: &jstangle.BeautifiedCode{
		Format: "webpack", ModuleCount: 2, ModulePaths: []string{"./src/a.js", "./src/b.js"},
		Changed: true, Content: beautified,
	}}

	// Revealed first: the catalog may capture only part of the token (the
	// GitHub rule drops the ghp_ prefix), and the redacted form is that capture
	// masked.
	revealed := ""
	for _, reveal := range []bool{true, false} {
		resetKitBeautifyFlags(t)
		globalJSON = true
		kitBeautifyScanSecrets = true
		kitBeautifyShowSecrets = reveal

		stdout, _, _ := runKitBeautifyWithFake(t, "var gh=\""+token+"\";", res)
		var doc kitBeautifyResult
		if err := json.Unmarshal(kitBeautifyItem(t, stdout), &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Secrets) != 1 || doc.Counts[kitKindSecrets] != 1 {
			t.Fatalf("reveal=%v: want one deduped secret, got %+v (counts %v)", reveal, doc.Secrets, doc.Counts)
		}
		hit := doc.Secrets[0]
		if hit.File != "./src/a.js" || hit.Line != 2 {
			t.Errorf("secret should point into its module: %s:%d", hit.File, hit.Line)
		}
		if reveal {
			if len(hit.Secret) < 20 || !strings.Contains(token, hit.Secret) {
				t.Fatalf("--show-secrets should print the value, got %q", hit.Secret)
			}
			revealed = hit.Secret
		} else if hit.Secret == revealed || hit.Secret != redactSecret(revealed) {
			t.Errorf("secrets must be redacted by default, got %q", hit.Secret)
		}
		if doc.Endpoints != nil || doc.Paths != nil {
			t.Errorf("--secrets alone must not report facts")
		}
	}

	resetKitBeautifyFlags(t)
	kitBeautifyShowSecrets = true
	if err := runKitJSBeautify(kitJSBeautifyCmd, []string{"-"}); err == nil {
		t.Error("--show-secrets without --secrets should be a usage error")
	}
}

// With -o the content goes to the file once; the -j document says where and
// leaves the content out.
func TestKitBeautifyOutputOmitsContent(t *testing.T) {
	resetKitBeautifyFlags(t)
	globalJSON = true
	kitBeautifyOutput = filepath.Join(t.TempDir(), "out.js")

	stdout, _, _ := runKitBeautifyWithFake(t, kitBeautifyGoldenInput, kitAllKindsResult())
	var doc map[string]any
	if err := json.Unmarshal(kitBeautifyItem(t, stdout), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["content"] != "" || doc["content_omitted"] != true {
		t.Fatalf("content must be omitted with -o: content=%v content_omitted=%v", doc["content"], doc["content_omitted"])
	}
	if doc["output_path"] != kitBeautifyOutput {
		t.Fatalf("output_path = %v", doc["output_path"])
	}
	written, err := os.ReadFile(kitBeautifyOutput)
	if err != nil || len(written) == 0 {
		t.Fatalf("the file holds the content: %v (%d bytes)", err, len(written))
	}
}
