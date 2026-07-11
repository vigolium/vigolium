package discovery

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
)

func TestJSAssetGraphResolvesAndTerminatesCycles(t *testing.T) {
	graph := NewJSAssetGraph(JSAssetGraphConfig{MaxDepth: 3, MaxAssetsPerParent: 4, MaxAssetsPerHost: 10, MaxAssetsTotal: 20})
	graph.AddRoot("https://example.com/assets/app.js", AssetScript)
	chunk, added, reason := graph.Add("https://example.com/assets/app.js", "./chunks/lazy.js", AssetDynamicImport)
	if !added || reason != "" || chunk.String() != "https://example.com/assets/chunks/lazy.js" {
		t.Fatalf("unexpected resolved chunk: %v added=%v reason=%s", chunk, added, reason)
	}
	worker, added, _ := graph.Add(chunk.String(), "../worker.js", AssetWorker)
	if !added || worker.String() != "https://example.com/assets/worker.js" {
		t.Fatalf("unexpected worker edge: %v", worker)
	}
	if _, added, reason := graph.Add(worker.String(), "./chunks/lazy.js", AssetDynamicImport); added || reason != "duplicate-url" {
		t.Fatalf("cycle was not terminated: added=%v reason=%s", added, reason)
	}
	if nodes := graph.Nodes(); len(nodes) != 3 {
		t.Fatalf("graph nodes = %d, want 3: %+v", len(nodes), nodes)
	}
}

func TestJSAssetGraphEnforcesParentAndDepthCaps(t *testing.T) {
	graph := NewJSAssetGraph(JSAssetGraphConfig{MaxDepth: 1, MaxAssetsPerParent: 1, MaxAssetsPerHost: 10, MaxAssetsTotal: 10})
	graph.AddRoot("https://example.com/app.js", AssetScript)
	first, added, _ := graph.Add("https://example.com/app.js", "/one.js", AssetScript)
	if !added {
		t.Fatal("first child rejected")
	}
	if _, added, reason := graph.Add("https://example.com/app.js", "/two.js", AssetScript); added || reason != "parent-limit" {
		t.Fatalf("parent cap: added=%v reason=%s", added, reason)
	}
	if _, added, reason := graph.Add(first.String(), "/deep.js", AssetScript); added || reason != "depth-limit" {
		t.Fatalf("depth cap: added=%v reason=%s", added, reason)
	}
}

func TestParseSourceMapSourcesContentAndSanitizesPaths(t *testing.T) {
	content := []byte(`{
      "version":3,"sourceRoot":"webpack:///../../",
      "sources":["../src/api.ts","src/no-content.ts"],
      "sourcesContent":["fetch('/api/from-source-map')",null],"mappings":""
    }`)
	sources, err := ParseSourceMap(content, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("ParseSourceMap: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("sources = %+v", sources)
	}
	if strings.Contains(sources[0].Path, "..") || strings.HasPrefix(sources[0].Path, "/") {
		t.Fatalf("unsafe recovered path: %q", sources[0].Path)
	}
	if sources[0].Language != "ts" || string(sources[0].Content) != "fetch('/api/from-source-map')" {
		t.Fatalf("unexpected recovered source: %+v", sources[0])
	}
}

func TestParseIndexedAndInlineSourceMaps(t *testing.T) {
	child := `{"version":3,"sources":["src/a.js"],"sourcesContent":["fetch('/a')"],"mappings":""}`
	indexed := []byte(fmt.Sprintf(`{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":%s}]}`, child))
	sources, err := ParseSourceMap(indexed, "https://example.com/app.js")
	if err != nil || len(sources) != 1 {
		t.Fatalf("indexed parse: sources=%+v err=%v", sources, err)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(child))
	ref, inline, ok := ExtractSourceMapReference([]byte("const x=1;\n//# sourceMappingURL=data:application/json;base64," + encoded))
	if !ok || ref != "inline:source-map" || string(inline) != child {
		t.Fatalf("inline reference: ref=%q ok=%v content=%q", ref, ok, inline)
	}
}

func TestParseSourceMapRejectsMalformedAndOversizedContent(t *testing.T) {
	if _, err := ParseSourceMap([]byte(`{"version":2}`), "https://example.com/app.js"); err == nil {
		t.Fatal("unsupported map version accepted")
	}
	if _, err := ParseSourceMap(make([]byte, maxSourceMapBytes+1), "https://example.com/app.js"); err == nil {
		t.Fatal("oversized map accepted")
	}
}

func TestAnnotateSourceMappedResultCoversEveryTypedFactFamily(t *testing.T) {
	provenance := jstangle.Provenance{Extractor: "fixture", Confidence: "high"}
	result := &jstangle.ScanResult{
		RequestFacts:      []jstangle.HTTPRequestFact{{Provenance: provenance}},
		DomFlowFacts:      []jstangle.DomFlowFact{{Provenance: provenance}},
		AssetFacts:        []jstangle.AssetReferenceFact{{Provenance: provenance}},
		GraphQLOperations: []jstangle.GraphQLOperationFact{{Provenance: provenance}},
		WebSockets:        []jstangle.WebSocketFact{{Provenance: provenance}},
		EventSources:      []jstangle.EventSourceFact{{Provenance: provenance}},
		ClientRoutes:      []jstangle.ClientRouteFact{{Provenance: provenance}},
		BrowserFlows:      []jstangle.BrowserSecurityFlowFact{{Provenance: provenance}},
	}
	source := OriginalSource{
		Path: "src/api.ts", GeneratedSourceURL: "https://example.test/assets/app.js",
	}

	annotateSourceMappedResult(result, source)
	assertMapped := func(name string, got jstangle.Provenance) {
		t.Helper()
		if got.ModulePath != source.Path || len(got.ResolutionSteps) != 1 {
			t.Fatalf("%s provenance not mapped: %#v", name, got)
		}
		step := got.ResolutionSteps[0]
		if step.Kind != "source-map" || step.Name != source.Path || step.Value != source.GeneratedSourceURL {
			t.Fatalf("%s source-map step = %#v", name, step)
		}
	}
	assertMapped("http", result.RequestFacts[0].Provenance)
	assertMapped("dom", result.DomFlowFacts[0].Provenance)
	assertMapped("asset", result.AssetFacts[0].Provenance)
	assertMapped("graphql", result.GraphQLOperations[0].Provenance)
	assertMapped("websocket", result.WebSockets[0].Provenance)
	assertMapped("sse", result.EventSources[0].Provenance)
	assertMapped("route", result.ClientRoutes[0].Provenance)
	assertMapped("browser", result.BrowserFlows[0].Provenance)

	annotateSourceMappedResult(result, source)
	if len(result.RequestFacts[0].Provenance.ResolutionSteps) != 1 {
		t.Fatal("source-map annotation was not idempotent")
	}
}
