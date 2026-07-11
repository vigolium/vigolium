package discovery

import (
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
)

func newTestJSExtractedTask(reqs []jstangle.ExtractedRequest) *JSExtractedRequestTask {
	dir, _ := url.Parse("https://example.com/app/")
	return NewJSExtractedRequestTask(&JSExtractedRequestTaskConfig{
		DirURL:               dir,
		Depth:                1,
		GetExtractedRequests: func() []jstangle.ExtractedRequest { return reqs },
	})
}

func typedFact(id, rawURL, method, confidence string) jstangle.HTTPRequestFact {
	return jstangle.HTTPRequestFact{
		Kind: "httpRequest", ID: id,
		URL:    jstangle.ValueTemplate{Rendered: rawURL, Static: !ContainsTemplateVar(rawURL)},
		Method: jstangle.ValueTemplate{Rendered: method, Static: true},
		Client: "fetch", Provenance: jstangle.Provenance{Extractor: "fetch", Confidence: confidence},
	}
}

func TestResolveReplayURL(t *testing.T) {
	dir, _ := url.Parse("https://crawl.example/some/dir/")
	const bundle = "https://app.example/assets/js/app.js"
	cases := []struct {
		name      string
		rawURL    string
		sourceURL string
		want      string
	}{
		// Root-relative always resolves against the origin (base path is irrelevant).
		{"root-relative", "/api/users", bundle, "https://app.example/api/users"},
		// Path-relative resolves against the origin ROOT (document base), NOT the
		// bundle's /assets/js/ directory — this is the core bug fix.
		{"path-relative", "api/users", bundle, "https://app.example/api/users"},
		{"dot-relative", "./api", bundle, "https://app.example/api"},
		{"parent-relative clamps at root", "../api/users/1", bundle, "https://app.example/api/users/1"},
		// Absolute references pass through untouched.
		{"absolute", "https://api.other/v1/x", bundle, "https://api.other/v1/x"},
		// With no bundle URL (legacy path), the origin comes from the crawl dir.
		{"origin from fallback", "api/x", "", "https://crawl.example/api/x"},
		// Unresolved placeholders and empties are dropped, never replayed.
		{"placeholder", "${apiBase}/users", bundle, ""},
		{"empty", "", bundle, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveReplayURL(tc.rawURL, tc.sourceURL, dir); got != tc.want {
				t.Fatalf("resolveReplayURL(%q, %q) = %q, want %q", tc.rawURL, tc.sourceURL, got, tc.want)
			}
		})
	}
}

func TestTypedReplayUsesSourceURLAndExactObservedSemantics(t *testing.T) {
	registry := NewRequestTemplateRegistry()
	fact := typedFact("fact-1", "../api/users/${id}", "POST", "high")
	fact.Query = []jstangle.FieldTemplate{{
		Name:  jstangle.ValueTemplate{Rendered: "expand", Static: true},
		Value: jstangle.ValueTemplate{Rendered: "${expand}", Static: false},
	}}
	fact.Body = &jstangle.BodyTemplate{
		Kind: "json", ContentType: "application/json",
		Value: jstangle.ValueTemplate{Rendered: `{"name":"${name}"}`, Static: false},
	}
	fact.Headers = []jstangle.HeaderTemplate{
		{Name: jstangle.ValueTemplate{Rendered: "Accept", Static: true}, Value: jstangle.ValueTemplate{Rendered: "application/json", Static: true}},
		{Name: jstangle.ValueTemplate{Rendered: "X-App-Version", Static: true}, Value: jstangle.ValueTemplate{Rendered: "7", Static: true}},
		{Name: jstangle.ValueTemplate{Rendered: "Authorization", Static: true}, Value: jstangle.ValueTemplate{Rendered: "Bearer public-literal", Static: true}, Sensitive: true},
		{Name: jstangle.ValueTemplate{Rendered: "Host", Static: true}, Value: jstangle.ValueTemplate{Rendered: "attacker.test", Static: true}},
	}
	registry.Add("https://example.com/assets/js/app.js", fact)
	dir, _ := url.Parse("https://example.com/unrelated/directory/")
	task := NewJSExtractedRequestTask(&JSExtractedRequestTaskConfig{
		DirURL: dir, Depth: 1, GetRequestTemplates: registry.PendingReplay,
	})

	variants := task.GenerateAllVariants()
	if len(variants) != 1 {
		t.Fatalf("exact fact generated %d variants, want 1: %+v", len(variants), variants)
	}
	variant := variants[0]
	// The reference "../api/users/1" resolves against the app origin root
	// (document base), NOT the bundle's /assets/js/ directory and NOT the
	// unrelated crawl directory.
	if variant.URL != "https://example.com/api/users/1?expand=1" {
		t.Fatalf("document-relative URL = %q", variant.URL)
	}
	if variant.Method != "POST" || variant.Body != `{"name":"1"}` || variant.ReplayTier != "exact" {
		t.Fatalf("observed semantics not preserved: %+v", variant)
	}
	if !slices.Contains(variant.Headers, "Accept: application/json") || !slices.Contains(variant.Headers, "X-App-Version: 7") {
		t.Fatalf("safe semantic headers missing: %+v", variant.Headers)
	}
	for _, header := range variant.Headers {
		if strings.HasPrefix(strings.ToLower(header), "authorization:") || strings.HasPrefix(strings.ToLower(header), "host:") {
			t.Fatalf("unsafe header was replayed: %s", header)
		}
	}
}

func TestTypedReplayConfidenceAndAlternativePolicy(t *testing.T) {
	registry := NewRequestTemplateRegistry()
	low := typedFact("low", "/low", "GET", "low")
	registry.Add("https://example.com/app.js", low)
	medium := typedFact("medium", "/primary", "GET", "medium")
	medium.URL.Alternatives = []string{"/alternative-one", "/alternative-two"}
	registry.Add("https://example.com/app.js", medium)
	placeholderBase := typedFact("base", "${apiBase}/users", "GET", "high")
	registry.Add("https://example.com/app.js", placeholderBase)
	dir, _ := url.Parse("https://example.com/")
	task := NewJSExtractedRequestTask(&JSExtractedRequestTaskConfig{
		DirURL: dir, Depth: 1, GetRequestTemplates: registry.PendingReplay,
	})

	variants := task.GenerateAllVariants()
	if len(variants) != 2 {
		t.Fatalf("medium policy generated %d variants, want primary + one alternative: %+v", len(variants), variants)
	}
	for _, variant := range variants {
		if variant.Confidence != "medium" || variant.ReplayTier != "conservative" ||
			strings.Contains(variant.URL, "/low") || strings.Contains(variant.URL, "apiBase") {
			t.Fatalf("invalid confidence routing: %+v", variant)
		}
	}
	if again := task.GenerateAllVariants(); len(again) != 0 {
		t.Fatalf("templates replayed more than once: %+v", again)
	}
}

func TestRequestTemplateRegistryKeepsSameRelativeFactPerSource(t *testing.T) {
	registry := NewRequestTemplateRegistry()
	fact := typedFact("same-fact", "./api", "GET", "high")
	registry.Add("https://one.example/a/app.js", fact)
	registry.Add("https://two.example/b/app.js", fact)
	if got := registry.Len(); got != 2 {
		t.Fatalf("registry length = %d, want 2 source-scoped templates", got)
	}
	dir, _ := url.Parse("https://fallback.invalid/")
	task := NewJSExtractedRequestTask(&JSExtractedRequestTaskConfig{DirURL: dir, GetRequestTemplates: registry.PendingReplay})
	variants := task.GenerateAllVariants()
	urls := []string{variants[0].URL, variants[1].URL}
	slices.Sort(urls)
	// The same relative fact "./api" stays source-scoped — distinct per origin —
	// but resolves against each app's origin root (document base), not the bundle's
	// /a/ or /b/ asset directory.
	want := []string{"https://one.example/api", "https://two.example/api"}
	if !slices.Equal(urls, want) {
		t.Fatalf("source-scoped URLs = %#v, want %#v", urls, want)
	}
}

func TestReplayDedupPrefersOriginalSourceMapProvenance(t *testing.T) {
	bundle := typedFact("bundle", "/api/users", "GET", "high")
	source := typedFact("source", "/api/users", "GET", "high")
	source.Provenance.ModulePath = "src/api.ts"
	source.Provenance.ResolutionSteps = []jstangle.ResolutionStep{{Kind: "source-map", Value: "sha256"}}
	registry := NewRequestTemplateRegistry()
	registry.Add("https://example.test/assets/app.js", bundle)
	registry.Add("https://example.test/assets/app.js#source=src%2Fapi.ts", source)
	dir, _ := url.Parse("https://example.test/")
	task := NewJSExtractedRequestTask(&JSExtractedRequestTaskConfig{DirURL: dir, GetRequestTemplates: registry.PendingReplay})
	variants := task.GenerateAllVariants()
	if len(variants) != 1 || !variants[0].SourceMapped || variants[0].SourceURL != "https://example.test/assets/app.js#source=src%2Fapi.ts" {
		t.Fatalf("duplicate replay did not retain original-source provenance: %+v", variants)
	}
}

func TestGraphQLOperationRequestPreservesOperationAndVariables(t *testing.T) {
	endpoint := jstangle.ValueTemplate{Rendered: "/graphql", Static: true}
	request, ok := graphQLOperationRequest(&jstangle.GraphQLOperationFact{
		Kind: "graphqlOperation", ID: "g1", Endpoint: &endpoint,
		OperationType: "mutation", OperationName: "UpdateUser",
		Document:  "mutation UpdateUser($id:ID!){updateUser(id:$id){id}}",
		Variables: []jstangle.GraphQLVariableTemplate{{Name: "id", Type: "ID!", Required: true}},
		Transport: "http", Provenance: jstangle.Provenance{Extractor: "graphql-document", Confidence: "high"},
	})
	if !ok || request.Method.Rendered != "POST" || request.Client != "graphql" || request.Body == nil {
		t.Fatalf("GraphQL operation was not converted: ok=%v request=%+v", ok, request)
	}
	if !strings.Contains(request.Body.Value.Rendered, `"query"`) || !strings.Contains(request.Body.Value.Rendered, `"${id}"`) {
		t.Fatalf("GraphQL body lost operation/variable shape: %s", request.Body.Value.Rendered)
	}
	if request.Body.Value.Static || request.Provenance.Confidence != "high" {
		t.Fatalf("GraphQL template metadata lost: %+v", request)
	}
}

func TestProtocolHandshakeFactsAreExplicitAndReplaySafe(t *testing.T) {
	ws, ok := webSocketHandshakeRequest(&jstangle.WebSocketFact{
		ID:           "ws-1",
		URL:          jstangle.ValueTemplate{Rendered: "wss://example.com/socket", Static: true},
		Subprotocols: []string{"graphql-transport-ws", "chat"},
		Provenance:   jstangle.Provenance{Start: &jstangle.SourceLocation{Line: 7}, Evidence: "new WebSocket(...)"},
	})
	if !ok || ws.URL.Rendered != "https://example.com/socket" || ws.Provenance.Extractor != "websocket-handshake" {
		t.Fatalf("WebSocket handshake conversion failed: ok=%v fact=%+v", ok, ws)
	}
	headers := safeReplayHeaders(&ws)
	for _, want := range []string{
		"Connection: Upgrade", "Upgrade: websocket", "Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Protocol: graphql-transport-ws, chat",
	} {
		if !slices.Contains(headers, want) {
			t.Errorf("handshake headers %#v do not contain %q", headers, want)
		}
	}

	// A normal request cannot smuggle browser-controlled headers through the
	// replay boundary, even when their values are static.
	normal := typedFact("normal", "/api", "GET", "high")
	normal.Headers = append(ws.Headers, jstangle.HeaderTemplate{
		Name:  jstangle.ValueTemplate{Rendered: "Origin", Static: true},
		Value: jstangle.ValueTemplate{Rendered: "https://attacker.invalid", Static: true},
	})
	if got := safeReplayHeaders(&normal); len(got) != 0 {
		t.Fatalf("ordinary request replayed controlled protocol headers: %#v", got)
	}
}

func TestEventSourceHandshakePreservesOnlyStaticCursor(t *testing.T) {
	staticCursor := jstangle.ValueTemplate{Rendered: "evt-42", Static: true}
	sse, ok := eventSourceHandshakeRequest(&jstangle.EventSourceFact{
		ID: "sse-1", URL: jstangle.ValueTemplate{Rendered: "/events", Static: true}, LastEventID: &staticCursor,
	})
	if !ok || sse.Provenance.Extractor != "eventsource-handshake" {
		t.Fatalf("EventSource handshake conversion failed: ok=%v fact=%+v", ok, sse)
	}
	headers := safeReplayHeaders(&sse)
	if !slices.Contains(headers, "Accept: text/event-stream") || !slices.Contains(headers, "Last-Event-ID: evt-42") {
		t.Fatalf("EventSource headers lost: %#v", headers)
	}

	dynamicCursor := jstangle.ValueTemplate{Rendered: "${cursor}", Static: false}
	sse, _ = eventSourceHandshakeRequest(&jstangle.EventSourceFact{
		ID: "sse-2", URL: jstangle.ValueTemplate{Rendered: "/events", Static: true}, LastEventID: &dynamicCursor,
	})
	if got := safeReplayHeaders(&sse); slices.Contains(got, "Last-Event-ID: ${cursor}") {
		t.Fatalf("dynamic SSE cursor was replayed: %#v", got)
	}
}

func TestStableClientRouteBoundsDynamicAndWildcardRoutes(t *testing.T) {
	cases := map[string]string{
		"/users/:id":       "/users/1",
		"/org/[org]/users": "/org/1/users",
		"/post/${slug}":    "/post/1",
	}
	for input, want := range cases {
		got, ok := stableClientRoute(input)
		if !ok || got != want {
			t.Errorf("stableClientRoute(%q) = %q, %v; want %q", input, got, ok, want)
		}
	}
	for _, input := range []string{"*", "/*", "/files/:path*", "https://other.test/page"} {
		if got, ok := stableClientRoute(input); ok {
			t.Errorf("wildcard/non-root route %q unexpectedly became %q", input, got)
		}
	}
}

func TestIsReplayableMethod(t *testing.T) {
	cases := map[string]bool{
		"GET":  true,
		"POST": true,
		"PUT":  true,
		"ws":   false,
		"WS":   false,
		"sse":  false,
		"SSE":  false,
	}
	for method, want := range cases {
		if got := isReplayableMethod(method); got != want {
			t.Errorf("isReplayableMethod(%q) = %v, want %v", method, got, want)
		}
	}
}

func TestGenerateAllVariantsSkipsNonReplayableMethods(t *testing.T) {
	reqs := []jstangle.ExtractedRequest{
		{URL: "wss://example.com/ws/notifications", Method: "WS"},
		{URL: "/events/stream", Method: "SSE"},
		// Absolute different-host URL is returned as-is by resolveRequestURL,
		// guaranteeing a deterministic positive variant.
		{URL: "https://api.other.com/v1/ping", Method: "GET"},
	}

	task := newTestJSExtractedTask(reqs)
	variants := task.GenerateAllVariants()

	for _, v := range variants {
		if v.Method == "WS" || v.Method == "SSE" {
			t.Fatalf("non-replayable method %q produced a variant: %+v", v.Method, v)
		}
		if strings.Contains(v.URL, "/ws/notifications") || strings.Contains(v.URL, "/events/stream") {
			t.Fatalf("non-replayable URL was replayed: %s", v.URL)
		}
	}

	foundPing := false
	for _, v := range variants {
		if strings.Contains(v.URL, "api.other.com/v1/ping") {
			foundPing = true
		}
	}
	if !foundPing {
		t.Fatalf("expected replayable GET to produce a variant, got %+v", variants)
	}
}
