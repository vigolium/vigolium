package jstangle

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCapabilitiesHas(t *testing.T) {
	var none *Capabilities
	if none.Has(CapabilityPathLiteral) {
		t.Fatal("nil capabilities must advertise nothing")
	}
	old := &Capabilities{Capabilities: []string{"endpoints", "clientRoutes"}}
	if old.Has(CapabilityRouteFullPath) {
		t.Fatal("a helper that predates fullPath must not report it")
	}
	current := &Capabilities{Capabilities: []string{"endpoints", CapabilityPathLiteral, CapabilityTruncationCounts}}
	if !current.Has(CapabilityPathLiteral) || !current.Has(CapabilityTruncationCounts) {
		t.Fatalf("advertised features not found: %v", current.Capabilities)
	}
}

func TestAppendAnalysisRecordDecodesReleaseOneFacts(t *testing.T) {
	records := []string{
		`{"kind":"pathLiteral","id":"path-1","value":{"rendered":"/api/v2/profile","static":true,"variables":[]},"reason":"object-value","key":"profile","provenance":{"extractor":"path-literal","confidence":"low"}}`,
		`{"kind":"httpRequest","id":"http-1","url":{"rendered":"/api/v3/things","static":true,"variables":[]},"method":{"rendered":"GET","static":true,"variables":[]},"query":[],"headers":[],"cookies":[],"client":"axios","provenance":{"extractor":"axios","confidence":"high"},"auth":{"kind":"bearer","header":"Authorization","scheme":"Bearer","source":"localStorage:jwt","sourceKind":"localStorage"},"callSite":"cs-1","suppressed":[{"id":"http-2","url":"/things","reason":"suffix"}]}`,
		`{"kind":"clientRoute","id":"route-1","path":{"rendered":"reports","static":true,"variables":[]},"routeType":"page","fullPath":{"rendered":"/admin/reports","static":true,"variables":[]},"parentId":"route-0","provenance":{"extractor":"router-config","confidence":"high"}}`,
		`{"kind":"assetReference","id":"asset-1","assetType":"script","url":{"rendered":"/static/js/1.js","static":true,"variables":[]},"eager":false,"loader":"webpack-chunk","provenance":{"extractor":"webpack-runtime","confidence":"high"}}`,
	}
	result := &ScanResult{}
	for _, record := range records {
		appendAnalysisRecord(result, json.RawMessage(record))
	}
	if result.UnknownRecords != 0 || result.MalformedRecords != 0 {
		t.Fatalf("unknown=%d malformed=%d", result.UnknownRecords, result.MalformedRecords)
	}
	if len(result.PathLiterals) != 1 || result.PathLiterals[0].Key != "profile" || result.PathLiterals[0].Reason != "object-value" {
		t.Fatalf("path literal not decoded: %+v", result.PathLiterals)
	}
	fact := result.RequestFacts[0]
	if fact.Auth == nil || fact.Auth.Source != "localStorage:jwt" || fact.CallSite != "cs-1" || len(fact.Suppressed) != 1 {
		t.Fatalf("request fact release-1 fields not decoded: %+v", fact)
	}
	route := &result.ClientRoutes[0]
	if route.RoutePath() != "/admin/reports" || route.ParentID != "route-0" {
		t.Fatalf("route full path not decoded: %+v", route)
	}
	if result.AssetFacts[0].Loader != "webpack-chunk" {
		t.Fatalf("asset loader not decoded: %+v", result.AssetFacts[0])
	}
}

func TestClientRouteRoutePathFallsBackToPath(t *testing.T) {
	route := &ClientRouteFact{Path: ValueTemplate{Rendered: "/legacy"}}
	if route.RoutePath() != "/legacy" {
		t.Fatalf("RoutePath() = %q", route.RoutePath())
	}
}

type capsServiceBackend struct {
	fakeServiceBackend
	capabilities []string
}

func (b *capsServiceBackend) Capabilities() (*Capabilities, error) {
	return &Capabilities{
		Type: "capabilities", ProtocolVersion: ProtocolVersion, SourceHash: "caps-source-hash",
		Capabilities: b.capabilities,
	}, nil
}

// fullBucket returns a backend result holding exactly n request facts, as a
// helper does when its request cap cut the list.
func fullBucket(n int, status string, diagnostics ...Diagnostic) func(context.Context, []byte, ScanOptions) (*ScanResult, error) {
	return func(_ context.Context, _ []byte, options ScanOptions) (*ScanResult, error) {
		result := &ScanResult{Analysis: &AnalysisResultV2{SchemaVersion: 2}, Diagnostics: diagnostics}
		for i := range n {
			fact := HTTPRequestFact{
				Kind: "httpRequest", ID: fmt.Sprintf("http-%d", i),
				URL:    ValueTemplate{Rendered: fmt.Sprintf("/api/cap/%d", i), Static: true},
				Method: ValueTemplate{Rendered: "GET", Static: true}, Client: "fetch",
				Provenance: Provenance{Extractor: "fetch", Confidence: "high"},
			}
			result.RequestFacts = append(result.RequestFacts, fact)
			result.Requests = append(result.Requests, legacyRequestFromFact(fact))
		}
		result.Analysis.Stats.Status = status
		result.Completion = &ScanCompletion{Type: "scanCompleted", Status: status, Profile: options.Profile}
		result.Completion.Counts.Requests = n
		return result, nil
	}
}

func TestServiceInfersRequestCapFromOlderHelper(t *testing.T) {
	backend := &capsServiceBackend{fakeServiceBackend: fakeServiceBackend{scan: fullBucket(5, "complete")}}
	service := testService(backend, 4, 1024*1024)
	defer func() { _ = service.Close() }()

	result, err := service.ScanWithOptions(context.Background(), []byte(`fetch('/api/cap/0')`), ScanOptions{Profile: ProfileDiscovery, MaxRequests: 5})
	if err != nil {
		t.Fatal(err)
	}
	if result.Completion.Status != "partial" || result.Completion.ReasonCode != ReasonRequestCap {
		t.Fatalf("full bucket from an older helper was not marked request_cap: %+v", result.Completion)
	}
	if result.Analysis.Stats.Status != "partial" {
		t.Fatalf("analysis status = %q", result.Analysis.Stats.Status)
	}
	found := false
	for _, diagnostic := range result.Diagnostics {
		found = found || diagnostic.Code == requestCapDiagnosticCode
	}
	if !found {
		t.Fatalf("missing %s diagnostic: %+v", requestCapDiagnosticCode, result.Diagnostics)
	}
	if hits := service.Stats().LimitHits[requestCapDiagnosticCode]; hits != 1 {
		t.Fatalf("limit hits for %s = %d", requestCapDiagnosticCode, hits)
	}
}

func TestServiceNamesReasonForOlderHelperCapDiagnostic(t *testing.T) {
	diagnostic := Diagnostic{Type: "diagnostic", Severity: "warning", Stage: "endpoints", Code: "request_limit_reached"}
	backend := &capsServiceBackend{fakeServiceBackend: fakeServiceBackend{scan: fullBucket(3, "partial", diagnostic)}}
	service := testService(backend, 4, 1024*1024)
	defer func() { _ = service.Close() }()

	result, err := service.ScanWithOptions(context.Background(), []byte(`fetch('/x')`), ScanOptions{Profile: ProfileDiscovery, MaxRequests: 3})
	if err != nil {
		t.Fatal(err)
	}
	if result.Completion.ReasonCode != ReasonRequestCap {
		t.Fatalf("reason = %q, want %q", result.Completion.ReasonCode, ReasonRequestCap)
	}
	for _, d := range result.Diagnostics {
		if d.Code == requestCapDiagnosticCode {
			t.Fatal("helper already diagnosed the cap; Go must not add a second diagnostic")
		}
	}
}

func TestServiceTrustsHelperThatCountsTruncation(t *testing.T) {
	backend := &capsServiceBackend{
		fakeServiceBackend: fakeServiceBackend{scan: fullBucket(4, "complete")},
		capabilities:       []string{"endpoints", CapabilityTruncationCounts},
	}
	service := testService(backend, 4, 1024*1024)
	defer func() { _ = service.Close() }()

	result, err := service.ScanWithOptions(context.Background(), []byte(`fetch('/y')`), ScanOptions{Profile: ProfileDiscovery, MaxRequests: 4})
	if err != nil {
		t.Fatal(err)
	}
	if result.Completion.Status != "complete" || result.Completion.ReasonCode != "" {
		t.Fatalf("exactly-full bucket from a counting helper must stay complete: %+v", result.Completion)
	}
}

func TestCheapFallbackCountsRequestCap(t *testing.T) {
	var source strings.Builder
	for i := range 12 {
		fmt.Fprintf(&source, "fetch(\"/api/fallback/%d\");\n", i)
	}
	source.WriteString("fetch(\"/api/fallback/0\");\n") // a repeat is not a drop
	result := cheapFallbackAnalysis([]byte(source.String()), normalizeScanOptions(ScanOptions{Profile: ProfileDiscovery, MaxRequests: 5}), "hash")
	if len(result.RequestFacts) != 5 {
		t.Fatalf("kept %d facts, want 5", len(result.RequestFacts))
	}
	if got := result.Completion.Counts.Truncated["httpRequest"]; got != 7 {
		t.Fatalf("truncated httpRequest = %d, want 7", got)
	}
	if result.Analysis.Stats.Truncated["httpRequest"] != 7 {
		t.Fatalf("analysis truncated = %+v", result.Analysis.Stats.Truncated)
	}
	if result.Completion.ReasonCode != "ast_analysis_skipped_very_large" {
		t.Fatalf("fallback reason must stay the more fundamental one, got %q", result.Completion.ReasonCode)
	}
	found := false
	for _, diagnostic := range result.Diagnostics {
		found = found || diagnostic.Code == requestCapDiagnosticCode
	}
	if !found || result.Completion.Counts.Diagnostics != len(result.Diagnostics) {
		t.Fatalf("cap diagnostic missing or uncounted: %+v", result.Diagnostics)
	}
}

func TestCheapFallbackUnderCapReportsNoTruncation(t *testing.T) {
	result := cheapFallbackAnalysis([]byte(`fetch("/api/one"); fetch("/api/two");`), normalizeScanOptions(ScanOptions{Profile: ProfileDiscovery}), "hash")
	if result.Completion.Counts.Truncated != nil || len(result.Diagnostics) != 1 {
		t.Fatalf("unexpected truncation: %+v %+v", result.Completion.Counts, result.Diagnostics)
	}
}

// A helper advertising facts.clientRoute.meta reports the route record's
// literal metadata (non-literal values null) and a data route's loader.
func TestAppendAnalysisRecordDecodesRouteMeta(t *testing.T) {
	record := `{"kind":"clientRoute","id":"route-9","path":{"rendered":"/admin","static":true,"variables":[]},"routeType":"page","guards":["inject(AuthService).isLoggedIn()","<inline>"],"meta":{"requiresAuth":true,"roles":["admin","ops"],"level":3,"check":null,"nested":{"a":"b"}},"loader":"adminLoader","provenance":{"extractor":"router-config","confidence":"high"}}`
	result := &ScanResult{}
	appendAnalysisRecord(result, json.RawMessage(record))
	if result.UnknownRecords != 0 || result.MalformedRecords != 0 || len(result.ClientRoutes) != 1 {
		t.Fatalf("unknown=%d malformed=%d routes=%d", result.UnknownRecords, result.MalformedRecords, len(result.ClientRoutes))
	}
	route := result.ClientRoutes[0]
	if route.Meta["requiresAuth"] != true || route.Meta["level"] != float64(3) {
		t.Fatalf("meta literals not decoded: %+v", route.Meta)
	}
	if roles, _ := route.Meta["roles"].([]any); len(roles) != 2 || roles[0] != "admin" {
		t.Fatalf("meta roles not decoded: %+v", route.Meta["roles"])
	}
	if v, ok := route.Meta["check"]; !ok || v != nil {
		t.Fatalf("a non-literal meta value stays a null key: %+v", route.Meta)
	}
	if route.Loader != "adminLoader" || len(route.Guards) != 2 || route.Guards[1] != "<inline>" {
		t.Fatalf("loader/guards not decoded: %+v", route)
	}
	caps := &Capabilities{Capabilities: []string{CapabilityRouteMeta}}
	if !caps.Has(CapabilityRouteMeta) {
		t.Fatal("route meta capability not advertised")
	}
}
