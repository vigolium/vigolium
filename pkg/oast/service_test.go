package oast

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestExtractNonce(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"abc123nonce456.oast.pro", "abc123nonce456"},
		{"correlationid.server.example.com", "correlationid"},
		{"nodot", ""},
		{"", ""},
		{".leading-dot", ""},
	}

	for _, tt := range tests {
		got := extractNonce(tt.url)
		if got != tt.want {
			t.Errorf("extractNonce(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestNewDisabledConfig(t *testing.T) {
	cfg := &config.OASTConfig{Enabled: false}
	svc, err := New(cfg, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc != nil {
		t.Fatal("expected nil service when disabled")
	}
}

func TestNewNilConfig(t *testing.T) {
	svc, err := New(nil, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc != nil {
		t.Fatal("expected nil service for nil config")
	}
}

func TestEnabledNilService(t *testing.T) {
	var svc *Service
	if svc.Enabled() {
		t.Fatal("nil service should not be enabled")
	}
}

func TestGenerateURLNilService(t *testing.T) {
	var svc *Service
	url := svc.GenerateURL("http://target.com", "url", "param", "mod-id", "hash123")
	if url != "" {
		t.Fatalf("expected empty URL from nil service, got %q", url)
	}
}

func TestFlushCloseNilService(t *testing.T) {
	// Should not panic on nil receiver
	var svc *Service
	svc.Flush()
	svc.Close()
	svc.Start()
}

func TestSetRequestUUIDResolverNilService(t *testing.T) {
	// Should not panic on nil receiver
	var svc *Service
	svc.SetRequestUUIDResolver(func(hash string) string { return "uuid-123" })
}

func TestSaveFindingNoRepo(t *testing.T) {
	// saveFinding with nil repo should not panic
	svc := &Service{}
	svc.saveFinding(nil, "hash123")
}

func TestSaveFindingEmptyHash(t *testing.T) {
	// saveFinding with empty request hash should be a no-op
	svc := &Service{repo: nil}
	svc.saveFinding(nil, "")
}

func extractedValue(results []string, prefix string) (string, bool) {
	for _, r := range results {
		if strings.HasPrefix(r, prefix) {
			return strings.TrimPrefix(r, prefix), true
		}
	}
	return "", false
}

// TestEnrichOASTResult verifies an out-of-band finding is made self-tracing: the
// planting request/response are embedded and human-readable anchors (origin
// request, http_record UUID, planted callback URL, callback evidence) are added.
func TestEnrichOASTResult(t *testing.T) {
	interaction := &server.Interaction{
		Protocol:      "http",
		UniqueID:      "nonce123",
		RawRequest:    "GET / HTTP/1.1\r\nHost: nonce123.oast.pro\r\n\r\n",
		RawResponse:   "HTTP/1.1 200 OK\r\n\r\n",
		RemoteAddress: "203.0.113.7",
		Timestamp:     time.Date(2026, 6, 9, 5, 30, 37, 0, time.UTC),
	}
	pctx := PayloadContext{
		TargetURL:     "http://victim.example/css",
		ParameterName: "request-line",
		InjectionType: "routing-ssrf (request-line)",
		ModuleID:      "routing-ssrf",
		RequestHash:   "deadbeef",
		CallbackURL:   "http://nonce123.oast.pro",
	}
	origin := &database.HTTPRecord{
		UUID:        "d85c371d-e536-4ad5-b00c-8204f32ddcfe",
		Method:      "GET",
		URL:         "http://victim.example/css",
		RawRequest:  []byte("GET /css HTTP/1.1\r\nHost: victim.example\r\n\r\n"),
		RawResponse: []byte("HTTP/1.1 200 OK\r\n\r\nbody"),
	}

	sev, _, desc := classifyInteraction(interaction.Protocol, pctx)
	result := &output.ResultEvent{
		ModuleID: pctx.ModuleID,
		Info:     output.Info{Description: desc, Severity: sev},
		ExtractedResults: []string{
			"protocol=" + interaction.Protocol,
			"oast_id=" + interaction.UniqueID,
			"remote_addr=" + interaction.RemoteAddress,
		},
	}

	enrichOASTResult(result, interaction, pctx, origin)

	// The planting request is embedded with the request-line payload re-applied,
	// so the panel shows where the callback URL was planted — not the bare
	// original. The original Host header (the victim) is preserved.
	if !strings.Contains(result.Request, "GET http://nonce123.oast.pro/ HTTP/1.1") {
		t.Errorf("Request missing reconstructed request-line payload: got %q", result.Request)
	}
	if !strings.Contains(result.Request, "Host: victim.example") {
		t.Errorf("Request dropped the victim Host header: got %q", result.Request)
	}
	if result.Response != string(origin.RawResponse) {
		t.Errorf("Response not embedded: got %q", result.Response)
	}

	// The planted payload + injection point are stated explicitly.
	if v, ok := extractedValue(result.ExtractedResults, "injected_payload="); !ok || v != "http://nonce123.oast.pro/ (request-line)" {
		t.Errorf("injected_payload anchor missing/wrong: %q ok=%v", v, ok)
	}

	// Trace anchors are present in extracted-results.
	if v, ok := extractedValue(result.ExtractedResults, "http_record="); !ok || v != origin.UUID {
		t.Errorf("http_record anchor missing/wrong: %q ok=%v", v, ok)
	}
	if v, ok := extractedValue(result.ExtractedResults, "callback_url="); !ok || v != pctx.CallbackURL {
		t.Errorf("callback_url anchor missing/wrong: %q ok=%v", v, ok)
	}
	if v, ok := extractedValue(result.ExtractedResults, "origin_request="); !ok || v != "GET http://victim.example/css" {
		t.Errorf("origin_request anchor missing/wrong: %q ok=%v", v, ok)
	}
	if _, ok := extractedValue(result.ExtractedResults, "interacted_at="); !ok {
		t.Error("interacted_at anchor missing")
	}

	// Description is self-describing in plain-text outputs.
	if !strings.Contains(result.Info.Description, origin.UUID) ||
		!strings.Contains(result.Info.Description, "GET http://victim.example/css") {
		t.Errorf("description missing origin anchors: %q", result.Info.Description)
	}

	// The out-of-band callback request is retained as evidence.
	if len(result.AdditionalEvidence) == 0 ||
		!strings.Contains(result.AdditionalEvidence[0], "nonce123.oast.pro") {
		t.Errorf("callback evidence missing: %v", result.AdditionalEvidence)
	}
}

// TestPayloadRequest verifies the payload is re-applied at the right injection
// point so the Request panel is never a bare original. Covers the real-world
// bare-host callback (no scheme), header injection, and the parameter fallback.
func TestPayloadRequest(t *testing.T) {
	raw := []byte("GET /foo?a=1 HTTP/1.1\r\nHost: victim.example\r\nAccept: */*\r\n\r\n")

	// Request-line SSRF with a bare-host callback (as interactsh emits it) over
	// https → absolute-URI target on the request line, Host header untouched.
	rl := payloadRequest(raw, PayloadContext{
		ParameterName: "request-line",
		InjectionType: "routing-ssrf (request-line)",
		CallbackURL:   "abc123.oast.vigolium.com",
	}, "https")
	if !strings.HasPrefix(rl, "GET https://abc123.oast.vigolium.com/ HTTP/1.1\r\n") {
		t.Errorf("request-line reconstruction wrong: %q", rl)
	}
	if !strings.Contains(rl, "Host: victim.example") || !strings.Contains(rl, "Accept: */*") {
		t.Errorf("request-line reconstruction dropped headers: %q", rl)
	}

	// Header injection → the named header carries the callback URL.
	hdr := payloadRequest(raw, PayloadContext{
		ParameterName: "X-Forwarded-Host",
		InjectionType: "header",
		CallbackURL:   "abc123.oast.vigolium.com",
	}, "http")
	if !strings.Contains(hdr, "X-Forwarded-Host: http://abc123.oast.vigolium.com") {
		t.Errorf("header reconstruction missing payload: %q", hdr)
	}

	// Parameter injection is not reconstructed (the wire form is unknown) — the
	// original request is returned unchanged.
	param := payloadRequest(raw, PayloadContext{
		ParameterName: "url",
		InjectionType: "parameter",
		CallbackURL:   "abc123.oast.vigolium.com",
	}, "http")
	if param != string(raw) {
		t.Errorf("parameter injection should return original request, got: %q", param)
	}

	// When the planting module recorded the exact value (PayloadContext.Payload),
	// header reconstruction uses it verbatim — so a command-injection finding shows
	// the real ";nslookup <host>" shell payload in the header, not a bare host.
	cmdi := payloadRequest(raw, PayloadContext{
		ParameterName: "X-Forwarded-For",
		InjectionType: "os-command-injection (header)",
		CallbackURL:   "abc123.oast.vigolium.com",
		Payload:       ";nslookup abc123.oast.vigolium.com",
	}, "dns")
	if !strings.Contains(cmdi, "X-Forwarded-For: ;nslookup abc123.oast.vigolium.com") {
		t.Errorf("cmdi header reconstruction must use the recorded shell payload, got: %q", cmdi)
	}
}

// TestDescribeInjectedPayload verifies the injected_payload anchor states the
// exact value the module planted when recorded — surfacing the shell payload for
// command injection — and falls back to the http/bare-host shape otherwise.
func TestDescribeInjectedPayload(t *testing.T) {
	// Command injection: the anchor must show the real shell payload + header, not
	// the bare callback host (the original investigation pain point).
	cmdi := describeInjectedPayload(PayloadContext{
		ParameterName: "X-Forwarded-For",
		InjectionType: "os-command-injection (header)",
		CallbackURL:   "abc123.oast.vigolium.com",
		Payload:       ";nslookup abc123.oast.vigolium.com",
	}, "dns")
	if cmdi != ";nslookup abc123.oast.vigolium.com (header X-Forwarded-For)" {
		t.Errorf("cmdi injected_payload anchor wrong: %q", cmdi)
	}

	// No recorded payload → falls back to the http://<host> header shape.
	fallback := describeInjectedPayload(PayloadContext{
		ParameterName: "X-Forwarded-Host",
		InjectionType: "header",
		CallbackURL:   "abc123.oast.vigolium.com",
	}, "http")
	if fallback != "http://abc123.oast.vigolium.com (header X-Forwarded-Host)" {
		t.Errorf("fallback injected_payload anchor wrong: %q", fallback)
	}

	// A protocol-smuggling payload carrying literal CR/LF must render on one line
	// (control characters escaped) so it can't break the anchor.
	smuggle := describeInjectedPayload(PayloadContext{
		ParameterName: "url",
		InjectionType: "ssrf-smuggle:crlf",
		CallbackURL:   "abc123.oast.vigolium.com",
		Payload:       "gopher://abc123.oast.vigolium.com:80/_GET / HTTP/1.1\r\nHost: x\r\n",
	}, "dns")
	if strings.ContainsAny(smuggle, "\r\n") {
		t.Errorf("smuggle anchor must not contain raw CR/LF: %q", smuggle)
	}
	if !strings.Contains(smuggle, `\r\n`) || !strings.Contains(smuggle, "(parameter url)") {
		t.Errorf("smuggle anchor should escape CR/LF and keep the location: %q", smuggle)
	}
}

// TestEnrichOASTResultNoOrigin verifies enrichment degrades gracefully when the
// originating record could not be recovered (e.g. a fixed-URL OAST callback).
func TestEnrichOASTResultNoOrigin(t *testing.T) {
	interaction := &server.Interaction{Protocol: "dns", UniqueID: "n", RemoteAddress: "198.51.100.4"}
	pctx := PayloadContext{InjectionType: "parameter", CallbackURL: "http://n.oast.pro"}
	result := &output.ResultEvent{Info: output.Info{Description: "base"}}

	enrichOASTResult(result, interaction, pctx, nil)

	if result.Request != "" || result.Response != "" {
		t.Error("expected no embedded request/response without an origin record")
	}
	if _, ok := extractedValue(result.ExtractedResults, "http_record="); ok {
		t.Error("did not expect an http_record anchor without an origin record")
	}
	if v, ok := extractedValue(result.ExtractedResults, "callback_url="); !ok || v != pctx.CallbackURL {
		t.Errorf("callback_url anchor should still be present: %q ok=%v", v, ok)
	}
}

// TestOASTProtocolRank locks in the ordering that drives finding upgrades: an
// HTTP(S) fetch (proof a command/SSRF actually reached out) outranks a bare DNS
// resolution, with any other protocol sitting between the two.
func TestOASTProtocolRank(t *testing.T) {
	if oastProtocolRank("https") != oastProtocolRank("http") {
		t.Error("http and https should rank equally")
	}
	if oastProtocolRank("http") <= oastProtocolRank("dns") {
		t.Error("http should outrank dns")
	}
	if r := oastProtocolRank("smtp"); r <= oastProtocolRank("dns") || r >= oastProtocolRank("http") {
		t.Errorf("an unknown protocol should rank between dns and http, got %d", r)
	}
}

// TestClaimEmission verifies the per-nonce coalescing decision: the first callback
// for a payload emits, duplicate/weaker callbacks are suppressed, a strictly
// stronger callback upgrades once, and different payloads are independent.
func TestClaimEmission(t *testing.T) {
	s := &Service{}

	if emit, up := s.claimEmission("n1", "dns"); !emit || up {
		t.Fatalf("first DNS callback: got emit=%v upgrade=%v, want true/false", emit, up)
	}
	// The DNS A/AAAA/resolver flood for the same payload is suppressed.
	for i := 0; i < 3; i++ {
		if emit, _ := s.claimEmission("n1", "dns"); emit {
			t.Fatalf("duplicate DNS callback %d emitted, want suppressed", i)
		}
	}
	// The HTTP fetch leg confirms execution → emit once as an upgrade.
	if emit, up := s.claimEmission("n1", "http"); !emit || !up {
		t.Fatalf("HTTP upgrade: got emit=%v upgrade=%v, want true/true", emit, up)
	}
	// Anything weaker-or-equal after the upgrade is suppressed.
	if emit, _ := s.claimEmission("n1", "dns"); emit {
		t.Fatal("DNS after HTTP upgrade emitted, want suppressed")
	}
	if emit, _ := s.claimEmission("n1", "https"); emit {
		t.Fatal("repeat HTTP after upgrade emitted, want suppressed")
	}
	// A different payload (nonce) is tracked independently.
	if emit, up := s.claimEmission("n2", "dns"); !emit || up {
		t.Fatalf("first callback for a new nonce: got emit=%v upgrade=%v, want true/false", emit, up)
	}
}

func newOASTTestRepo(t *testing.T) *database.Repository {
	t.Helper()
	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        filepath.Join(t.TempDir(), "oast-test.sqlite"),
			BusyTimeout: 5000,
			JournalMode: "WAL",
			Synchronous: "NORMAL",
			CacheSize:   1000,
		},
	}
	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return database.NewRepository(db)
}

// TestHandleInteractionCoalescesPerNonce is the end-to-end coalescing test: many
// callbacks for one planted payload (the DNS A/AAAA/resolver flood, then the HTTP
// fetch leg) must yield exactly ONE finding — the strongest seen — not a pile of
// findings sharing one OAST host. This is the behaviour the investigation flagged.
func TestHandleInteractionCoalescesPerNonce(t *testing.T) {
	repo := newOASTTestRepo(t)
	ctx := context.Background()
	const project = "proj-1"

	var emits int
	svc := &Service{
		repo:        repo,
		emitResult:  func(*output.ResultEvent) { emits++ },
		scanUUID:    "scan-1",
		projectUUID: project,
	}

	const nonce = "corrid00000000000000nonce1234"
	host := nonce + ".oast.vigolium.com"
	svc.trackerCache().Add(nonce, PayloadContext{
		TargetURL:     "http://victim.example/run?cmd=1",
		ParameterName: "cmd", // a genuine request parameter → DNS classifies High/Firm
		InjectionType: "os-command-injection (parameter)",
		ModuleID:      "command-injection-oast",
		CallbackURL:   host,
		// A fetch command (curl) on a genuine parameter: its DNS resolve leg
		// classifies High/Firm and its HTTP-fetch leg legitimately upgrades to
		// Critical. (A DNS-only nslookup payload yielding an HTTP callback would be a
		// protocol mismatch and stay Low — see TestClassifyCommandInjectionProtocolMismatch.)
		Payload: "1;curl http://" + host,
	})

	dns := func() *server.Interaction {
		return &server.Interaction{Protocol: "dns", UniqueID: nonce, RemoteAddress: "8.8.8.8", Timestamp: time.Unix(1, 0).UTC()}
	}

	// A flood of DNS callbacks (A + AAAA + several recursive resolvers) for one payload.
	for i := 0; i < 5; i++ {
		svc.handleInteraction(dns())
	}
	if emits != 1 {
		t.Fatalf("DNS flood emitted %d findings, want 1 (coalesced per nonce)", emits)
	}
	highs, err := repo.GetFindingsBySeverity(ctx, project, "high", 10)
	if err != nil {
		t.Fatalf("GetFindingsBySeverity(high): %v", err)
	}
	if len(highs) != 1 {
		t.Fatalf("after DNS flood: %d high findings, want 1", len(highs))
	}

	// The HTTP-fetch leg confirms execution → upgrade in place to Critical. Still one
	// finding total: the High DNS lead is replaced, not left as a sibling.
	svc.handleInteraction(&server.Interaction{Protocol: "http", UniqueID: nonce, RemoteAddress: "203.0.113.9", Timestamp: time.Unix(2, 0).UTC()})
	if emits != 2 {
		t.Fatalf("expected exactly one upgrade emit (total 2), got %d", emits)
	}
	highs, _ = repo.GetFindingsBySeverity(ctx, project, "high", 10)
	crits, err := repo.GetFindingsBySeverity(ctx, project, "critical", 10)
	if err != nil {
		t.Fatalf("GetFindingsBySeverity(critical): %v", err)
	}
	if len(highs) != 0 {
		t.Fatalf("after HTTP upgrade: %d high findings remain, want 0 (replaced)", len(highs))
	}
	if len(crits) != 1 {
		t.Fatalf("after HTTP upgrade: %d critical findings, want 1", len(crits))
	}

	// Further weaker-or-equal callbacks are fully suppressed — no new findings.
	svc.handleInteraction(dns())
	svc.handleInteraction(&server.Interaction{Protocol: "https", UniqueID: nonce})
	if emits != 2 {
		t.Fatalf("post-upgrade callbacks emitted extra findings: emits=%d, want 2", emits)
	}
	crits, _ = repo.GetFindingsBySeverity(ctx, project, "critical", 10)
	if len(crits) != 1 {
		t.Fatalf("post-upgrade: %d critical findings, want 1", len(crits))
	}
}

// TestHandleInteractionCoalescesInfoPerHostInjectionPoint covers the noise the
// investigation flagged: a crawler plants the same low-signal injection point (a
// Referer the target logs and resolves) across dozens of URLs on one host, and
// each DNS-only callback classifies Info/Tentative. Those must collapse to ONE
// finding per (module, host, injection point) — not one per URL — while a distinct
// injection point or a distinct host still keys separately.
func TestHandleInteractionCoalescesInfoPerHostInjectionPoint(t *testing.T) {
	repo := newOASTTestRepo(t)
	ctx := context.Background()
	const project = "proj-info"

	var emits int
	svc := &Service{
		repo:        repo,
		emitResult:  func(*output.ResultEvent) { emits++ },
		scanUUID:    "scan-info",
		projectUUID: project,
	}

	// Register one payload (nonce) per crawled URL, all on host dialog1.example via
	// the same Referer injection point, then fire a DNS callback for each. A generic
	// blind-SSRF DNS-only callback classifies Info/Tentative.
	fire := func(nonce, targetURL, param, moduleID string) {
		svc.trackerCache().Add(nonce, PayloadContext{
			TargetURL:     targetURL,
			ParameterName: param,
			InjectionType: "parameter",
			ModuleID:      moduleID,
			CallbackURL:   nonce + ".oast.vigolium.com",
		})
		svc.handleInteraction(&server.Interaction{Protocol: "dns", UniqueID: nonce, RemoteAddress: "8.8.8.8", Timestamp: time.Unix(1, 0).UTC()})
	}

	urls := []string{
		"https://dialog1.example/",
		"https://dialog1.example/login",
		"https://dialog1.example/s/",
		"https://dialog1.example/_ui/12345",
		"https://dialog1.example/idp/endpoint?SAMLRequest=x",
	}
	for i, u := range urls {
		fire("nonceReferer"+string(rune('a'+i)), u, "Referer", "oast-probe")
	}
	if emits != 1 {
		t.Fatalf("Info DNS callbacks across %d URLs (same host+param) emitted %d findings, want 1 (coalesced)", len(urls), emits)
	}

	// A different injection point on the same host is a distinct signal → new finding.
	fire("nonceRefURL", "https://dialog1.example/dlg?refURL=y", "refURL", "oast-probe")
	if emits != 2 {
		t.Fatalf("distinct injection point on same host: emits=%d, want 2", emits)
	}

	// A different module on the same host+param also keys separately.
	fire("nonceBlind", "https://dialog1.example/", "Referer", "ssrf-blind")
	if emits != 3 {
		t.Fatalf("distinct module on same host+param: emits=%d, want 3", emits)
	}

	// A different host, same module+param → new finding.
	fire("nonceOtherHost", "https://other.example/", "Referer", "oast-probe")
	if emits != 4 {
		t.Fatalf("distinct host: emits=%d, want 4", emits)
	}

	infos, err := repo.GetFindingsBySeverity(ctx, project, "info", 50)
	if err != nil {
		t.Fatalf("GetFindingsBySeverity(info): %v", err)
	}
	if len(infos) != 4 {
		t.Fatalf("stored %d info findings, want 4 (5 same-key URLs collapsed to 1, + 3 distinct keys)", len(infos))
	}
}

// TestHandleInteractionXXEHarvestedCallbackDowngrade is the end-to-end reproduction
// of the reported false positive: an XXE external-entity payload is planted, then a
// monitoring bot fetches the injected OAST URL (the wild ginandjuice.shop callback).
// The persisted finding must be a Low/Tentative UNCONFIRMED lead — not a High/Certain
// "Blind XXE confirmed" — because the callback bears crawler fingerprints (a
// self-identifying User-Agent + an h2c upgrade) an XML parser never produces.
func TestHandleInteractionXXEHarvestedCallbackDowngrade(t *testing.T) {
	repo := newOASTTestRepo(t)
	ctx := context.Background()
	const project = "proj-xxe"

	var emitted *output.ResultEvent
	svc := &Service{
		repo:        repo,
		emitResult:  func(r *output.ResultEvent) { emitted = r },
		scanUUID:    "scan-xxe",
		projectUUID: project,
	}

	const nonce = "d997mujaf7ek583c4p00f5uwnu9ajo4y6"
	svc.trackerCache().Add(nonce, PayloadContext{
		TargetURL:     "https://ginandjuice.shop/catalog/product/stock",
		ParameterName: "body",
		InjectionType: "xxe (external entity)",
		ModuleID:      "xxe-generic",
		CallbackURL:   nonce + ".oast.vigolium.com",
	})

	svc.handleInteraction(&server.Interaction{
		Protocol:      "http",
		UniqueID:      nonce,
		RemoteAddress: "18.200.201.133",
		RawRequest:    wildXXECallback,
		Timestamp:     time.Unix(3, 0).UTC(),
	})

	if emitted == nil {
		t.Fatal("expected a finding to be emitted for the correlated XXE callback")
	}
	if emitted.Info.Severity.String() != "low" || emitted.Info.Confidence != severity.Tentative {
		t.Fatalf("harvested XXE callback = %s/%s, want low/tentative", emitted.Info.Severity, emitted.Info.Confidence)
	}
	if !strings.Contains(emitted.Info.Description, "UNCONFIRMED") {
		t.Errorf("finding must be labelled UNCONFIRMED; desc: %s", emitted.Info.Description)
	}

	// It must not have been stored as a High "confirmed" XXE.
	highs, err := repo.GetFindingsBySeverity(ctx, project, "high", 10)
	if err != nil {
		t.Fatalf("GetFindingsBySeverity(high): %v", err)
	}
	if len(highs) != 0 {
		t.Fatalf("harvested XXE callback stored %d high findings, want 0", len(highs))
	}
	lows, err := repo.GetFindingsBySeverity(ctx, project, "low", 10)
	if err != nil {
		t.Fatalf("GetFindingsBySeverity(low): %v", err)
	}
	if len(lows) != 1 {
		t.Fatalf("harvested XXE callback stored %d low findings, want 1", len(lows))
	}
}

func TestOASTEmissionKey(t *testing.T) {
	base := PayloadContext{ParameterName: "Referer", ModuleID: "oast-probe"}

	// Non-Info interactions keep per-nonce identity.
	for _, sev := range []severity.Severity{severity.High, severity.Critical, severity.Medium, severity.Low} {
		p := base
		p.TargetURL = "https://h.example/a"
		if got := oastEmissionKey(sev, "nonce-1", p); got != "nonce-1" {
			t.Errorf("oastEmissionKey(%s) = %q, want per-nonce %q", sev, got, "nonce-1")
		}
	}

	// Info interactions coalesce across URLs on the same host+injection point.
	a := base
	a.TargetURL = "https://h.example/a?q=1"
	b := base
	b.TargetURL = "https://h.example/b"
	ka := oastEmissionKey(severity.Info, "nonce-a", a)
	kb := oastEmissionKey(severity.Info, "nonce-b", b)
	if ka != kb {
		t.Errorf("Info keys for same host+param differ: %q vs %q", ka, kb)
	}
	if ka == "nonce-a" {
		t.Errorf("Info key must not be the nonce, got %q", ka)
	}

	// Distinct param, host, or module → distinct key.
	pParam := base
	pParam.TargetURL = "https://h.example/a"
	pParam.ParameterName = "refURL"
	pHost := base
	pHost.TargetURL = "https://other.example/a"
	pMod := base
	pMod.TargetURL = "https://h.example/a"
	pMod.ModuleID = "ssrf-blind"
	for name, p := range map[string]PayloadContext{"param": pParam, "host": pHost, "module": pMod} {
		if got := oastEmissionKey(severity.Info, "nonce-x", p); got == ka {
			t.Errorf("distinct %s should not share key %q", name, ka)
		}
	}

	// Header case-insensitivity: Referer and referer collapse.
	lower := base
	lower.TargetURL = "https://h.example/c"
	lower.ParameterName = "referer"
	if oastEmissionKey(severity.Info, "n", lower) != ka {
		t.Errorf("case-different param names must coalesce")
	}
}

func TestClassifyInteraction(t *testing.T) {
	pctx := PayloadContext{
		TargetURL:     "http://target.com",
		ParameterName: "url",
		InjectionType: "parameter",
	}

	tests := []struct {
		protocol    string
		wantHighSev bool // true = High, false = not High
	}{
		{"http", true},
		{"https", true},
		{"HTTP", true},
		{"dns", false},
		{"smtp", false},
	}

	for _, tt := range tests {
		sev, _, desc := classifyInteraction(tt.protocol, pctx)
		if tt.wantHighSev && sev.String() != "high" {
			t.Errorf("classifyInteraction(%q) severity = %s, want high; desc: %s", tt.protocol, sev, desc)
		}
		if !tt.wantHighSev && sev.String() == "high" {
			t.Errorf("classifyInteraction(%q) severity = high, expected non-high; desc: %s", tt.protocol, desc)
		}
		if desc == "" {
			t.Errorf("classifyInteraction(%q) returned empty description", tt.protocol)
		}
	}
}

// TestClassifyInteractionHostRoutingInfo locks in the host-routing SSRF
// downgrade: request-line manipulation (routing-ssrf) and X-Forwarded-Host
// header injection are reported as informational (often low-impact), while
// generic parameter-based blind SSRF and the other forwarding headers stay high.
func TestClassifyInteractionHostRoutingInfo(t *testing.T) {
	// routing-ssrf (request-line) → Info on any HTTP-family callback.
	routing := PayloadContext{TargetURL: "http://target.com", InjectionType: "request-line", ModuleID: "routing-ssrf"}
	for _, proto := range []string{"http", "https", "HTTPS"} {
		if sev, _, _ := classifyInteraction(proto, routing); sev.String() != "info" {
			t.Errorf("routing-ssrf classifyInteraction(%q) severity = %s, want info", proto, sev)
		}
	}

	// The proxy-reflected host-header family → Info (case-insensitive on the name).
	// A reverse proxy reflects these into a redirect Location / upstream URL that the
	// proxy (or the scanner following the redirect) fetches, so the HTTP callback is
	// not proof of a server-side SSRF — the same FP class as the command branch.
	for _, name := range []string{"X-Forwarded-Host", "x-forwarded-host", "X-Forwarded-Server", "X-Host", "X-Original-Host", "X-Original-URL", "X-Rewrite-URL"} {
		xfh := PayloadContext{TargetURL: "http://target.com", InjectionType: "header", ParameterName: name, ModuleID: "oast-probe"}
		if sev, _, _ := classifyInteraction("http", xfh); sev.String() != "info" {
			t.Errorf("host-reflection header (%q) classifyInteraction severity = %s, want info", name, sev)
		}
	}

	// Client-IP / non-reflected forwarding headers must remain high (genuine SSRF
	// signal — they are not reflected into outbound redirect/upstream URLs).
	for _, name := range []string{"X-Forwarded-For", "Referer", "Origin"} {
		other := PayloadContext{TargetURL: "http://target.com", InjectionType: "header", ParameterName: name, ModuleID: "oast-probe"}
		if sev, _, _ := classifyInteraction("http", other); sev.String() != "high" {
			t.Errorf("header %q classifyInteraction severity = %s, want high", name, sev)
		}
	}

	// A different module's parameter-based HTTP callback must remain high.
	generic := PayloadContext{TargetURL: "http://target.com", InjectionType: "parameter", ParameterName: "url", ModuleID: "ssrf-detection"}
	if sev, _, _ := classifyInteraction("http", generic); sev.String() != "high" {
		t.Errorf("generic SSRF classifyInteraction severity = %s, want high", sev)
	}
}

// TestClassifyCommandInjectionForwardingHeaderFP locks in the false-positive
// defense for OAST command injection: a DNS-only callback for a payload injected
// into a client-IP / forwarding header is NOT confirmed command injection (edge
// infrastructure resolves those header values for geo-IP/logging), so it is
// downgraded to Low / Tentative — while the HTTP-fetch leg stays Critical and a
// genuine request parameter stays High on DNS.
func TestClassifyCommandInjectionForwardingHeaderFP(t *testing.T) {
	// The exact false-positive class observed in the wild: nslookup/ping payloads
	// in X-Forwarded-For / X-Real-IP / True-Client-IP resolved over DNS by a
	// Google-fronted geo-IP edge. Must be downgraded, never High.
	for _, name := range []string{"X-Forwarded-For", "x-real-ip", "True-Client-IP", "CF-Connecting-IP", "X-Client-IP"} {
		pctx := PayloadContext{
			TargetURL:     "http://target.com",
			ParameterName: name,
			InjectionType: "os-command-injection (parameter)",
			ModuleID:      "command-injection-oast",
		}
		sev, conf, desc := classifyInteraction("dns", pctx)
		if sev.String() != "low" {
			t.Errorf("cmdi DNS on %q severity = %s, want low; desc: %s", name, sev, desc)
		}
		if conf != severity.Tentative {
			t.Errorf("cmdi DNS on %q confidence = %s, want tentative", name, conf)
		}
	}

	// HTTP/HTTPS callback (the curl/wget leg) on the same forwarding header is
	// strong proof a shell ran → stays Critical / Certain.
	httpPctx := PayloadContext{
		TargetURL:     "http://target.com",
		ParameterName: "X-Forwarded-For",
		InjectionType: "os-command-injection (header)",
		ModuleID:      "command-injection-oast",
	}
	if sev, conf, _ := classifyInteraction("http", httpPctx); sev.String() != "critical" || conf != severity.Certain {
		t.Errorf("cmdi HTTP on X-Forwarded-For = %s/%s, want critical/certain", sev, conf)
	}

	// DNS-only callback for a genuine request parameter (not a forwarding header)
	// is a strong lead → stays High, but Firm rather than Certain (no HTTP fetch).
	paramPctx := PayloadContext{
		TargetURL:     "http://target.com",
		ParameterName: "host",
		InjectionType: "os-command-injection (parameter)",
		ModuleID:      "command-injection-oast",
	}
	if sev, conf, _ := classifyInteraction("dns", paramPctx); sev.String() != "high" || conf != severity.Firm {
		t.Errorf("cmdi DNS on genuine param = %s/%s, want high/firm", sev, conf)
	}
}

// TestClassifyCommandInjectionProtocolMismatch reproduces the exact wild false
// positive: a ";nslookup <oast>" payload injected into X-Forwarded-Host yields an
// HTTPS callback (the proxy reflected the header into a redirect Location and a
// client followed it to <oast>/login). A DNS-only command cannot make an HTTP
// request by executing, so this must NOT be reported as confirmed command
// injection — it is downgraded to Low / Tentative, UNCONFIRMED.
func TestClassifyCommandInjectionProtocolMismatch(t *testing.T) {
	const host = "d8vktfraf7em8h1864k0bigm5o33zt98m.oast.vigolium.com"
	// The wild payload, verbatim: base host + ";nslookup <oast>" in X-Forwarded-Host.
	xfh := PayloadContext{
		TargetURL:     "https://lk-customerops-dr.hooli-corp.net/",
		ParameterName: "X-Forwarded-Host",
		InjectionType: "os-command-injection (header)",
		ModuleID:      "command-injection-oast",
		CallbackURL:   host,
		Payload:       "lk-customerops-dr.hooli-corp.net;nslookup " + host,
	}
	for _, proto := range []string{"http", "https", "HTTPS"} {
		sev, conf, desc := classifyInteraction(proto, xfh)
		if sev.String() != "low" || conf != severity.Tentative {
			t.Errorf("nslookup payload + %s callback = %s/%s, want low/tentative; desc: %s", proto, sev, conf, desc)
		}
		if !strings.Contains(desc, "UNCONFIRMED") {
			t.Errorf("downgraded finding must be labelled UNCONFIRMED; desc: %s", desc)
		}
	}

	// Protocol mismatch is parameter-agnostic: a DNS-only command yielding an HTTP
	// callback is a false positive even on a genuine request parameter (the host was
	// reached as a URL substring, not by the shell).
	param := PayloadContext{
		TargetURL:     "http://target.com/run",
		ParameterName: "cmd",
		InjectionType: "os-command-injection (parameter)",
		ModuleID:      "command-injection-oast",
		CallbackURL:   host,
		Payload:       "1;nslookup " + host,
	}
	if sev, conf, _ := classifyInteraction("http", param); sev.String() != "low" || conf != severity.Tentative {
		t.Errorf("nslookup payload + HTTP on genuine param = %s/%s, want low/tentative", sev, conf)
	}

	// A genuine fetch command (curl) producing an HTTP callback on a genuine
	// parameter is real command execution → stays Critical / Certain. The
	// protocol-mismatch guard must not touch it.
	curl := PayloadContext{
		TargetURL:     "http://target.com/run",
		ParameterName: "cmd",
		InjectionType: "os-command-injection (parameter)",
		ModuleID:      "command-injection-oast",
		CallbackURL:   host,
		Payload:       "1;curl http://" + host,
	}
	if sev, conf, _ := classifyInteraction("http", curl); sev.String() != "critical" || conf != severity.Certain {
		t.Errorf("curl payload + HTTP on genuine param = %s/%s, want critical/certain", sev, conf)
	}
}

// TestClassifyCommandInjectionReflectedHostHeader locks in the second guard: even a
// fetch command (curl) injected into a proxy-reflected host header is not confirmed
// command injection, because the proxy fetches the host embedded in the header
// regardless of any shell metacharacter (a bare-host control calls back the same).
// Both the HTTP and DNS callbacks on these headers are downgraded.
func TestClassifyCommandInjectionReflectedHostHeader(t *testing.T) {
	const host = "abc123.oast.vigolium.com"
	base := PayloadContext{
		TargetURL:     "http://target.com/",
		InjectionType: "os-command-injection (header)",
		ModuleID:      "command-injection-oast",
		CallbackURL:   host,
	}
	for _, name := range []string{"X-Forwarded-Host", "x-forwarded-server", "X-Host", "X-Original-Host", "X-Original-URL", "X-Rewrite-URL"} {
		// HTTP callback for a curl payload (protocol matches the command, so guard 1
		// does not fire) — guard 2 must still downgrade it on a reflected host header.
		curl := base
		curl.ParameterName = name
		curl.Payload = "target.com;curl http://" + host
		if sev, conf, desc := classifyInteraction("http", curl); sev.String() != "low" || conf != severity.Tentative {
			t.Errorf("curl payload + HTTP on %q = %s/%s, want low/tentative; desc: %s", name, sev, conf, desc)
		}
		// DNS callback on a reflected host header is likewise the proxy resolving the
		// host for routing → downgraded.
		nsl := curl
		nsl.Payload = "target.com;nslookup " + host
		if sev, conf, _ := classifyInteraction("dns", nsl); sev.String() != "low" || conf != severity.Tentative {
			t.Errorf("nslookup payload + DNS on %q = %s/%s, want low/tentative", name, sev, conf)
		}
	}
}

// wildXXECallback is the exact out-of-band callback that triggered the reported
// false positive: ginandjuice.shop's own monitoring bot fetched the injected OAST
// URL with a self-identifying User-Agent and an HTTP/2 cleartext upgrade — nothing
// to do with an XML parser dereferencing an external entity.
const wildXXECallback = "GET / HTTP/1.1\r\n" +
	"Host: d997mujaf7ek583c4p00f5uwnu9ajo4y6.oast.vigolium.com\r\n" +
	"Connection: Upgrade, HTTP2-Settings\r\n" +
	"Http2-Settings: AAEAAEAAAAIAAAABAAMAAABkAAQBAAAAAAUAAEAA\r\n" +
	"Upgrade: h2c\r\n" +
	"User-Agent: ginandjuice.shop; support@portswigger.net\r\n" +
	"X-Forwarded-For: 10.0.3.83\r\n\r\n"

// TestLooksLikeHarvestedURLFetch locks in the callback-source fingerprinting that
// separates a genuine server-side XML-parser entity fetch from a crawler / URL-
// preview bot / monitor that harvested the injected OAST URL and visited it.
func TestLooksLikeHarvestedURLFetch(t *testing.T) {
	target := "https://ginandjuice.shop/catalog/product/stock"
	tests := []struct {
		name    string
		raw     string
		target  string
		harvest bool
	}{
		{"reported wild FP (email UA + h2c)", wildXXECallback, target, true},
		{"browser User-Agent", "GET / HTTP/1.1\r\nHost: n.oast\r\nUser-Agent: Mozilla/5.0 (X11) AppleWebKit/537.36 Chrome/149 Safari/537.36\r\n\r\n", target, true},
		{"self-identifying bot", "GET / HTTP/1.1\r\nHost: n.oast\r\nUser-Agent: Slackbot-LinkExpanding 1.0\r\n\r\n", target, true},
		{"link-preview crawler", "GET / HTTP/1.1\r\nHost: n.oast\r\nUser-Agent: facebookexternalhit/1.1\r\n\r\n", target, true},
		{"contact address in UA", "GET / HTTP/1.1\r\nHost: n.oast\r\nUser-Agent: SomeScanner (+admin@evil-monitor.io)\r\n\r\n", target, true},
		{"UA names the target host", "GET / HTTP/1.1\r\nHost: n.oast\r\nUser-Agent: ginandjuice.shop\r\n\r\n", target, true},
		{"h2c upgrade only", "GET / HTTP/1.1\r\nHost: n.oast\r\nUpgrade: h2c\r\n\r\n", target, true},
		{"two browser-only headers", "GET / HTTP/1.1\r\nHost: n.oast\r\nAccept-Language: en-US\r\nSec-Fetch-Mode: navigate\r\n\r\n", target, true},

		// Genuine XML-parser entity fetches — must NOT be flagged.
		{"bare libxml2 fetch (no UA)", "GET /d.dtd HTTP/1.0\r\nHost: n.oast\r\n\r\n", target, false},
		{"Java URL fetch", "GET / HTTP/1.1\r\nHost: n.oast\r\nUser-Agent: Java/1.8.0_292\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n", target, false},
		{"Python-urllib fetch", "GET / HTTP/1.1\r\nHost: n.oast\r\nUser-Agent: Python-urllib/3.9\r\n\r\n", target, false},
		{"curl fetch (ambiguous, not flagged)", "GET / HTTP/1.1\r\nHost: n.oast\r\nUser-Agent: curl/7.68.0\r\n\r\n", target, false},
		{"single benign header", "GET / HTTP/1.1\r\nHost: n.oast\r\nAccept-Language: en-US\r\n\r\n", target, false},
		{"empty request (DNS/fixed-URL)", "", target, false},
	}
	for _, tt := range tests {
		got, reason := looksLikeHarvestedURLFetch(tt.raw, tt.target)
		if got != tt.harvest {
			t.Errorf("%s: looksLikeHarvestedURLFetch = %v (reason %q), want %v", tt.name, got, reason, tt.harvest)
		}
		if got && reason == "" {
			t.Errorf("%s: harvested callback must carry a reason", tt.name)
		}
	}
}

// TestRefineOASTCallbackXXE locks in the second-signal confirmation for XXE: an
// XXE OAST HTTP callback that looks like a harvested-URL fetch is downgraded to
// Low/Tentative UNCONFIRMED, while a bare parser-consistent fetch stays High/Certain
// and DNS interactions are untouched.
func TestRefineOASTCallbackXXE(t *testing.T) {
	xxe := PayloadContext{
		TargetURL:     "https://ginandjuice.shop/catalog/product/stock",
		ParameterName: "body",
		InjectionType: "xxe (external entity)",
		ModuleID:      "xxe-generic",
	}

	// The reported wild FP: HTTP callback from a monitoring bot → downgraded.
	inter := &server.Interaction{Protocol: "http", RawRequest: wildXXECallback}
	sev, conf, desc := refineOASTCallback(inter, xxe, severity.High, severity.Certain, "Blind XXE confirmed")
	if sev.String() != "low" || conf != severity.Tentative {
		t.Fatalf("harvested XXE HTTP callback = %s/%s, want low/tentative", sev, conf)
	}
	if !strings.Contains(desc, "UNCONFIRMED") || !strings.Contains(desc, "XXE") {
		t.Errorf("downgraded XXE finding must be labelled UNCONFIRMED XXE; desc: %s", desc)
	}

	// A bare, parser-consistent HTTP fetch on the same injection → stays High/Certain.
	parser := &server.Interaction{Protocol: "http", RawRequest: "GET /d.dtd HTTP/1.0\r\nHost: n.oast.vigolium.com\r\n\r\n"}
	if sev, conf, _ := refineOASTCallback(parser, xxe, severity.High, severity.Certain, "Blind XXE confirmed"); sev.String() != "high" || conf != severity.Certain {
		t.Errorf("bare parser XXE fetch = %s/%s, want high/certain (untouched)", sev, conf)
	}

	// DNS callbacks carry no request to fingerprint → left as classifyXXE rated them.
	dns := &server.Interaction{Protocol: "dns", RawRequest: ""}
	if sev, conf, _ := refineOASTCallback(dns, xxe, severity.High, severity.Firm, "Blind XXE likely"); sev.String() != "high" || conf != severity.Firm {
		t.Errorf("XXE DNS callback = %s/%s, want high/firm (untouched)", sev, conf)
	}
}

// TestRefineOASTCallbackSiblingClasses verifies the harvested-URL guard now covers
// the other out-of-band classes whose real fetcher is a specific non-browser client
// — JWT jku/x5u (JWKS fetcher), out-of-band SQLi (database engine), and command
// injection (curl/wget) — while leaving fetcher-consistent callbacks alone.
func TestRefineOASTCallbackSiblingClasses(t *testing.T) {
	harvested := &server.Interaction{Protocol: "https", RawRequest: wildXXECallback}

	cases := []struct {
		name    string
		inj     string
		wantLbl string
	}{
		{"jwt jku/x5u", "jwt-header-key-url-injection (header)", "JWT"},
		{"oob sqli", "sql-injection (out-of-band)", "SQL injection"},
		{"command injection", "os-command-injection (parameter)", "OS command injection"},
		{"saml xxe", "XXE (SAML external DTD)", "XXE"},
	}
	for _, tc := range cases {
		pctx := PayloadContext{TargetURL: "https://api.acme.test/x", InjectionType: tc.inj}
		sev, conf, desc := refineOASTCallback(harvested, pctx, severity.High, severity.Certain, "confirmed")
		if sev.String() != "low" || conf != severity.Tentative {
			t.Errorf("%s harvested callback = %s/%s, want low/tentative", tc.name, sev, conf)
		}
		if !strings.Contains(desc, "UNCONFIRMED") || !strings.Contains(desc, tc.wantLbl) {
			t.Errorf("%s: desc must be UNCONFIRMED %q; got %s", tc.name, tc.wantLbl, desc)
		}
	}

	// A fetcher-consistent callback (curl UA for command injection; a JWKS library
	// GET for JWT) must NOT be downgraded.
	curl := &server.Interaction{Protocol: "http", RawRequest: "GET / HTTP/1.1\r\nHost: n.oast\r\nUser-Agent: curl/7.68.0\r\n\r\n"}
	cmdi := PayloadContext{TargetURL: "http://t/run", InjectionType: "os-command-injection (parameter)"}
	if sev, conf, _ := refineOASTCallback(curl, cmdi, severity.Critical, severity.Certain, "confirmed"); sev.String() != "critical" || conf != severity.Certain {
		t.Errorf("curl-UA cmdi callback = %s/%s, want critical/certain (untouched)", sev, conf)
	}
}

// TestRefineOASTCallbackSSRFNarrow verifies generic blind SSRF uses only the narrow
// external-monitor signal: a self-identifying monitor (contact email / target-host
// UA) downgrades to Info/Tentative, but a plain browser UA or h2c handshake does NOT
// (it could be a genuine headless-browser / link-preview-service SSRF).
func TestRefineOASTCallbackSSRFNarrow(t *testing.T) {
	ssrf := PayloadContext{TargetURL: "https://ginandjuice.shop/p", ParameterName: "url", InjectionType: "parameter", ModuleID: "ssrf-blind"}

	// External monitor (the wild UA: contact email + names the target host) → Info.
	monitor := &server.Interaction{Protocol: "http", RawRequest: wildXXECallback}
	if sev, conf, desc := refineOASTCallback(monitor, ssrf, severity.High, severity.Certain, "Blind SSRF confirmed"); sev.String() != "info" || conf != severity.Tentative {
		t.Errorf("external-monitor SSRF callback = %s/%s, want info/tentative; desc: %s", sev, conf, desc)
	}

	// A plain browser / h2c callback must stay High — it may be a real headless-
	// browser or link-preview-service SSRF, which the narrow check must not suppress.
	browser := &server.Interaction{Protocol: "http", RawRequest: "GET / HTTP/1.1\r\nHost: n.oast\r\nUpgrade: h2c\r\nUser-Agent: Mozilla/5.0 Chrome/149 Safari/537.36\r\n\r\n"}
	if sev, conf, _ := refineOASTCallback(browser, ssrf, severity.High, severity.Certain, "Blind SSRF confirmed"); sev.String() != "high" || conf != severity.Certain {
		t.Errorf("browser/h2c SSRF callback = %s/%s, want high/certain (genuine headless-browser SSRF preserved)", sev, conf)
	}

	// An already-Info host-routing SSRF is left untouched (nothing to downgrade to).
	routing := PayloadContext{TargetURL: ssrf.TargetURL, ParameterName: "request-line", InjectionType: "routing-ssrf (request-line)", ModuleID: "routing-ssrf"}
	if sev, _, _ := refineOASTCallback(monitor, routing, severity.Info, severity.Certain, "informational"); sev.String() != "info" {
		t.Errorf("already-Info routing SSRF = %s, want info (untouched)", sev)
	}
}

// TestLooksLikeExternalMonitor pins the narrow SSRF check: only a contact-address UA
// or a UA naming the target host fires; plain browser/bot/h2c signals do not.
func TestLooksLikeExternalMonitor(t *testing.T) {
	target := "https://ginandjuice.shop/p"
	tests := []struct {
		raw  string
		want bool
	}{
		{wildXXECallback, true}, // contact email + names target host
		{"GET / HTTP/1.1\r\nHost: n\r\nUser-Agent: UptimeRobot (+admin@monitor.io)\r\n\r\n", true},
		{"GET / HTTP/1.1\r\nHost: n\r\nUser-Agent: ginandjuice.shop-monitor\r\n\r\n", true},
		{"GET / HTTP/1.1\r\nHost: n\r\nUser-Agent: Mozilla/5.0 Chrome/149\r\n\r\n", false}, // headless-browser SSRF stays
		{"GET / HTTP/1.1\r\nHost: n\r\nUpgrade: h2c\r\n\r\n", false},                       // h2c alone must not fire
		{"", false},
	}
	for i, tt := range tests {
		if got, _ := looksLikeExternalMonitor(tt.raw, target); got != tt.want {
			t.Errorf("case %d: looksLikeExternalMonitor = %v, want %v", i, got, tt.want)
		}
	}
}

// TestClassifyXXEDNSConfidence pins the DNS-only XXE leg at High/Firm (not
// Certain): a bare DNS resolution of the per-payload subdomain carries no request
// to attribute to the XML parser, so it is one notch below the HTTP-fetch leg —
// mirroring the SQLi/JWT out-of-band DNS legs.
func TestClassifyXXEDNSConfidence(t *testing.T) {
	if sev, conf, _ := classifyXXE("dns", "xxe (external entity) via parameter body"); sev.String() != "high" || conf != severity.Firm {
		t.Errorf("classifyXXE(dns) = %s/%s, want high/firm", sev, conf)
	}
	if sev, conf, _ := classifyXXE("http", "xxe (external entity) via parameter body"); sev.String() != "high" || conf != severity.Certain {
		t.Errorf("classifyXXE(http) = %s/%s, want high/certain", sev, conf)
	}
}

// TestCmdiPayloadExpectsHTTP verifies the command→protocol mapping that drives the
// protocol-mismatch guard, including that a hostname embedding a tool name as a
// substring (no trailing space) is never mistaken for the command.
func TestCmdiPayloadExpectsHTTP(t *testing.T) {
	tests := []struct {
		payload         string
		wantKnown       bool
		wantExpectsHTTP bool
	}{
		{";nslookup abc.oast.pro", true, false},
		{"1.2.3.4 & ping -n 1 abc.oast.pro", true, false},
		{";curl http://abc.oast.pro", true, true},
		{";wget -q -O- http://abc.oast.pro", true, true},
		{"", false, false},                              // no payload recorded
		{"plainvalue", false, false},                    // no recognised command
		{"curling.example.com", false, false},           // substring without a command space
		{"sleeping-pingpong.example.com", false, false}, // "ping" embedded in a host, no space
	}
	for _, tt := range tests {
		known, expectsHTTP := cmdiPayloadExpectsHTTP(tt.payload)
		if known != tt.wantKnown || expectsHTTP != tt.wantExpectsHTTP {
			t.Errorf("cmdiPayloadExpectsHTTP(%q) = (%v,%v), want (%v,%v)", tt.payload, known, expectsHTTP, tt.wantKnown, tt.wantExpectsHTTP)
		}
	}
}
