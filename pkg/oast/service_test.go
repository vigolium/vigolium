package oast

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
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
		sev, desc := classifyInteraction(tt.protocol, pctx)
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
