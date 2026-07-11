package jstangle

import (
	"context"
	"errors"
	"testing"
)

func TestCapabilitiesSupportsProfile(t *testing.T) {
	// A helper that advertises no profiles is treated as supporting everything so
	// an older capability record never regresses a working profile.
	var empty *Capabilities
	if !empty.SupportsProfile(ProfileBeautify) {
		t.Errorf("nil capabilities should be lenient")
	}
	none := &Capabilities{}
	if !none.SupportsProfile(ProfileDOMSecurity) {
		t.Errorf("empty profile list should be lenient")
	}

	// A modern helper that advertises a list gates strictly against it.
	caps := &Capabilities{Profiles: []string{"legacy", "endpoints", "discovery"}}
	if !caps.SupportsProfile(ProfileLegacy) {
		t.Errorf("advertised profile should be supported")
	}
	if caps.SupportsProfile(ProfileBeautify) {
		t.Errorf("unadvertised profile must not be reported as supported")
	}
	if caps.SupportsProfile(ProfileDOMSecurity) {
		t.Errorf("unadvertised dom-security profile must not be reported as supported")
	}
}

// profileGatedBackend advertises a fixed profile list and records whether a scan
// was ever dispatched, so we can assert the handshake short-circuits before the
// worker.
type profileGatedBackend struct {
	profiles []string
	scanned  bool
}

func (b *profileGatedBackend) ScanWithOptions(_ context.Context, _ []byte, _ ScanOptions) (*ScanResult, error) {
	b.scanned = true
	return &ScanResult{Analysis: &AnalysisResultV2{SchemaVersion: 2}}, nil
}

func (b *profileGatedBackend) Capabilities() (*Capabilities, error) {
	return &Capabilities{Type: "capabilities", ProtocolVersion: ProtocolVersion, SourceHash: "h", Profiles: b.profiles}, nil
}

func TestAnalyzeRejectsUnsupportedProfile(t *testing.T) {
	backend := &profileGatedBackend{profiles: []string{"legacy", "endpoints", "discovery"}}
	service := testService(backend, 4, 1024*1024)
	defer func() { _ = service.Close() }()

	_, err := service.ScanWithOptions(context.Background(), []byte(`location.hash`), ScanOptions{Profile: ProfileBeautify})
	if !errors.Is(err, ErrUnsupportedProfile) {
		t.Fatalf("expected ErrUnsupportedProfile, got %v", err)
	}
	if backend.scanned {
		t.Errorf("worker should not be dispatched for an unsupported profile")
	}

	// A supported profile still dispatches normally.
	backend.scanned = false
	if _, err := service.ScanWithOptions(context.Background(), []byte(`fetch('/api')`), ScanOptions{Profile: ProfileDiscovery}); err != nil {
		t.Fatalf("supported profile scan: %v", err)
	}
	if !backend.scanned {
		t.Errorf("worker should be dispatched for a supported profile")
	}
}
