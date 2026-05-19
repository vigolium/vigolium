package api_spec_ingest

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestNew(t *testing.T) {
	m := New()
	if m.ID() != ModuleID {
		t.Errorf("ID() = %q, want %q", m.ID(), ModuleID)
	}
	if !m.ScanScopes().Has(modkit.ScanScopeRequest) {
		t.Error("expected ScanScopeRequest to be set")
	}
	if len(m.Tags()) == 0 {
		t.Error("expected tags to be set")
	}
}

func TestCanProcess(t *testing.T) {
	m := New()

	if m.CanProcess(nil) {
		t.Error("CanProcess(nil) should return false")
	}

	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequest(rawReq)
	rr := httpmsg.NewHttpRequestResponse(req, nil)
	if !m.CanProcess(rr) {
		t.Error("CanProcess should return true for valid request")
	}
}

func TestIncludesBaseCanProcess(t *testing.T) {
	m := New()
	if m.IncludesBaseCanProcess() {
		t.Error("IncludesBaseCanProcess should return false")
	}
}

func TestProbePaths(t *testing.T) {
	if len(probePaths) == 0 {
		t.Error("probePaths should not be empty")
	}
	// Verify some key paths are present
	has := make(map[string]bool)
	for _, p := range probePaths {
		has[p] = true
	}
	expected := []string{"openapi.json", "swagger.json", "postman_collection.json"}
	for _, exp := range expected {
		if !has[exp] {
			t.Errorf("probePaths missing %q", exp)
		}
	}
}
