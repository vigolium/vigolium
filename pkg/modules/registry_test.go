package modules

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// stubModule implements Module for testing.
type stubModule struct {
	id   string
	name string
	tags []string
}

func (s stubModule) ID() string                                     { return s.id }
func (s stubModule) Name() string                                   { return s.name }
func (s stubModule) Description() string                            { return "" }
func (s stubModule) ShortDescription() string                       { return "" }
func (s stubModule) ConfirmationCriteria() string                   { return "" }
func (s stubModule) Severity() severity.Severity                    { return severity.Info }
func (s stubModule) Confidence() severity.Confidence                { return severity.Tentative }
func (s stubModule) CanProcess(r *httpmsg.HttpRequestResponse) bool { return true }
func (s stubModule) ScanScopes() ScanScope                           { return 0 }
func (s stubModule) Tags() []string                                  { return s.tags }

// stubActive wraps stubModule to satisfy ActiveModule.
type stubActive struct{ stubModule }

func (s stubActive) AllowedInsertionPointTypes() InsertionPointTypeSet { return AllInsertionPointTypes }
func (s stubActive) ScanPerInsertionPoint(_ *httpmsg.HttpRequestResponse, _ httpmsg.InsertionPoint, _ *http.Requester, _ *ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (s stubActive) ScanPerRequest(_ *httpmsg.HttpRequestResponse, _ *http.Requester, _ *ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (s stubActive) ScanPerHost(_ *httpmsg.HttpRequestResponse, _ *http.Requester, _ *ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

// stubPassive wraps stubModule to satisfy PassiveModule.
type stubPassive struct{ stubModule }

func (s stubPassive) Scope() PassiveScanScope { return 0 }
func (s stubPassive) ScanPerRequest(_ *httpmsg.HttpRequestResponse, _ *ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (s stubPassive) ScanPerHost(_ *httpmsg.HttpRequestResponse, _ *ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func buildTestRegistry() *Registry {
	r := NewRegistry()
	r.RegisterActive(stubActive{stubModule{id: "sqli-error-based", name: "SQLi Error Based Scanner", tags: []string{"injection", "sqli"}}})
	r.RegisterActive(stubActive{stubModule{id: "sqli-boolean-blind", name: "SQLi Boolean Blind Scanner", tags: []string{"injection", "sqli", "heavy"}}})
	r.RegisterActive(stubActive{stubModule{id: "xss-reflected", name: "Reflected XSS Scanner", tags: []string{"injection", "xss"}}})
	r.RegisterActive(stubActive{stubModule{id: "cors-misconfiguration", name: "CORS Misconfiguration Scanner", tags: []string{"misconfiguration", "header-security"}}})
	r.RegisterPassive(stubPassive{stubModule{id: "csp-header", name: "CSP Header Analyzer", tags: []string{"header-security", "light"}}})
	r.RegisterPassive(stubPassive{stubModule{id: "jwt-claims-detect", name: "JWT Claims Detector", tags: []string{"authentication", "session"}}})
	return r
}

func TestResolveModulePatterns_ExactMatch(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModulePatterns([]string{"sqli-error-based"})
	if len(got) != 1 || got[0] != "sqli-error-based" {
		t.Fatalf("expected exact match, got %v", got)
	}
}

func TestResolveModulePatterns_SubstringID(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModulePatterns([]string{"sqli"})
	if len(got) != 2 {
		t.Fatalf("expected 2 sqli modules, got %v", got)
	}
}

func TestResolveModulePatterns_SubstringName(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModulePatterns([]string{"reflected"})
	if len(got) != 1 || got[0] != "xss-reflected" {
		t.Fatalf("expected reflected xss module, got %v", got)
	}
}

func TestResolveModulePatterns_CaseInsensitive(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModulePatterns([]string{"CORS"})
	if len(got) != 1 || got[0] != "cors-misconfiguration" {
		t.Fatalf("expected cors module, got %v", got)
	}
}

func TestResolveModulePatterns_MultiplePatterns(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModulePatterns([]string{"xss", "jwt"})
	if len(got) != 2 {
		t.Fatalf("expected 2 modules, got %v", got)
	}
}

func TestResolveModulePatterns_All(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModulePatterns([]string{"all"})
	if len(got) != 1 || got[0] != "all" {
		t.Fatalf("expected [all], got %v", got)
	}
}

func TestResolveModulePatterns_Empty(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModulePatterns(nil)
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestResolveModulePatterns_NoMatch(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModulePatterns([]string{"nonexistent"})
	if len(got) != 0 {
		t.Fatalf("expected empty for no match, got %v", got)
	}
}

func TestResolveModulePatterns_Dedup(t *testing.T) {
	r := buildTestRegistry()
	// "sqli" and "error" both match active-sqli-error-based
	got := r.ResolveModulePatterns([]string{"sqli", "error"})
	counts := make(map[string]int)
	for _, id := range got {
		counts[id]++
	}
	for id, c := range counts {
		if c > 1 {
			t.Fatalf("duplicate ID %q in results", id)
		}
	}
}

func TestResolveModulePatterns_MatchesPassive(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModulePatterns([]string{"csp"})
	if len(got) != 1 || got[0] != "csp-header" {
		t.Fatalf("expected passive csp module, got %v", got)
	}
}

func TestResolveModuleTags_SingleTag(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModuleTags([]string{"sqli"})
	if len(got) != 2 {
		t.Fatalf("expected 2 sqli-tagged modules, got %v", got)
	}
}

func TestResolveModuleTags_OR(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModuleTags([]string{"xss", "authentication"})
	if len(got) != 2 {
		t.Fatalf("expected 2 modules (xss + authentication), got %v", got)
	}
}

func TestResolveModuleTags_CaseInsensitive(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModuleTags([]string{"INJECTION"})
	if len(got) != 3 {
		t.Fatalf("expected 3 injection-tagged modules, got %v", got)
	}
}

func TestResolveModuleTags_CrossType(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModuleTags([]string{"header-security"})
	if len(got) != 2 {
		t.Fatalf("expected 2 header-security modules (active + passive), got %v", got)
	}
}

func TestResolveModuleTags_NoMatch(t *testing.T) {
	r := buildTestRegistry()
	got := r.ResolveModuleTags([]string{"nonexistent"})
	if len(got) != 0 {
		t.Fatalf("expected empty for no match, got %v", got)
	}
}
