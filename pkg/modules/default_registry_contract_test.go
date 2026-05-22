package modules

import (
	"regexp"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// kebabCase matches lowercase kebab-case identifiers: alphanumeric segments
// joined by single hyphens (e.g. "sqli-error-based", "cve-2021-44228").
var kebabCase = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func validSeverity(s severity.Severity) bool {
	switch s {
	case severity.Info, severity.Suspect, severity.Low, severity.Medium, severity.High, severity.Critical:
		return true
	}
	return false
}

func validConfidence(c severity.Confidence) bool {
	switch c {
	case severity.Tentative, severity.Firm, severity.Certain:
		return true
	}
	return false
}

// allDefaultModules returns every registered module as the base Module interface,
// tagged with its kind for error messages.
func allDefaultModules() []struct {
	kind string
	mod  Module
} {
	var out []struct {
		kind string
		mod  Module
	}
	for _, m := range DefaultRegistry.GetActiveModules() {
		out = append(out, struct {
			kind string
			mod  Module
		}{"active", m})
	}
	for _, m := range DefaultRegistry.GetPassiveModules() {
		out = append(out, struct {
			kind string
			mod  Module
		}{"passive", m})
	}
	return out
}

// TestDefaultRegistry_ModuleMetadataContract asserts the metadata invariants that
// every built-in module must satisfy. Registration already enforces lowercase and
// within-type uniqueness; this covers the rest.
func TestDefaultRegistry_ModuleMetadataContract(t *testing.T) {
	for _, entry := range allDefaultModules() {
		m := entry.mod
		id := m.ID()

		if id == "" {
			t.Errorf("%s module has empty ID (name=%q)", entry.kind, m.Name())
			continue
		}
		if !kebabCase.MatchString(id) {
			t.Errorf("%s module ID %q is not lowercase kebab-case", entry.kind, id)
		}
		if strings.TrimSpace(m.Name()) == "" {
			t.Errorf("module %q has empty Name()", id)
		}
		if strings.TrimSpace(m.ShortDescription()) == "" {
			t.Errorf("module %q has empty ShortDescription()", id)
		}
		if !validSeverity(m.Severity()) {
			t.Errorf("module %q has invalid severity %d", id, m.Severity())
		}
		if !validConfidence(m.Confidence()) {
			t.Errorf("module %q has invalid confidence %d", id, m.Confidence())
		}
		for _, tag := range m.Tags() {
			if tag == "" {
				t.Errorf("module %q has an empty tag", id)
				continue
			}
			if tag != strings.ToLower(tag) {
				t.Errorf("module %q has non-lowercase tag %q", id, tag)
			}
			if tag != strings.TrimSpace(tag) {
				t.Errorf("module %q has untrimmed tag %q", id, tag)
			}
		}
	}
}

// TestDefaultRegistry_ScanScopesDeclared asserts each module declares at least one
// scan scope appropriate to its kind.
func TestDefaultRegistry_ScanScopesDeclared(t *testing.T) {
	for _, m := range DefaultRegistry.GetActiveModules() {
		if m.ScanScopes() == 0 {
			t.Errorf("active module %q declares no scan scope", m.ID())
		}
	}
	for _, m := range DefaultRegistry.GetPassiveModules() {
		if m.Scope() == 0 {
			t.Errorf("passive module %q declares no passive scan scope", m.ID())
		}
	}
}

// TestDefaultRegistry_NoDuplicateIDsAcrossTypes ensures no ID is shared between an
// active and a passive module (registration only guards within a single type).
func TestDefaultRegistry_NoDuplicateIDsAcrossTypes(t *testing.T) {
	active := map[string]struct{}{}
	for _, m := range DefaultRegistry.GetActiveModules() {
		active[m.ID()] = struct{}{}
	}
	for _, m := range DefaultRegistry.GetPassiveModules() {
		if _, clash := active[m.ID()]; clash {
			t.Errorf("module ID %q is registered as both active and passive", m.ID())
		}
	}
}

// TestDefaultRegistry_CanProcessNoPanic verifies CanProcess tolerates a minimal,
// well-formed request without panicking.
func TestDefaultRegistry_CanProcessNoPanic(t *testing.T) {
	rr, err := httpmsg.ParseRawRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if err != nil {
		t.Fatalf("build minimal request: %v", err)
	}

	for _, entry := range allDefaultModules() {
		m := entry.mod
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s module %q panicked in CanProcess: %v", entry.kind, m.ID(), r)
				}
			}()
			_ = m.CanProcess(rr)
		}()
	}
}
