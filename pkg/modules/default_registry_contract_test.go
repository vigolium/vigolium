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

// requiredDescSections are the labels every built-in module's Description() must
// carry. The executor composes this block onto each finding (see
// core.assignModuleInfo) so the report explains what the finding means and how it
// is exploited; keeping it enforced here stops new modules from drifting back to a
// one-line description.
var requiredDescSections = []string{"**What it means:**", "**How it's exploited:**", "**Fix:**"}

// maxDescWords bounds the explanation block so the composed finding description
// (per-finding context line + this block) stays concise in reports.
const maxDescWords = 100

// TestDefaultRegistry_DescriptionFormatContract asserts every built-in module's
// Description() is a reader-facing What/Exploit/Fix block within the word budget.
func TestDefaultRegistry_DescriptionFormatContract(t *testing.T) {
	for _, entry := range allDefaultModules() {
		m := entry.mod
		desc := m.Description()
		if strings.TrimSpace(desc) == "" {
			t.Errorf("module %q has empty Description()", m.ID())
			continue
		}
		for _, label := range requiredDescSections {
			if !strings.Contains(desc, label) {
				t.Errorf("module %q Description() is missing the %q section", m.ID(), label)
			}
		}
		if n := len(strings.Fields(desc)); n > maxDescWords {
			t.Errorf("module %q Description() is %d words, over the %d-word budget", m.ID(), n, maxDescWords)
		}
	}
}

// deliberatelyAlwaysOnActiveModules are the active modules that intentionally
// carry no intensity-tier tag so they run at every intensity (the tier gate
// treats an untagged module as TierAlwaysOn). These are core confirmation
// modules that must always run; every other active module must declare an
// explicit tier so a forgotten tag can't silently make a heavy framework probe
// run at `quick`. Keep this list short and justified.
var deliberatelyAlwaysOnActiveModules = map[string]string{
	"xss-stored":      "core stored-XSS confirmation must run at every intensity",
	"xss-dom-confirm": "core DOM-XSS confirmation must run at every intensity",
}

// TestDefaultRegistry_ActiveModuleTierDeclared asserts every active module either
// declares an explicit intensity tier (light/moderate/heavy/intrusive) or is in
// the documented always-on waiver list. This prevents the failure mode where a
// new framework probe ships without a tier tag and, defaulting to TierAlwaysOn,
// runs even in a `quick` scan.
func TestDefaultRegistry_ActiveModuleTierDeclared(t *testing.T) {
	for _, m := range DefaultRegistry.GetActiveModules() {
		id := m.ID()
		if ModuleTierRank(m.Tags()) != TierAlwaysOn {
			continue
		}
		if _, waived := deliberatelyAlwaysOnActiveModules[id]; waived {
			continue
		}
		t.Errorf("active module %q declares no intensity tier (light/moderate/heavy/intrusive); "+
			"add one to its ModuleTags, or add it to deliberatelyAlwaysOnActiveModules with a justification", id)
	}
}

// TestDefaultRegistry_TierWaiverListIsCurrent guards against the waiver list
// going stale: every ID it names must still be a registered active module that
// is in fact untagged. A waiver for a module that has since gained a tier (or
// been removed) is a lie that should be cleaned up.
func TestDefaultRegistry_TierWaiverListIsCurrent(t *testing.T) {
	active := map[string]Module{}
	for _, m := range DefaultRegistry.GetActiveModules() {
		active[m.ID()] = m
	}
	for id := range deliberatelyAlwaysOnActiveModules {
		m, ok := active[id]
		if !ok {
			t.Errorf("tier waiver names %q, which is not a registered active module", id)
			continue
		}
		if ModuleTierRank(m.Tags()) != TierAlwaysOn {
			t.Errorf("tier waiver names %q, but it now declares a tier — remove the waiver", id)
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

// TestDefaultRegistry_TentativeImpliesSuspect: a module whose default
// confidence is Tentative declares an unproven oracle, so its default severity
// must be Suspect or below — unless it is on TentativeSeverityWaivers with a
// reason.
func TestDefaultRegistry_TentativeImpliesSuspect(t *testing.T) {
	for _, entry := range allDefaultModules() {
		m := entry.mod
		if m.Confidence() == severity.Tentative && m.Severity() > severity.Suspect && !TentativeSeverityWaived(m.ID()) {
			t.Errorf("%s module %q is Tentative but %s: an unproven oracle files Suspect "+
				"(fix the metadata, or add a reasoned entry to TentativeSeverityWaivers)",
				entry.kind, m.ID(), m.Severity())
		}
	}
}

// TestTentativeSeverityWaiversCurrent keeps the waiver list honest: every entry
// names a registered module and carries a reason.
func TestTentativeSeverityWaiversCurrent(t *testing.T) {
	registered := map[string]bool{}
	for _, entry := range allDefaultModules() {
		registered[entry.mod.ID()] = true
	}
	for id, reason := range TentativeSeverityWaivers {
		if !registered[id] {
			t.Errorf("waiver %q names no registered module (stale entry)", id)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("waiver %q has no reason", id)
		}
	}
}
