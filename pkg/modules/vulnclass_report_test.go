package modules

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/vulnclass"
)

// Every registered module declares its reported class (vuln_class on finding
// and module rows), and the declaration table names no module that is not
// registered: a new module cannot ship unclassified, and a renamed one cannot
// leave a stale row behind.
func TestEveryModuleDeclaresReportedVulnClass(t *testing.T) {
	declared := vulnclass.DeclaredModules()
	registered := map[string]bool{}
	check := func(id string) {
		registered[id] = true
		c, ok := declared[id]
		if !ok {
			t.Errorf("module %q has no reported class: add it to pkg/vulnclass/modules.go", id)
			return
		}
		if !c.Valid() {
			t.Errorf("module %q declares %q, which is not in the vulnclass vocabulary", id, c)
		}
	}
	for _, m := range DefaultRegistry.GetActiveModules() {
		check(m.ID())
	}
	for _, m := range DefaultRegistry.GetPassiveModules() {
		check(m.ID())
	}
	for id := range declared {
		if !registered[id] {
			t.Errorf("pkg/vulnclass/modules.go declares %q, which is not a registered module", id)
		}
	}
}

// The blind (out-of-band) XSS module is distinguishable from reflected and
// stored XSS: they are different proofs.
func TestReportedVulnClassSeparatesXSSKinds(t *testing.T) {
	for id, want := range map[string]vulnclass.Class{
		"blind-xss-oast":       vulnclass.XSSBlind,
		"xss-light-url-params": vulnclass.XSSReflected,
		"xss-stored":           vulnclass.XSSStored,
		"xss-dom-confirm":      vulnclass.XSSDOM,
		"dom-xss-detect":       vulnclass.XSSDOM,
	} {
		if got := vulnclass.ForModule(id); got != want {
			t.Errorf("ForModule(%q) = %q, want %q", id, got, want)
		}
	}
}
