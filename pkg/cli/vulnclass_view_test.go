package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/vulnclass"
)

// Every `module ls -j` row names its reported class, and blind XSS is not
// reflected XSS.
func TestModuleLsRowsCarryVulnClass(t *testing.T) {
	opts := &moduleOptions{ModuleType: "all"}
	doc := emitCaptured(t, func() error { return printModuleJSON(moduleLsCmd, opts, "") })
	items := requireEnvelope(t, doc, "module ls", "read")
	byID := map[string]string{}
	for _, it := range items {
		row := it.(map[string]any)
		vc, _ := row["vuln_class"].(string)
		require.NotEmpty(t, vc, "module %v has no vuln_class", row["id"])
		require.True(t, vulnclass.Class(vc).Valid(), "module %v: %q is not in the vocabulary", row["id"], vc)
		byID[row["id"].(string)] = vc
	}
	require.Equal(t, "xss_blind", byID["blind-xss-oast"])
	require.Equal(t, "xss_reflected", byID["xss-light-url-params"])
}

// `finding -j` carries vuln_class and, when the emit-time rule filed the
// finding lower than the module asked, claimed_severity. A row stored before
// the column existed falls back to the module's declared class.
func TestFindingViewCarriesVulnClassAndClaimedSeverity(t *testing.T) {
	var f database.Finding
	require.NoError(t, f.FromResultEvent(&output.ResultEvent{
		ModuleID: "sqli-boolean-blind",
		Info:     output.Info{Name: "SQLi", Severity: severity.Suspect, Confidence: severity.Tentative},
		URL:      "https://app.test/?id=1",
		Metadata: map[string]any{"claimed_severity": "high"},
	}))
	v := compactFindingView(&f, nil, agentViewOptions{})
	require.Equal(t, "sqli", v["vuln_class"])
	require.Equal(t, "high", v["claimed_severity"])
	require.Equal(t, "suspect", v["severity"])

	legacy := &database.Finding{ModuleID: "blind-xss-oast", Severity: "high", Confidence: "firm"}
	v = compactFindingView(legacy, nil, agentViewOptions{})
	require.Equal(t, "xss_blind", v["vuln_class"])
	require.NotContains(t, v, "claimed_severity")

	imported := &database.Finding{ModuleID: "CVE-2024-0001-template", Severity: "high", Confidence: "firm"}
	require.NotContains(t, compactFindingView(imported, nil, agentViewOptions{}), "vuln_class")

	// Both are selectable --fields names.
	require.NoError(t, validateFieldSelection([]string{"vuln_class", "claimed_severity"}, findingViewFields))
}
