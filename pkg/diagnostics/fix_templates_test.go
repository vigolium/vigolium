package diagnostics

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/nucleitemplates"
)

// TestFixNucleiTemplates_ArchiveAndRefresh: the nuclei fix installs
// the pinned release archive (no git), and `--fix --only nuclei` refreshes
// templates that are already present.
func TestFixNucleiTemplates_ArchiveAndRefresh(t *testing.T) {
	prevOut := fixOut
	fixOut = discard{}
	t.Cleanup(func() { fixOut = prevOut })
	var pins []nucleitemplates.Pin
	prev := installTemplates
	installTemplates = func(_ context.Context, _ string, pin nucleitemplates.Pin) (*nucleitemplates.Marker, error) {
		pins = append(pins, pin)
		return &nucleitemplates.Marker{Version: "v1", SHA256: "abcdef0123456789", InstalledAt: time.Now()}, nil
	}
	t.Cleanup(func() { installTemplates = prev })

	settings := config.DefaultSettings()
	settings.KnownIssueScan.TemplatesVersion = "v10.0.1"
	settings.KnownIssueScan.TemplatesSHA256 = "deadbeef"
	present := claudeMissingReport()
	present.Tools["claude"] = &ToolCheck{Status: StatusOK}

	if res := RunFixes(context.Background(), present, settings, nil); len(res) != 0 || len(pins) != 0 {
		t.Fatalf("bare --fix with templates present = %+v (installs %d), want nothing", res, len(pins))
	}
	res := RunFixes(context.Background(), present, settings, []string{"nuclei"})
	if len(res) != 1 || !res[0].Success || len(pins) != 1 {
		t.Fatalf("--only nuclei = %+v (installs %d), want one refresh", res, len(pins))
	}
	if pins[0].Version != "v10.0.1" || pins[0].SHA256 != "deadbeef" {
		t.Fatalf("pin = %+v, want the configured version and digest", pins[0])
	}
}
