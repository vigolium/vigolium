package runner

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestJSEngineOptions_CarryOASTAndProject: the extension engine
// gets the scan's OAST service (vigolium.oast.* was dead in scans) and its
// project.
func TestJSEngineOptions_CarryOASTAndProject(t *testing.T) {
	opts := types.DefaultOptions()
	opts.ScanUUID = "scan-x"
	opts.ProjectUUID = "proj-x"
	settings := config.DefaultSettings()
	r := &Runner{options: opts, settings: settings}
	svc := &oast.Service{}
	got := r.jsEngineOptions(&phaseInfra{oast: svc})
	if got.OASTService != svc {
		t.Error("OASTService not passed to the extension engine")
	}
	if got.ProjectUUID != "proj-x" || got.ScanUUID != "scan-x" {
		t.Errorf("project/scan = %q/%q", got.ProjectUUID, got.ScanUUID)
	}
}
