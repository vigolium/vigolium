package runner

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
)

// The extension engine gets the scan's project, so what an extension
// stores (vigolium.ingest → SaveRecord) lands in that project.
func TestJSEngineOptionsCarryProject(t *testing.T) {
	opts := types.DefaultOptions()
	opts.ProjectUUID = "proj-123"
	opts.ScanUUID = "scan-1"
	r := &Runner{options: opts, settings: config.DefaultSettings()}
	got := r.jsEngineOptions(&phaseInfra{})
	if got.ProjectUUID != "proj-123" || got.ScanUUID != "scan-1" {
		t.Errorf("engine options = project %q scan %q, want proj-123 / scan-1", got.ProjectUUID, got.ScanUUID)
	}
	if got.ScopeConfig == nil {
		t.Error("scope config must be carried")
	}
}
