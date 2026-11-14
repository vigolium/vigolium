package secret_detect

import (
	"strings"
	"testing"
)

// TestModuleDescMakesNoLiveValidationClaim: the detector never validates a
// secret against its service, so the description must not promise it.
func TestModuleDescMakesNoLiveValidationClaim(t *testing.T) {
	if strings.Contains(strings.ToLower(ModuleDesc), "live-validated") {
		t.Fatal("ModuleDesc promises live validation that the detector does not perform")
	}
}
