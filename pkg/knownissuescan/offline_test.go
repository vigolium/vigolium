package knownissuescan

import (
	"path/filepath"
	"strings"
	"testing"
)

// --offline never clones the templates; a missing directory fails
// with a provisioning hint.
func TestEnsureTemplatesOfflineNoClone(t *testing.T) {
	calls := fakeClone(t, true)
	err := EnsureTemplates(Config{TemplatesDir: filepath.Join(t.TempDir(), "missing"), Offline: true}, nil)
	if err == nil || !strings.Contains(err.Error(), "--offline") {
		t.Fatalf("err = %v, want an offline error", err)
	}
	if *calls != 0 {
		t.Errorf("clone called %d times under --offline", *calls)
	}
}
