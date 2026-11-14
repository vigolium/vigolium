package knownissuescan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/paths"
	"github.com/vigolium/vigolium/pkg/nucleitemplates"
)

// TestEnsureTemplatesStatelessFailsClosed: a -S scan never clones
// templates; it fails with the way out.
func TestEnsureTemplatesStatelessFailsClosed(t *testing.T) {
	paths.EnableStateless(t.TempDir())
	t.Cleanup(func() { paths.EnableStateless("") })
	orig := cloneTemplates
	cloneTemplates = func(context.Context, string, nucleitemplates.Pin) ([]byte, error) {
		t.Fatal("stateless scan cloned templates")
		return nil, nil
	}
	t.Cleanup(func() { cloneTemplates = orig })

	err := EnsureTemplates(Config{TemplatesDir: filepath.Join(t.TempDir(), "absent")}, nil)
	if err == nil || !strings.Contains(err.Error(), "doctor --fix --only nuclei") {
		t.Fatalf("EnsureTemplates = %v, want a fail-closed error naming the fix", err)
	}
}
