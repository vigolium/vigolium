package knownissuescan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/nucleitemplates"
)

// fakeClone replaces the templates install for one test; mkdir decides whether the
// "clone" creates the directory (success) or fails.
func fakeClone(t *testing.T, mkdir bool) *int {
	t.Helper()
	calls := 0
	orig := installTemplates
	installTemplates = func(_ context.Context, dir string, _ nucleitemplates.Pin) ([]byte, error) {
		calls++
		if !mkdir {
			return []byte("fatal: unable to access"), errors.New("exit status 128")
		}
		return nil, os.MkdirAll(dir, 0o755)
	}
	t.Cleanup(func() { installTemplates = orig })
	return &calls
}

type progressLog []string

func (p *progressLog) fn() TemplatesProgress {
	return func(state, _ string, _ error) { *p = append(*p, state) }
}

func TestEnsureTemplatesPresentReportsNothing(t *testing.T) {
	calls := fakeClone(t, true)
	dir := t.TempDir()
	var log progressLog
	if err := EnsureTemplates(Config{TemplatesDir: dir}, log.fn()); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 || len(log) != 0 {
		t.Fatalf("present templates: clone calls=%d progress=%v, want none", *calls, log)
	}
}

func TestEnsureTemplatesClonesWithProgress(t *testing.T) {
	calls := fakeClone(t, true)
	dir := filepath.Join(t.TempDir(), "nuclei-templates")
	var log progressLog
	if err := EnsureTemplates(Config{TemplatesDir: dir}, log.fn()); err != nil {
		t.Fatal(err)
	}
	if *calls != 1 || strings.Join(log, ",") != "started,finished" {
		t.Fatalf("clone calls=%d progress=%v, want 1 and started,finished", *calls, log)
	}
	if !TemplatesPresent(dir) {
		t.Fatal("templates not present after clone")
	}
}

func TestEnsureTemplatesFailureNamesDoctorFix(t *testing.T) {
	fakeClone(t, false)
	dir := filepath.Join(t.TempDir(), "nuclei-templates")
	var log progressLog
	err := EnsureTemplates(Config{TemplatesDir: dir}, log.fn())
	if err == nil {
		t.Fatal("want an error when the clone fails")
	}
	if !strings.Contains(err.Error(), "vigolium doctor --fix --only nuclei") {
		t.Errorf("error %q does not name the fix", err)
	}
	if strings.Join(log, ",") != "started,failed" {
		t.Errorf("progress = %v, want started,failed", log)
	}
}
