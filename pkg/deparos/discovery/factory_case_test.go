package discovery

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/config"
)

func shortFileURLs(t *testing.T, f *Factory) []string {
	t.Helper()
	tasks, err := f.CreateInitialTasks([]byte("http://example.com/"), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		if wt, ok := task.(*WordlistTask); ok && wt.TaskType() == ShortFilesNoExt {
			return collectURLs(t, wt)
		}
	}
	t.Fatal("no short-file task")
	return nil
}

// Wordlists keep their case until the host is known case-insensitive,
// so WEB-INF is actually sent; a case-insensitive host gets the folded list.
func TestFactory_WordlistCaseFollowsDetection(t *testing.T) {
	list := filepath.Join(t.TempDir(), "files.txt")
	if err := os.WriteFile(list, []byte("WEB-INF\nweb-inf\nWEB-INF\nMakefile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := factoryTestConfig()
	cfg.Engine.CaseSensitivity = config.CaseAutoDetect
	cfg.Filenames.Wordlists.ShortFilePath = list
	cfg.Extensions.CustomList = nil
	f := NewFactory(cfg)

	mode := config.CaseAutoDetect
	f.SetCaseModeSource(func(bool) config.CaseSensitivityMode { return mode })

	got := shortFileURLs(t, f)
	want := []string{"http://example.com/WEB-INF", "http://example.com/web-inf", "http://example.com/Makefile"}
	if !slices.Equal(got, want) {
		t.Fatalf("undetected host: got %v, want %v (original case, exact dedup)", got, want)
	}

	mode = config.CaseInsensitive
	got = shortFileURLs(t, f)
	want = []string{"http://example.com/web-inf", "http://example.com/makefile"}
	if !slices.Equal(got, want) {
		t.Fatalf("insensitive host: got %v, want %v (folded)", got, want)
	}
}
