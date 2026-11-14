package discovery

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
)

// MISS-5: a confirmed extension is swept with the short file list in every
// known directory, not only at the start path, so /admin/upload.php is
// guessed. The long list × extension stays at the start path.
func TestFactory_DynamicExtensionShortListPerDirectory(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "short.txt")
	long := filepath.Join(dir, "long.txt")
	if err := os.WriteFile(short, []byte("upload\nindex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(long, []byte("backup\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := factoryTestConfig()
	cfg.Filenames.Wordlists.ShortFilePath = short
	cfg.Filenames.Wordlists.LongFilePath = long
	f := NewFactory(cfg)

	tasks := f.CreateDynamicExtensionTasks("php",
		[]string{"http://example.com/", "http://example.com/admin/"},
		payload.NewObservedProvider(true), 1)

	var shortURLs, longURLs []string
	for _, task := range tasks {
		wt, ok := task.(*WordlistTask)
		if !ok {
			continue
		}
		switch wt.TaskType() {
		case ShortFilesObservedExt:
			shortURLs = append(shortURLs, collectURLs(t, wt)...)
		case LongFilesObservedExt:
			longURLs = append(longURLs, collectURLs(t, wt)...)
		}
	}
	for _, want := range []string{"http://example.com/upload.php", "http://example.com/admin/upload.php"} {
		if !slices.Contains(shortURLs, want) {
			t.Errorf("short list × .php missing %s; got %v", want, shortURLs)
		}
	}
	if !slices.Equal(longURLs, []string{"http://example.com/backup.php"}) {
		t.Errorf("long list × .php must stay at the start path; got %v", longURLs)
	}

	// The recursion path builds the same task for a recursed directory, so the
	// queue's hash dedup collapses the two.
	rec := f.CreateShortFileExtensionTasks([]byte("http://example.com"), []byte("/admin/"), 1, []string{"php"})
	if len(rec) != 1 {
		t.Fatalf("want 1 recursion task, got %d", len(rec))
	}
	found := false
	for _, task := range tasks {
		if task.Hash() == rec[0].Hash() {
			found = true
		}
	}
	if !found {
		t.Error("recursion and dynamic-extension tasks for /admin/ × php must share a hash")
	}
}
