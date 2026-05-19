package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/storage"
)

func TestStorageTreeRender(t *testing.T) {
	objects := []storage.ObjectInfo{
		{Key: "ugc/foo.tar.gz", Size: 1500, LastModified: time.Now()},
		{Key: "ugc/bar.zip", Size: 2048, LastModified: time.Now()},
		{Key: "native-scans/abc123/results.tar.gz", Size: 4096, LastModified: time.Now()},
		{Key: "agentic-scans/run-9/results.tar.gz", Size: 1024, LastModified: time.Now()},
	}

	root := buildStorageTree(objects)

	// Capture stdout
	r, w, _ := os.Pipe()
	orig := os.Stdout
	os.Stdout = w
	printStorageTree(root, "")
	_ = w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	want := []string{
		"agentic-scans",
		"native-scans",
		"ugc",
		"abc123",
		"results.tar.gz",
		"foo.tar.gz",
		"bar.zip",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("tree output missing %q\n--- output ---\n%s", w, out)
		}
	}

	// Top-level dirs should appear before leaves; ugc/ should come after the
	// other two (alphabetical), and ugc/ should render before its file children.
	if i, j := strings.Index(out, "ugc"), strings.Index(out, "foo.tar.gz"); i == -1 || j == -1 || i >= j {
		t.Errorf("expected ugc/ to appear before its leaves; got:\n%s", out)
	}
}
