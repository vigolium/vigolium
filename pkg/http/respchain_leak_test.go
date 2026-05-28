package http

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fullResponseCall matches a bare `.FullResponse(` call but not the non-pooled
// `.FullResponseString(` / `.FullResponseBytes(` accessors.
var fullResponseCall = regexp.MustCompile(`\.FullResponse\(`)

// TestNoPooledFullResponseAccessor guards against a scan-wide deadlock.
//
// ResponseChain.FullResponse() checks a buffer out of projectdiscovery's
// global, fixed-size pool (10000, not resizable at runtime here) and returns it
// with no way to give it back — putBuffer is unexported, and GC does not release
// the pool's semaphore permit. Every call therefore leaks one buffer. With many
// module call sites doing resp.FullResponse().String()/.Bytes() per request, a
// long scan drained the pool; getBuffer() then blocks forever on a
// non-cancellable context.Background(), wedging the whole scan (first caught
// mid-canary, where leaks from several scans in one process added up).
//
// Production code must read the response via the non-pooled
// FullResponseString()/FullResponseBytes() instead. This test fails if any
// non-test source under pkg/ or internal/ reintroduces the pooled accessor.
func TestNoPooledFullResponseAccessor(t *testing.T) {
	root := repoRoot(t)

	var offenders []string
	for _, top := range []string{"pkg", "internal"} {
		base := filepath.Join(root, top)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == "platform" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			for i, line := range strings.Split(string(b), "\n") {
				if fullResponseCall.MatchString(line) {
					rel, _ := filepath.Rel(root, path)
					offenders = append(offenders, rel+":"+itoa(i+1))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}

	if len(offenders) > 0 {
		t.Errorf("found %d use(s) of the pool-leaking ResponseChain.FullResponse(); "+
			"use FullResponseString()/FullResponseBytes() instead:\n  %s",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate go.mod above the test working directory")
		}
		dir = parent
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
