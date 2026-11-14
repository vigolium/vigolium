package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// statelessHomeAllowlist are the HOME subtrees a -S scan may still touch: the
// embedded nuclei/uncover libraries create their config directories at
// package init, before vigolium parses a flag (documented limitation).
var statelessHomeAllowlist = []string{
	filepath.Join("Library", "Application Support", "nuclei"),
	filepath.Join("Library", "Application Support", "uncover"),
	filepath.Join(".config", "nuclei"),
	filepath.Join(".config", "uncover"),
}

func snapshotTree(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		out[rel] = true
		return nil
	})
	return out
}

// TestStatelessScanWritesNothingToHome is RUN-3: a -S scan adds nothing under
// HOME but the nuclei/uncover package-init directories, and still completes
// when HOME is read-only.
func TestStatelessScanWritesNothingToHome(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	srv, hits := countingServer(t)
	target := srv.URL + "/"

	cases := map[string][]string{
		"scan-url -S": {"scan-url", target, "-S", "-j", "-m", "security-headers-missing"},
		"scan -S":     {"scan", "-t", target, "-S", "-j", "--only", "dynamic-assessment", "-m", "security-headers-missing"},
	}
	for name, args := range cases {
		for _, readOnly := range []bool{false, true} {
			name := name
			if readOnly {
				name += " read-only HOME"
			}
			runStatelessHomeCase(t, name, args, readOnly, hits)
		}
	}
}

// runStatelessHomeCase runs one -S scan: with a writable HOME it asserts no
// path appeared outside the allowlist (a read-only HOME would hide a write
// attempt as a silent failure); with a read-only HOME it asserts the scan
// still completes.
func runStatelessHomeCase(t *testing.T, name string, args []string, readOnly bool, hits interface{ Load() int64 }) {
	t.Run(name, func(t *testing.T) {
		home := t.TempDir()
		// The config is read (allowed); OAST off keeps the run local.
		dir := filepath.Join(home, ".vigolium")
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "vigolium-configs.yaml"), []byte(noOASTConfig), 0o600))
		for _, a := range statelessHomeAllowlist {
			require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(home, a)), 0o755))
		}
		before := snapshotTree(t, home)
		if readOnly {
			for _, d := range []string{home, dir} {
				require.NoError(t, os.Chmod(d, 0o555))
			}
			t.Cleanup(func() {
				_ = os.Chmod(home, 0o755)
				_ = os.Chmod(dir, 0o755)
			})
		}

		code, stdout, stderr := runA3(t, home, args...)
		require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
		require.NotZero(t, hits.Load(), "the target was scanned")

		for path := range snapshotTree(t, home) {
			if before[path] {
				continue
			}
			allowed := false
			for _, a := range statelessHomeAllowlist {
				if path == a || strings.HasPrefix(path, a+string(filepath.Separator)) {
					allowed = true
				}
			}
			require.True(t, allowed, "-S wrote %s under HOME\nstderr:\n%s", path, stderr)
		}
	})
}
