//go:build e2e

package e2eexpect

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestStateDirKeepsHomeEmpty: with VIGOLIUM_STATE_DIR set, `version -j`,
// `config ls -j` and a `scan --dry-run` write nothing under HOME — not the
// config, the database, presets, the init marker, nor the embedded nuclei,
// uncover and goimports directories those libraries create at package init —
// and everything they did write is under the state dir. The dry run names a
// loopback target and sends nothing.
func TestStateDirKeepsHomeEmpty(t *testing.T) {
	bin := vigoliumBin(t)
	dir := t.TempDir()
	home, state, tmp := filepath.Join(dir, "home"), filepath.Join(dir, "state"), filepath.Join(dir, "tmp")
	for _, d := range []string{home, state, tmp} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	env := []string{
		"HOME=" + home, "USERPROFILE=" + home, "TMPDIR=" + tmp, "NO_COLOR=1",
		"VIGOLIUM_DISABLE_UPDATE_CHECK=1", "VIGOLIUM_STATE_DIR=" + state,
		"PATH=" + os.Getenv("PATH"),
	}

	for _, argv := range [][]string{
		{"version", "-j"},
		{"config", "ls", "-j"},
		{"scan", "-t", "http://127.0.0.1:9/", "--dry-run", "-j"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cmd := exec.CommandContext(ctx, bin, argv...)
		cmd.Env = env
		cmd.Dir = tmp
		out, err := cmd.CombinedOutput()
		cancel()
		require.NoErrorf(t, err, "vigolium %s\n%s", strings.Join(argv, " "), out)
	}

	var underHome []string
	require.NoError(t, filepath.WalkDir(home, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != home {
			underHome = append(underHome, strings.TrimPrefix(p, home))
		}
		return nil
	}))
	require.Emptyf(t, underHome, "vigolium wrote under HOME with VIGOLIUM_STATE_DIR set")

	for _, rel := range []string{"vigolium-configs.yaml", "database-vgnm.sqlite", filepath.Join("lib", "nuclei")} {
		_, err := os.Stat(filepath.Join(state, rel))
		require.NoErrorf(t, err, "%s is not under the state dir", rel)
	}
}
