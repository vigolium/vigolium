package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// "No implicit work": `scan` / `run <phase>` with no target used to fall through
// to a rescan of every HTTP record in the database. These tests pin the
// contract that replaced it: --all-records is required (a usage error, exit 2,
// otherwise), it must stand alone, and a TTY keeps the old fallback for one
// release behind a deprecation warning.

// a2ChildEnv carries the argv for the re-exec'd child, separated by \x1f.
const a2ChildEnv = "VIGOLIUM_A2_SCAN_ARGS"

// a2DBScanMarker is printed by the child's runDBScanFn stub, so the parent can
// tell "reached the database rescan" from "rejected before it".
const a2DBScanMarker = "A2-DBSCAN-REACHED"

// TestScanNoTargetChild is the child half of runA2Scan: it runs the real
// Execute() (cobra parse, PersistentPreRunE, exit-code mapping) with the
// database rescan stubbed out, so no runner, OAST client or network is touched.
func TestScanNoTargetChild(t *testing.T) {
	raw := os.Getenv(a2ChildEnv)
	if raw == "" {
		t.Skip("child process helper")
	}
	runDBScanFn = func(*config.Settings, *database.DB, *database.Repository, time.Time) error {
		fmt.Fprintln(os.Stderr, a2DBScanMarker)
		return nil
	}
	os.Args = append([]string{"vigolium"}, strings.Split(raw, "\x1f")...)
	Execute()
	os.Exit(0)
}

// runA2Scan re-execs the test binary as `vigolium <args...>` with stdin on
// /dev/null (exec.Cmd's default), stdout/stderr on pipes (so not a TTY), and a
// throwaway HOME whose first-run marker is already present (so the dependency
// bootstrap never downloads anything).
func runA2Scan(t *testing.T, args ...string) (exitCode int, stdout, stderr string) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".vigolium"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".vigolium", initMarkerFileName), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(home, "a2.sqlite")
	full := append([]string{"--db", db}, args...)

	cmd := exec.Command(os.Args[0], "-test.run=^TestScanNoTargetChild$", "-test.v=false")
	env := []string{a2ChildEnv + "=" + strings.Join(full, "\x1f"), "HOME=" + home, "NO_COLOR=1"}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "VIGOLIUM_") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String(), errb.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errb.String()
	default:
		t.Fatalf("run child: %v", err)
		return -1, "", ""
	}
}

func TestBareScanIsAUsageError(t *testing.T) {
	cases := map[string][]string{
		"scan":                   {"scan"},
		"run dynamic-assessment": {"run", "dynamic-assessment"},
		"scan -j":                {"scan", "-j"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runA2Scan(t, args...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2 (usage)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if strings.Contains(stderr, a2DBScanMarker) {
				t.Fatal("a bare scan must not reach the database rescan")
			}
			all := stdout + stderr
			if !strings.Contains(all, "--all-records") {
				t.Errorf("the error must name --all-records, got:\n%s", all)
			}
			if !strings.Contains(all, "a2.sqlite") {
				t.Errorf("the error must name the resolved database, got:\n%s", all)
			}
		})
	}
}

func TestAllRecordsReachesTheDatabaseRescan(t *testing.T) {
	code, stdout, stderr := runA2Scan(t, "run", "dast", "--all-records")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, a2DBScanMarker) {
		t.Fatalf("run dast --all-records must reach runDBScan, stderr:\n%s", stderr)
	}
}

func TestAllRecordsWithATargetIsAUsageError(t *testing.T) {
	for name, args := range map[string][]string{
		"-t":   {"scan", "--all-records", "-t", "http://127.0.0.1:1"},
		"-i":   {"scan", "--all-records", "-i", "-"},
		"-S":   {"scan", "--all-records", "-S"},
		"run":  {"run", "dast", "--all-records", "-t", "http://127.0.0.1:1"},
		"args": {"scan", "http://127.0.0.1:1", "--all-records"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runA2Scan(t, args...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if strings.Contains(stderr, a2DBScanMarker) {
				t.Fatal("a rejected combination must not reach the rescan")
			}
		})
	}
}

// A bare `vigolium scan` is a usage error on a terminal too — the
// deprecated TTY fallback that rescanned every stored record is gone. The error
// names the store and project, and -j/--events keep the same exit 2.
func TestBareScanIsAUsageErrorEverywhere(t *testing.T) {
	saveOpts := *scanOpts
	saveInput, saveJSON, saveAll := globalInput, globalJSON, globalAllRecords
	t.Cleanup(func() {
		*scanOpts = saveOpts
		globalInput, globalJSON, globalAllRecords = saveInput, saveJSON, saveAll
	})

	cmd := &cobra.Command{Use: "scan"}
	var input string
	cmd.Flags().StringVarP(&input, "input", "i", "-", "")
	settings := config.DefaultSettings()
	settings.Database.SQLite.Path = "/tmp/a2-tty.sqlite"

	scanOpts.Targets, scanOpts.TargetsFilePaths, scanOpts.Stdin, scanOpts.Events = nil, nil, false, ""
	scanOpts.ProjectUUID = database.DefaultProjectUUID
	globalInput, globalAllRecords = "-", false

	for _, mode := range []struct {
		name   string
		json   bool
		events string
	}{{"terminal", false, ""}, {"-j", true, ""}, {"--events", false, "-"}} {
		globalJSON, scanOpts.Events = mode.json, mode.events
		err := resolveScanTargetSource(cmd, settings)
		if err == nil || classifyExitCode(err) != 2 {
			t.Fatalf("%s: a bare scan must be a usage error, got %v", mode.name, err)
		}
		if !strings.Contains(err.Error(), "/tmp/a2-tty.sqlite") || !strings.Contains(err.Error(), "default project") {
			t.Errorf("%s: the error must name the store and project, got %q", mode.name, err)
		}
	}
}
