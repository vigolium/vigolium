package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// resetDBPathEnvGlobals restores every global applyDBPathEnv touches, so a case
// can't leak state into the next one (they are package-level CLI flag targets).
func resetDBPathEnvGlobals(t *testing.T) {
	t.Helper()
	origDB, origStateless, origGlob := globalDB, globalStateless, globalGlobDB
	origAuto, origPinned, origSilent := dbPathEnvAutoStateless, dbPathEnvPinned, globalSilent
	globalDB, globalStateless, globalGlobDB, dbPathEnvAutoStateless, dbPathEnvPinned = "", false, "", false, false
	globalSilent = true // keep the notice out of the test log
	t.Cleanup(func() {
		globalDB, globalStateless, globalGlobDB = origDB, origStateless, origGlob
		dbPathEnvAutoStateless, dbPathEnvPinned, globalSilent = origAuto, origPinned, origSilent
	})
}

// cmdAtPath builds a bare command at path ("agent audit") under a stand-in
// root, for the tables keyed by commandPathWithoutRoot.
func cmdAtPath(path string) *cobra.Command {
	parent := &cobra.Command{Use: "vigolium"}
	var cmd *cobra.Command
	for _, name := range strings.Fields(path) {
		cmd = &cobra.Command{Use: name}
		parent.AddCommand(cmd)
		parent = cmd
	}
	return cmd
}

// statelessCmd builds a command carrying an -S/--stateless flag, matching how
// the real commands register it: statelessWriteRequested reads the flag, not the
// variable behind it, so the binding target is irrelevant here.
func statelessCmd(path string) *cobra.Command {
	cmd := cmdAtPath(path)
	var stateless bool
	cmd.Flags().BoolVarP(&stateless, "stateless", "S", false, "")
	return cmd
}

// seedDBFile creates an empty file standing in for an existing session DB.
func seedDBFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.sqlite")
	require.NoError(t, os.WriteFile(path, []byte{}, 0o600))
	return path
}

func TestApplyDBPathEnv(t *testing.T) {
	cases := []struct {
		name string
		cmd  *cobra.Command
		// pre is what the user typed explicitly, applied after the reset.
		pre func(cmd *cobra.Command, envPath string)
		// wantDB is the expected globalDB; empty string means "the env path",
		// the "-" sentinel means "expected empty".
		wantDB string
		// wantStateless is the expected dbPathEnvAutoStateless. It is command-
		// agnostic by design: it only takes effect through
		// statelessReadRequested, which the write commands never consult.
		wantStateless bool
	}{
		{
			// The env var implies its read semantics through
			// statelessReadRequested, so every reader is covered — including
			// `fuzz`, which resolves records through effectiveProjectUUID
			// without ever registering an -S flag.
			name:          "read commands see the session DB unscoped",
			cmd:           statelessCmd("finding"),
			wantStateless: true,
		},
		{
			name:          "commands with no stateless flag are covered too",
			cmd:           &cobra.Command{Use: "fuzz"},
			wantStateless: true,
		},
		{
			// A scan writes to the session DB. The flag it consults is
			// globalStateless (asserted untouched below for every case), which
			// is what keeps it clear of "--stateless and --db are mutually
			// exclusive"; it never reads statelessReadRequested.
			name:          "scan writes to the session DB",
			cmd:           statelessCmd("scan"),
			wantStateless: true,
		},
		{
			name:          "ingest -S is --scan-on-receive, unrelated to the DB",
			cmd:           &cobra.Command{Use: "ingest"},
			wantStateless: true,
		},
		{
			name: "explicit --db wins",
			cmd:  statelessCmd("finding"),
			pre: func(_ *cobra.Command, _ string) {
				globalDB = "/tmp/explicit.sqlite"
			},
			wantDB: "/tmp/explicit.sqlite",
		},
		{
			// Applying the env var here would only surface "--stateless and
			// --db are mutually exclusive" for a --db the user never typed.
			name: "explicit -S on a scan ignores the env var",
			cmd:  statelessCmd("scan"),
			pre: func(cmd *cobra.Command, _ string) {
				require.NoError(t, cmd.Flags().Set("stateless", "true"))
			},
			wantDB: "-", // sentinel: expect empty
		},
		{
			// `audit -S` binds its own auditStateless, not globalStateless —
			// reading the flag rather than the variable is what covers it.
			name: "explicit -S on audit ignores the env var",
			cmd:  statelessCmd("audit"),
			pre: func(cmd *cobra.Command, _ string) {
				require.NoError(t, cmd.Flags().Set("stateless", "true"))
			},
			wantDB: "-",
		},
		{
			// Keyed by command path: `extensions run -S` is a read over the
			// pinned session DB, not top-level `run`'s throwaway store.
			name: "explicit -S on extensions run keeps the env var",
			cmd:  statelessCmd("extensions run"),
			pre: func(cmd *cobra.Command, _ string) {
				require.NoError(t, cmd.Flags().Set("stateless", "true"))
			},
			wantStateless: true,
		},
		{
			// --glob-db already drives a stateless read across a merged set.
			name: "--glob-db keeps driving the merge",
			cmd:  statelessCmd("finding"),
			pre: func(_ *cobra.Command, _ string) {
				globalGlobDB = "scans/*.sqlite"
			},
		},
		{
			// An explicit -S already answered the question; nothing to imply.
			name: "explicit -S on a read command needs no implication",
			cmd:  statelessCmd("traffic"),
			pre: func(_ *cobra.Command, _ string) {
				globalStateless = true
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetDBPathEnvGlobals(t)
			path := seedDBFile(t)
			t.Setenv(dbPathEnvVar, path)
			if tc.pre != nil {
				tc.pre(tc.cmd, path)
			}
			explicitStateless := globalStateless

			_ = applyDBPathEnv(tc.cmd)

			// The invariant that keeps the scan family clear of its
			// --stateless/--db mutual exclusion: this never writes the flag
			// variable those commands actually branch on.
			assert.Equal(t, explicitStateless, globalStateless, "globalStateless must be left alone")

			wantDB := tc.wantDB
			switch wantDB {
			case "":
				wantDB = path
			case "-":
				wantDB = ""
			}
			assert.Equal(t, wantDB, globalDB)
			assert.Equal(t, tc.wantStateless, dbPathEnvAutoStateless)
		})
	}
}

// A session whose database hasn't been written yet should read as empty, not
// fail: a stateless read stats its source and errors when it is missing.
func TestDBPathEnvSkipsStatelessWhenFileMissing(t *testing.T) {
	resetDBPathEnvGlobals(t)
	path := filepath.Join(t.TempDir(), "not-yet.sqlite")
	t.Setenv(dbPathEnvVar, path)

	_ = applyDBPathEnv(statelessCmd("traffic"))

	assert.Equal(t, path, globalDB)
	assert.False(t, dbPathEnvAutoStateless)
	assert.False(t, statelessReadRequested())
}

// The implication reaches reads through the one predicate they all consult,
// rather than through a list of command names.
func TestDBPathEnvDrivesStatelessReadRequested(t *testing.T) {
	resetDBPathEnvGlobals(t)
	t.Setenv(dbPathEnvVar, seedDBFile(t))
	require.False(t, statelessReadRequested())

	_ = applyDBPathEnv(statelessCmd("finding"))

	assert.True(t, statelessReadRequested())
}

func TestDBPathEnvExpandsHome(t *testing.T) {
	resetDBPathEnvGlobals(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(dbPathEnvVar, "~/session.sqlite")

	_ = applyDBPathEnv(statelessCmd("scan"))

	assert.Equal(t, filepath.Join(home, "session.sqlite"), globalDB)
}

func TestDBPathEnvUnsetIsNoOp(t *testing.T) {
	resetDBPathEnvGlobals(t)
	t.Setenv(dbPathEnvVar, "")

	_ = applyDBPathEnv(statelessCmd("finding"))

	assert.Empty(t, globalDB)
	assert.False(t, dbPathEnvAutoStateless)
}

// The notice is the change's only user-visible signal, so the modes that promise
// a clean stream have to stay clean.
func TestDBPathEnvNoticeSuppression(t *testing.T) {
	for _, tc := range []struct {
		name  string
		quiet func()
		want  bool
	}{
		{name: "default prints", quiet: func() {}, want: true},
		{name: "--silent", quiet: func() { globalSilent = true }},
		{name: "--json", quiet: func() { globalJSON = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetDBPathEnvGlobals(t)
			origJSON, origCI := globalJSON, globalCIOutput
			globalSilent, globalJSON, globalCIOutput = false, false, false
			t.Cleanup(func() { globalJSON, globalCIOutput = origJSON, origCI })
			tc.quiet()

			r, w, err := os.Pipe()
			require.NoError(t, err)
			origStderr := os.Stderr
			os.Stderr = w
			dbPathEnvNotice("notice-probe")
			os.Stderr = origStderr
			require.NoError(t, w.Close())

			buf := make([]byte, 256)
			n, _ := r.Read(buf)
			require.NoError(t, r.Close())

			assert.Equal(t, tc.want, n > 0, "notice printed")
		})
	}
}

// --stateless=false is an operator saying "I know about -S and I do not want
// it". Reading pflag's Changed as "enabled" dropped the VIGOLIUM_DB_PATH pin, so
// the scan wrote to the default database — the exact silent redirect the pin
// rule exists to forbid.
func TestDBPathEnvKeepsPinWhenStatelessExplicitlyFalse(t *testing.T) {
	resetDBPathEnvGlobals(t)
	path := seedDBFile(t)
	t.Setenv(dbPathEnvVar, path)

	cmd := statelessCmd("scan")
	require.NoError(t, cmd.Flags().Set("stateless", "false"))

	require.NoError(t, applyDBPathEnv(cmd))

	assert.Equal(t, path, globalDB,
		"--stateless=false must keep the pinned database, not fall back to the default")
}

// flagOn is the shared predicate behind the three sites that used Changed.
func TestFlagOn(t *testing.T) {
	newCmd := func() *cobra.Command {
		cmd := &cobra.Command{Use: "probe"}
		var b bool
		cmd.Flags().BoolVar(&b, "flag", false, "")
		cmd.Flags().String("name", "", "")
		return cmd
	}

	t.Run("untouched is off", func(t *testing.T) {
		assert.False(t, flagOn(newCmd(), "flag"))
	})
	t.Run("=true is on", func(t *testing.T) {
		cmd := newCmd()
		require.NoError(t, cmd.Flags().Set("flag", "true"))
		assert.True(t, flagOn(cmd, "flag"))
	})
	t.Run("=false is off", func(t *testing.T) {
		cmd := newCmd()
		require.NoError(t, cmd.Flags().Set("flag", "false"))
		assert.False(t, flagOn(cmd, "flag"), "an explicit false must not read as enabled")
	})
	t.Run("missing flag is off", func(t *testing.T) {
		assert.False(t, flagOn(newCmd(), "nope"))
	})
	t.Run("nil command is off", func(t *testing.T) {
		assert.False(t, flagOn(nil, "flag"))
	})
	t.Run("a set non-bool is on", func(t *testing.T) {
		cmd := newCmd()
		require.NoError(t, cmd.Flags().Set("name", "false"))
		assert.True(t, flagOn(cmd, "name"),
			"for a non-bool, 'set at all' is the only available meaning — even when the value reads as false")
	})
}

// -S on server/ingest used to mean --scan-on-receive. It is now a usage error
// whatever its value, and the long flag is unaffected.
func TestRetiredScanOnReceiveShorthand(t *testing.T) {
	orig := globalScanOnReceive
	t.Cleanup(func() { globalScanOnReceive = orig })

	newIngest := func() *cobra.Command {
		cmd := &cobra.Command{Use: "ingest"}
		registerScanOnReceiveFlags(cmd.Flags(), "")
		return cmd
	}

	for _, v := range []string{"true", "false"} {
		cmd := newIngest()
		require.NoError(t, cmd.Flags().Set(retiredScanOnReceiveFlag, v))
		err := rejectRetiredScanOnReceive(cmd)
		require.Error(t, err, "-S=%s", v)
		assert.Equal(t, 2, classifyExitCode(err), "usage error")
		assert.Contains(t, err.Error(), "--scan-on-receive")
	}

	globalScanOnReceive = false
	cmd := newIngest()
	require.NoError(t, cmd.Flags().Set("scan-on-receive", "true"))
	assert.NoError(t, rejectRetiredScanOnReceive(cmd))
	assert.True(t, globalScanOnReceive)
}

// --read-only rejects flags that WRITE. An explicitly-false writer flag writes
// nothing, so rejecting it was a conflict that did not exist.
func TestReadOnlyAcceptsWriterFlagFalse(t *testing.T) {
	orig := globalReadOnly
	origRequested := clicommon.Policy.ReadOnly
	t.Cleanup(func() {
		globalReadOnly = orig
		clicommon.Policy.ReadOnly = origRequested
	})

	newTraffic := func() *cobra.Command {
		root := &cobra.Command{Use: "vigolium"}
		cmd := &cobra.Command{Use: "traffic"}
		var save bool
		cmd.Flags().BoolVar(&save, "save-to-vigolium-db", false, "")
		root.AddCommand(cmd)
		return cmd
	}

	globalReadOnly = true

	clicommon.Policy.ReadOnly = false
	cmd := newTraffic()
	require.NoError(t, cmd.Flags().Set("save-to-vigolium-db", "false"))
	require.NoError(t, applyReadOnlyMode(cmd), "--save-to-vigolium-db=false writes nothing")
	assert.True(t, clicommon.Policy.ReadOnly)

	clicommon.Policy.ReadOnly = false
	cmd = newTraffic()
	require.NoError(t, cmd.Flags().Set("save-to-vigolium-db", "true"))
	err := applyReadOnlyMode(cmd)
	require.Error(t, err, "--save-to-vigolium-db=true still conflicts")
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
}
