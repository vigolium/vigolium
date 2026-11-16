package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/browsercookie"
)

// newKitCookiesTestCmd builds a command carrying just the flags the scope
// resolution inspects, so a test can say which were set without mutating the
// real command tree.
func newKitCookiesTestCmd(changed ...string) *cobra.Command {
	cmd := &cobra.Command{Use: "cookies"}
	cmd.Flags().String("scope", "host", "")
	cmd.Flags().Bool("apex", false, "")
	for _, name := range changed {
		if err := cmd.Flags().Set(name, cmd.Flags().Lookup(name).Value.String()); err != nil {
			panic(err)
		}
	}
	return cmd
}

// resetKitCookiesFlags restores every flag variable the command reads, so one
// test's settings cannot leak into the next through package state.
//
// Saved and restored field by field rather than positionally: the flag set
// grows, and a positional snapshot silently reassigns the wrong variables the
// moment a field is inserted.
func resetKitCookiesFlags(t *testing.T) {
	t.Helper()
	type snapshot struct {
		scope, format, output, sameSite, cloneDir string
		apex, stdout, reveal, requireMatch, ack   bool
		noPrompt                                  bool
		includeExpired, withStorage, json         bool
		names, browsers, profiles, dataDirs       []string
	}
	saved := snapshot{
		scope: kitCookiesScope, format: kitCookiesFormat, output: kitCookiesOutput,
		sameSite: kitCookiesSameSite, cloneDir: kitCookiesCloneDir,
		apex: kitCookiesApex, stdout: kitCookiesStdout, reveal: kitCookiesReveal,
		requireMatch: kitCookiesRequireMatch, ack: kitCookiesAck, noPrompt: kitCookiesNoPrompt,
		includeExpired: kitCookiesIncludeExp, withStorage: kitCookiesWithStorage,
		json:  globalJSON,
		names: kitCookiesNames, browsers: kitCookiesBrowsers,
		profiles: kitCookiesProfiles, dataDirs: kitCookiesUserDataDirs,
	}
	t.Cleanup(func() {
		kitCookiesScope, kitCookiesFormat, kitCookiesOutput = saved.scope, saved.format, saved.output
		kitCookiesSameSite, kitCookiesCloneDir = saved.sameSite, saved.cloneDir
		kitCookiesApex, kitCookiesStdout, kitCookiesReveal = saved.apex, saved.stdout, saved.reveal
		kitCookiesRequireMatch, kitCookiesAck = saved.requireMatch, saved.ack
		kitCookiesNoPrompt = saved.noPrompt
		kitCookiesIncludeExp, kitCookiesWithStorage = saved.includeExpired, saved.withStorage
		globalJSON = saved.json
		kitCookiesNames, kitCookiesBrowsers = saved.names, saved.browsers
		kitCookiesProfiles, kitCookiesUserDataDirs = saved.profiles, saved.dataDirs
	})
	kitCookiesScope, kitCookiesFormat, kitCookiesOutput = "host", "", ""
	kitCookiesSameSite, kitCookiesCloneDir = "", ""
	kitCookiesApex, kitCookiesStdout, kitCookiesReveal = false, false, false
	kitCookiesRequireMatch, kitCookiesWithStorage, kitCookiesIncludeExp = false, false, false
	kitCookiesNoPrompt = false
	// Acknowledged by default: a test must not print the first-run notice or
	// write its marker into the developer's home directory.
	kitCookiesAck = true
	kitCookiesNames, kitCookiesBrowsers = nil, nil
	kitCookiesProfiles, kitCookiesUserDataDirs = nil, nil
}

func TestKitCookiesRefusesABareInvocation(t *testing.T) {
	resetKitCookiesFlags(t)
	// Reading every cookie in every profile is both the least likely thing an
	// operator wants and the most sensitive thing the command can do, so a
	// mistyped invocation must not do it.
	err := runKitCookies(newKitCookiesTestCmd(), nil)
	if err == nil {
		t.Fatal("expected a usage error with no domain")
	}
	if got := classifyExitCode(err); got != ExitUsageError {
		t.Errorf("exit code = %d, want %d", got, ExitUsageError)
	}
	if !strings.Contains(err.Error(), "every cookie in every profile") {
		t.Errorf("error should say what it is refusing to do: %v", err)
	}
}

func TestKitCookiesRejectsContradictoryScopeFlags(t *testing.T) {
	resetKitCookiesFlags(t)
	kitCookiesApex = true
	kitCookiesScope = "subdomains"
	err := runKitCookies(newKitCookiesTestCmd("scope"), []string{"acme.test"})
	if err == nil {
		t.Fatal("expected --apex and --scope subdomains to be rejected")
	}
	if got := classifyExitCode(err); got != ExitUsageError {
		t.Errorf("exit code = %d, want %d", got, ExitUsageError)
	}
}

func TestKitCookiesApexAgreesWithExplicitScopeApex(t *testing.T) {
	resetKitCookiesFlags(t)
	kitCookiesApex = true
	kitCookiesScope = "apex"
	scope, err := kitCookiesResolveScope(newKitCookiesTestCmd("scope"))
	if err != nil {
		t.Fatalf("--apex with --scope apex should agree: %v", err)
	}
	if scope != browsercookie.ScopeApex {
		t.Errorf("scope = %v, want apex", scope)
	}
}

func TestKitCookiesApexWithoutExplicitScopeWins(t *testing.T) {
	resetKitCookiesFlags(t)
	kitCookiesApex = true
	scope, err := kitCookiesResolveScope(newKitCookiesTestCmd())
	if err != nil {
		t.Fatalf("kitCookiesResolveScope: %v", err)
	}
	if scope != browsercookie.ScopeApex {
		t.Errorf("scope = %v, want apex", scope)
	}
}

func TestKitCookiesFormatRequiresADestination(t *testing.T) {
	resetKitCookiesFlags(t)
	kitCookiesFormat = "playwright"
	// --format writes real session values. Requiring an explicit destination
	// keeps a live credential from landing in terminal scrollback by default.
	err := runKitCookies(newKitCookiesTestCmd(), []string{"acme.test"})
	if err == nil {
		t.Fatal("expected --format without -o or --stdout to be rejected")
	}
	if got := classifyExitCode(err); got != ExitUsageError {
		t.Errorf("exit code = %d, want %d", got, ExitUsageError)
	}
	for _, want := range []string{"-o", "--stdout"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %s: %v", want, err)
		}
	}
}

func TestKitCookiesOutputRequiresFormat(t *testing.T) {
	resetKitCookiesFlags(t)
	kitCookiesOutput = filepath.Join(t.TempDir(), "state.json")
	err := runKitCookies(newKitCookiesTestCmd(), []string{"acme.test"})
	if err == nil || classifyExitCode(err) != ExitUsageError {
		t.Fatalf("expected a usage error for -o without --format, got %v", err)
	}
}

func TestKitCookiesRejectsTwoDestinations(t *testing.T) {
	resetKitCookiesFlags(t)
	kitCookiesFormat = "netscape"
	kitCookiesOutput = filepath.Join(t.TempDir(), "jar.txt")
	kitCookiesStdout = true
	err := runKitCookies(newKitCookiesTestCmd(), []string{"acme.test"})
	if err == nil || classifyExitCode(err) != ExitUsageError {
		t.Fatalf("expected a usage error for --stdout with -o, got %v", err)
	}
}

func TestKitCookiesRejectsUnknownFormatAndSameSite(t *testing.T) {
	resetKitCookiesFlags(t)
	kitCookiesFormat = "yaml"
	kitCookiesStdout = true
	if err := runKitCookies(newKitCookiesTestCmd(), []string{"acme.test"}); err == nil || classifyExitCode(err) != ExitUsageError {
		t.Fatalf("expected a usage error for an unknown format, got %v", err)
	}

	resetKitCookiesFlags(t)
	kitCookiesSameSite = "maybe"
	if err := runKitCookies(newKitCookiesTestCmd(), []string{"acme.test"}); err == nil || classifyExitCode(err) != ExitUsageError {
		t.Fatalf("expected a usage error for an unknown same-site, got %v", err)
	}
}

func TestKitCookiesWriteSecretIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := kitCookiesWriteSecret(path, []byte(`{"cookies":[]}`)); err != nil {
		t.Fatalf("kitCookiesWriteSecret: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// The mode is set at create time rather than chmod'ed afterwards: a
	// window in which a session file is world-readable is the whole risk.
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %04o, want 0600", perm)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != `{"cookies":[]}` {
		t.Errorf("content = %q, %v", data, err)
	}
}

func TestKitCookiesWriteSecretTruncatesAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("stale and much longer than the replacement"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := kitCookiesWriteSecret(path, []byte("new")); err != nil {
		t.Fatalf("kitCookiesWriteSecret: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "new" {
		t.Errorf("content = %q, want the file replaced, not overwritten in place", data)
	}
}

func TestKitCookiesWriteSecretCodesAFailedWriteAsExportFailed(t *testing.T) {
	// A requested artifact that was never written must not look like a
	// database or source problem; the caller's fix is to retry the write.
	err := kitCookiesWriteSecret(filepath.Join(t.TempDir(), "missing-dir", "state.json"), []byte("x"))
	if err == nil {
		t.Fatal("expected a write failure")
	}
	var coded interface{ Code() apicontract.ErrorCode }
	if !errors.As(err, &coded) {
		t.Fatalf("error carries no code: %v", err)
	}
	if coded.Code() != apicontract.CodeExportFailed {
		t.Errorf("code = %q, want %q", coded.Code(), apicontract.CodeExportFailed)
	}
}

func TestKitCookiesErrorCodeMapping(t *testing.T) {
	cases := map[browsercookie.Problem]apicontract.ErrorCode{
		browsercookie.ProblemKeyringDenied:         apicontract.CodeKeyringDenied,
		browsercookie.ProblemEncryptionUnsupported: apicontract.CodeBrowserEncryptionUnsupported,
		browsercookie.ProblemUnreadable:            apicontract.CodeSourceUnreadable,
		browsercookie.ProblemDecryptFailed:         apicontract.CodeSourceUnreadable,
	}
	for problem, want := range cases {
		if got := kitCookiesErrorCode(problem); got != want {
			t.Errorf("kitCookiesErrorCode(%q) = %q, want %q", problem, got, want)
		}
		if !want.Valid() {
			t.Errorf("%q is not in the closed error-code set", want)
		}
	}
}

func TestKitCookiesProblemSummaryPointsAtTheFix(t *testing.T) {
	// The keyring message is the one an agent relays to a human, so it has to
	// name the command that grants access.
	got := kitCookiesProblemSummary(browsercookie.ProblemKeyringDenied)
	if !strings.Contains(got, "kit cookies doctor") {
		t.Errorf("keyring summary should name the doctor command: %q", got)
	}
	for _, p := range []browsercookie.Problem{
		browsercookie.ProblemEncryptionUnsupported,
		browsercookie.ProblemDecryptFailed,
		browsercookie.ProblemUnreadable,
	} {
		if kitCookiesProblemSummary(p) == "" {
			t.Errorf("no summary for %q", p)
		}
	}
}

func TestKitCookiesExpiryRendering(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	// "session" rather than a zero timestamp: it is the operator's cue that
	// the handoff may already be dead.
	if got := kitCookiesExpiry(browsercookie.Cookie{}, now); got != "session" {
		t.Errorf("session cookie = %q", got)
	}
	if got := kitCookiesExpiry(browsercookie.Cookie{Expires: now.Add(-time.Hour)}, now); got != "expired" {
		t.Errorf("past expiry = %q", got)
	}
	future := now.Add(time.Hour)
	if got := kitCookiesExpiry(browsercookie.Cookie{Expires: future}, now); got != future.Format(time.RFC3339) {
		t.Errorf("future expiry = %q", got)
	}
}

func TestKitCookiesFlagsRendering(t *testing.T) {
	cases := []struct {
		cookie browsercookie.Cookie
		want   string
	}{
		{browsercookie.Cookie{}, "-"},
		{browsercookie.Cookie{Secure: true, HTTPOnly: true}, "secure,httponly"},
		{browsercookie.Cookie{SameSite: "None"}, "samesite=none"},
	}
	for _, c := range cases {
		if got := kitCookiesFlags(c.cookie); got != c.want {
			t.Errorf("kitCookiesFlags(%+v) = %q, want %q", c.cookie, got, c.want)
		}
	}
}

func TestCookieProfileNameFallsBackToDirectoryThenDefault(t *testing.T) {
	cases := []struct {
		cookie browsercookie.Cookie
		want   string
	}{
		{browsercookie.Cookie{ProfileLabel: "Work", Profile: "Profile 3"}, "Work"},
		{browsercookie.Cookie{Profile: "Profile 3"}, "Profile 3"},
		{browsercookie.Cookie{}, "default"},
	}
	for _, c := range cases {
		if got := c.cookie.ProfileName(); got != c.want {
			t.Errorf("ProfileName(%+v) = %q, want %q", c.cookie, got, c.want)
		}
	}
}

func TestKitCookiesNoticeIsSuppressedByEnvironment(t *testing.T) {
	// An agent that has acknowledged the notice once should not have it
	// reprinted into every transcript.
	resetKitCookiesFlags(t)
	kitCookiesAck = false
	t.Setenv("VIGOLIUM_COOKIES_ACK", "1")

	stderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	kitCookiesNotice(newKitCookiesTestCmd())
	_ = w.Close()
	os.Stderr = stderr

	var buf [256]byte
	n, _ := r.Read(buf[:])
	if n > 0 {
		t.Errorf("notice printed despite VIGOLIUM_COOKIES_ACK: %q", buf[:n])
	}
}

func TestKitCookiesMachineKindsDeclared(t *testing.T) {
	for _, path := range []string{"kit cookies", "kit cookies profiles", "kit cookies doctor"} {
		if trait, ok := commandTraits[path]; !ok {
			t.Errorf("%q has no declared machine kind", path)
		} else if trait.Kind != kindRead {
			t.Errorf("%q declares %v, want kindRead", path, trait.Kind)
		}
	}
}

// TestKitCookiesNoticeStaysInsideItsCommand keeps the approval/EDR notice —
// and with it the keyring access that raises an OS prompt — confined to
// `kit cookies`.
//
// It is a source scan rather than a behavioural test because the risk is a
// future caller, not today's code: wired into a shared helper, a scan phase or
// the root command, this notice would print on invocations that read no cookie
// at all, and the keyring probe behind it would prompt the operator during
// unrelated work. Every other command must stay untouched.
func TestKitCookiesNoticeStaysInsideItsCommand(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read pkg/cli: %v", err)
	}
	allowed := map[string]bool{
		"kit_cookies.go":      true,
		"kit_cookies_test.go": true,
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || allowed[e.Name()] {
			continue
		}
		data, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, symbol := range []string{"kitCookiesNotice", "browsercookie.Read(", "browsercookie.Diagnose("} {
			if strings.Contains(string(data), symbol) {
				t.Errorf("%s references %s; reading browser cookies and warning about it belong to `kit cookies` alone", e.Name(), symbol)
			}
		}
	}
}

func TestKitCookiesSelectorMistakesExitTwo(t *testing.T) {
	// An unknown --browser reaches the command through the read, not through
	// flag parsing, so without the classification it would exit 1 and look
	// like the read itself failed.
	resetKitCookiesFlags(t)
	kitCookiesBrowsers = []string{"netscape"}
	err := runKitCookies(newKitCookiesTestCmd(), []string{"acme.test"})
	if err == nil {
		t.Fatal("expected an unknown browser to be rejected")
	}
	if got := classifyExitCode(err); got != ExitUsageError {
		t.Errorf("exit code = %d, want %d (a mistyped flag, not a failed read)", got, ExitUsageError)
	}

	resetKitCookiesFlags(t)
	kitCookiesUserDataDirs = []string{filepath.Join(t.TempDir(), "not-a-profile")}
	err = runKitCookies(newKitCookiesTestCmd(), []string{"acme.test"})
	if err == nil {
		t.Fatal("expected a missing --user-data-dir to be rejected")
	}
	if got := classifyExitCode(err); got != ExitUsageError {
		t.Errorf("exit code = %d, want %d", got, ExitUsageError)
	}
}

func TestKitCookiesCloneRejectsAFormat(t *testing.T) {
	// A clone writes a directory; a format writes a document. Accepting both
	// would leave the caller guessing which one carried their session.
	resetKitCookiesFlags(t)
	kitCookiesCloneDir = filepath.Join(t.TempDir(), "clone")
	kitCookiesFormat = "playwright"
	kitCookiesStdout = true
	err := runKitCookies(newKitCookiesTestCmd(), []string{"acme.test"})
	if err == nil || classifyExitCode(err) != ExitUsageError {
		t.Fatalf("expected a usage error for --clone-profile with --as, got %v", err)
	}
}

func TestKitCookiesCloneSourceNeedsOneProfile(t *testing.T) {
	// A clone is one user-data directory. Picking among several would hand over
	// a session from a profile the caller never named.
	two := browsercookie.Result{Stores: []browsercookie.StoreResult{
		{Store: browsercookie.StoreInfo{Browser: "chrome", Profile: "Default"}, Count: 2},
		{Store: browsercookie.StoreInfo{Browser: "brave", Profile: "Default"}, Count: 1},
	}}
	_, err := kitCookiesCloneSource(two)
	if err == nil || classifyExitCode(err) != ExitUsageError {
		t.Fatalf("expected a usage error when several profiles matched, got %v", err)
	}
	if !strings.Contains(err.Error(), "--browser") {
		t.Errorf("the error should say how to narrow it: %v", err)
	}

	one := browsercookie.Result{Stores: []browsercookie.StoreResult{
		{Store: browsercookie.StoreInfo{Browser: "chrome", Profile: "Work"}, Count: 0, StorageOrigins: 1},
		{Store: browsercookie.StoreInfo{Browser: "brave", Profile: "Default"}, Count: 0},
	}}
	got, err := kitCookiesCloneSource(one)
	if err != nil {
		t.Fatalf("kitCookiesCloneSource: %v", err)
	}
	// A profile that held only storage still counts: that is where the session
	// may live.
	if got.Profile != "Work" {
		t.Errorf("picked %q, want the only profile that held anything", got.Profile)
	}

	if _, err := kitCookiesCloneSource(browsercookie.Result{}); err == nil {
		t.Error("expected an error when nothing matched")
	}
}

func TestKitCookiesCloneImpliesStorage(t *testing.T) {
	// The clone's summary says what it carries, which it can only do if the
	// storage read ran.
	resetKitCookiesFlags(t)
	kitCookiesWithStorage = false
	kitCookiesCloneDir = filepath.Join(t.TempDir(), "clone")
	// A domain nothing matches: the run stops before cloning, which is enough
	// to observe the flag being set.
	_ = runKitCookies(newKitCookiesTestCmd(), []string{"no-such-domain-vigolium.invalid"})
	if !kitCookiesWithStorage {
		t.Error("--clone-profile should turn on the storage read")
	}
}
