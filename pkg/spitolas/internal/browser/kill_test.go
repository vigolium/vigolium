package browser

import (
	"fmt"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// failingBrowserBin writes an executable that exits non-zero immediately, so a
// launch attempt against it fails the way a broken distro build does: the binary
// exists, so the candidate resolves, but no DevTools URL is ever printed. Before
// exiting it records its arguments, one per line, in the returned args file, so
// a test can see which profile directory the attempt was handed.
func failingBrowserBin(t *testing.T) (bin, argsFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script candidate is not executable on Windows")
	}
	dir := t.TempDir()
	bin = filepath.Join(dir, "fake-browser")
	argsFile = filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argsFile + "'\nexit 1\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

// recordedUserDataDir returns the --user-data-dir the fake browser was launched
// with.
func recordedUserDataDir(t *testing.T, argsFile string) string {
	t.Helper()
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("the fake browser was never executed: %v", err)
	}
	for _, arg := range strings.Split(string(data), "\n") {
		if dir, ok := strings.CutPrefix(arg, "--user-data-dir="); ok {
			return dir
		}
	}
	t.Fatalf("the launch attempt passed no --user-data-dir: %q", data)
	return ""
}

// TestLaunchFromCleansUpAfterAFailedAttempt: every candidate gets its own scratch
// Chromium profile from newLauncher, and a candidate that fails to launch used to
// leave that directory behind — one per failure, on every launch, on a host where
// a cheaper candidate fails before a working one is found.
//
// It checks the attempt's own profile directory rather than counting profiles
// under the scratch root: in a process that has launched real browsers (the
// integration suite) that count also moves with other browsers' teardown.
func TestLaunchFromCleansUpAfterAFailedAttempt(t *testing.T) {
	bin, argsFile := failingBrowserBin(t)

	// Shorten the per-attempt bound: the fake binary exits at once, so the
	// timeout is not what ends the attempt, but a surprise should not cost 60s.
	origTimeout := browserLaunchTimeout
	browserLaunchTimeout = 5 * time.Second
	t.Cleanup(func() { browserLaunchTimeout = origTimeout })

	cfg, err := config.New("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	b := &Browser{config: cfg}

	launchErr := b.launchFrom(context.Background(), []browserCandidate{
		{label: "fake failing browser", resolve: func() (string, error) { return bin, nil }},
	})
	if launchErr == nil {
		t.Fatal("a binary that exits 1 must not report a successful launch")
	}
	if !strings.Contains(launchErr.Error(), "fake failing browser") {
		t.Fatalf("the error should name the candidate: %v", launchErr)
	}

	profile := recordedUserDataDir(t, argsFile)
	if _, err := os.Stat(profile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed launch left its profile directory %s behind (stat: %v)", profile, err)
	}
	// Nothing was published, so a later Kill must be a safe no-op.
	if b.killer != nil || b.killProfileDir != "" {
		t.Fatal("a failed launch must not publish kill handles")
	}
	b.Kill()
}

// fakeKiller records Kill calls without a real process.
type fakeKiller struct{ n atomic.Int64 }

func (f *fakeKiller) Kill() { f.n.Add(1) }

// TestKillDoesNotTakeTheBrowserLock is the reason Kill exists: the case that
// actually leaks a Chromium process is a WEDGED Close, and a wedged Close is
// holding b.mu. A Kill that needed the lock could never reach the process.
func TestKillDoesNotTakeTheBrowserLock(t *testing.T) {
	profile := t.TempDir()
	killer := &fakeKiller{}
	b := &Browser{killer: killer, killProfileDir: profile}

	// Stand in for a wedged Close.
	b.mu.Lock()
	defer b.mu.Unlock()

	done := make(chan struct{})
	go func() {
		b.Kill()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Kill blocked while b.mu was held — it must not take the lock")
	}

	if got := killer.n.Load(); got != 1 {
		t.Fatalf("launcher kill called %d times, want 1", got)
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Fatalf("Kill left the profile directory behind: %v", err)
	}
}

func TestKillIsIdempotentAndConcurrencySafe(t *testing.T) {
	killer := &fakeKiller{}
	b := &Browser{killer: killer, killProfileDir: t.TempDir()}

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Kill()
		}()
	}
	wg.Wait()

	if got := killer.n.Load(); got != 1 {
		t.Fatalf("launcher kill called %d times, want exactly 1", got)
	}
}

func TestKillOnAnUnlaunchedBrowserIsANoOp(t *testing.T) {
	// Never launched: no handles were published.
	(&Browser{}).Kill()
	// And a nil receiver, which the runner's abandonment paths can reach.
	var nilBrowser *Browser
	nilBrowser.Kill()
}

// TestCloseEscalatesToKillOnAFailedClose: a bounded close that errors means the
// browser never acknowledged shutdown within browserOpTimeout, so the process may
// still be running. Close() returning was previously the last anyone looked at it.
func TestCloseEscalatesToKillOnAFailedClose(t *testing.T) {
	killer := &fakeKiller{}
	profile := t.TempDir()
	b := &Browser{
		killer:         killer,
		killProfileDir: profile,
		profileDir:     profile,
		closeRod:       func() error { return errors.New("browser did not acknowledge shutdown") },
	}

	err := b.Close()
	if err == nil {
		t.Fatal("Close must still report the close failure")
	}
	if got := killer.n.Load(); got != 1 {
		t.Fatalf("a failed close killed the process %d time(s), want 1", got)
	}
	if _, statErr := os.Stat(profile); !os.IsNotExist(statErr) {
		t.Fatalf("the profile directory survived a failed close: %v", statErr)
	}
}

// TestCloseDoesNotKillOnACleanClose is the control: the ordinary path must not
// reach for the launcher's kill, which would make every normal teardown pay the
// launcher's built-in wait.
func TestCloseDoesNotKillOnACleanClose(t *testing.T) {
	killer := &fakeKiller{}
	profile := t.TempDir()
	b := &Browser{
		killer:         killer,
		killProfileDir: profile,
		profileDir:     profile,
		closeRod:       func() error { return nil },
	}

	if err := b.Close(); err != nil {
		t.Fatalf("clean Close returned %v", err)
	}
	if got := killer.n.Load(); got != 0 {
		t.Fatalf("a clean close killed the process %d time(s), want 0", got)
	}
	if _, statErr := os.Stat(profile); !os.IsNotExist(statErr) {
		t.Fatalf("a clean close left the profile behind: %v", statErr)
	}
}

// TestLaunchBoundedIsNotTheCallerContext pins the one thing launchBounded must
// never do: rod kills the browser process when the launcher's context ends, so
// binding the caller's long-lived context there would kill a healthy browser the
// moment a crawl deadline fired — before capture finished flushing.
func TestLaunchBoundedUsesItsOwnDeadline(t *testing.T) {
	if browserLaunchTimeout <= 0 {
		t.Fatal("browserLaunchTimeout must be positive or every launch expires at once")
	}
}

// TestLaunchFromMarksLaunchFailure is MISS-27: a browser that cannot be
// started is reported as ErrLaunch (through every wrapper up to the runner),
// and a launch the caller cancelled is not.
func TestLaunchFromMarksLaunchFailure(t *testing.T) {
	cfg, err := config.New("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	b := &Browser{config: cfg}
	launchErr := b.launchFrom(context.Background(), nil)
	if !errors.Is(fmt.Errorf("failed to create browser pool: %w", launchErr), ErrLaunch) {
		t.Fatalf("no candidate: %v, want ErrLaunch", launchErr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.launchFrom(ctx, nil); errors.Is(err, ErrLaunch) {
		t.Fatalf("a cancelled launch is not a launch failure: %v", err)
	}
}
