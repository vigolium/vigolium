//go:build e2e

package e2eexpect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	_ "github.com/vigolium/vigolium/pkg/cli" // registers every command's -j schema
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
)

// The binary half of the kit: drives the built vigolium executable the way an
// operator or a coding agent does, so exit codes, signals and the -j
// documents are what is under test. E2E_EXPECT_BIN points it at an
// already-built binary (e.g. bin/vigolium from `make build`); otherwise the
// suite builds one once into a temp directory.

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

func vigoliumBin(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("E2E_EXPECT_BIN"); p != "" {
		return p
	}
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "vigolium-e2e-expect-bin-")
		if err != nil {
			binErr = err
			return
		}
		bin := filepath.Join(dir, "vigolium")
		_, file, _, _ := runtime.Caller(0)
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/vigolium")
		cmd.Dir = filepath.Join(filepath.Dir(file), "..", "..")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			binErr = fmt.Errorf("go build: %w\n%s", err, stderr.String())
			return
		}
		binPath = bin
	})
	if binErr != nil {
		t.Fatalf("build vigolium: %v", binErr)
	}
	return binPath
}

// cli is an isolated vigolium install: its own HOME and database, an
// environment scrubbed of the operator's VIGOLIUM_* settings and proxies, and
// OAST off so nothing leaves the machine.
type cli struct {
	bin  string
	home string
	db   string
	// tmp is the child's TMPDIR, owned by the test, so scratch files a run
	// leaves behind (a stateless scan's throwaway database) are observable.
	tmp string
	// noDB drops the --db flag (stateless runs refuse it); the run then uses
	// the install's default database under home.
	noDB bool
}

func newCLI(t *testing.T) *cli {
	t.Helper()
	dir := t.TempDir()
	c := &cli{bin: vigoliumBin(t), home: filepath.Join(dir, "home"), db: filepath.Join(dir, "vigolium.sqlite"), tmp: filepath.Join(dir, "tmp")}
	require.NoError(t, os.MkdirAll(c.home, 0o755))
	require.NoError(t, os.MkdirAll(c.tmp, 0o755))
	r := c.run(t, time.Minute, "config", "set", "oast.enabled", "false", "-j")
	require.Equalf(t, 0, r.code, "disable OAST\n%s", r)
	return c
}

// withoutDB returns a view of the same install that omits --db.
func (c *cli) withoutDB() *cli {
	cp := *c
	cp.noDB = true
	return &cp
}

// cliRun is one finished invocation.
type cliRun struct {
	argv           []string
	code           int
	stdout, stderr string
	elapsed        time.Duration
}

func (r cliRun) String() string {
	clip := func(s string) string {
		if len(s) > 3000 {
			return s[:1500] + "\n…\n" + s[len(s)-1500:]
		}
		return s
	}
	return fmt.Sprintf("argv: %q\nexit: %d (%s)\nstdout:\n%s\nstderr:\n%s", r.argv, r.code, r.elapsed.Round(time.Millisecond), clip(r.stdout), clip(r.stderr))
}

func (c *cli) env() []string {
	env := []string{"HOME=" + c.home, "TMPDIR=" + c.tmp, "NO_COLOR=1", "VIGOLIUM_DISABLE_UPDATE_CHECK=1"}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case name == "HOME", name == "TMPDIR", strings.HasPrefix(name, "VIGOLIUM_"),
			name == "CLAUDECODE", name == "CLAUDE_CODE_ENTRYPOINT", name == "CODEX_SANDBOX",
			name == "CURSOR_AGENT", name == "GEMINI_CLI",
			strings.EqualFold(name, "http_proxy"), strings.EqualFold(name, "https_proxy"),
			strings.EqualFold(name, "all_proxy"), strings.EqualFold(name, "no_proxy"):
			continue
		}
		env = append(env, kv)
	}
	return env
}

// proc is one started (or ready to start) invocation and its captured output.
type proc struct {
	cmd            *exec.Cmd
	stdout, stderr bytes.Buffer
	start          time.Time
}

// result snapshots the invocation so far (exit code left for the caller).
func (p *proc) result() cliRun {
	return cliRun{argv: p.cmd.Args, stdout: p.stdout.String(), stderr: p.stderr.String(), elapsed: time.Since(p.start)}
}

func (c *cli) command(ctx context.Context, args ...string) *proc {
	argv := append([]string{"--skip-dependency-check"}, args...)
	if !c.noDB {
		argv = append([]string{"--db", c.db}, argv...)
	}
	p := &proc{cmd: exec.CommandContext(ctx, c.bin, argv...), start: time.Now()}
	p.cmd.Env = c.env()
	p.cmd.Dir = c.home
	p.cmd.Stdout, p.cmd.Stderr = &p.stdout, &p.stderr
	// CommandContext kills a wedged child; WaitDelay bounds pipe draining.
	p.cmd.WaitDelay = 10 * time.Second
	return p
}

// run executes args and fails the test if the process outlives deadline.
func (c *cli) run(t *testing.T, deadline time.Duration, args ...string) cliRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	p := c.command(ctx, args...)
	err := p.cmd.Run()
	r := p.result()
	if ctx.Err() != nil {
		t.Fatalf("vigolium did not exit within %s (killed)\n%s", deadline, r)
	}
	r.code = exitCode(t, err, r)
	return r
}

// runInterrupted starts args, sends sig `times` times (200ms apart) after
// `after` or as soon as ready returns true (polled every 100ms), and returns
// how the process ended. It fails the test if the process does not exit
// within grace of the first signal.
func (c *cli) runInterrupted(t *testing.T, sig syscall.Signal, times int, after time.Duration, ready func() bool, grace time.Duration, args ...string) cliRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := c.command(ctx, args...)
	require.NoError(t, p.cmd.Start())
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()

	deadline := time.After(after)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
wait:
	for {
		select {
		case err := <-done:
			t.Fatalf("vigolium exited before it could be interrupted (%v)\n%s", err, p.result())
		case <-deadline:
			break wait
		case <-tick.C:
			if ready() {
				break wait
			}
		}
	}
	signaledAt := time.Now()
	require.NoError(t, p.cmd.Process.Signal(sig))
	for range times - 1 {
		time.Sleep(200 * time.Millisecond)
		_ = p.cmd.Process.Signal(sig) // os.ErrProcessDone once it has exited
	}
	select {
	case err := <-done:
		r := p.result()
		r.code = exitCode(t, err, r)
		t.Logf("exited %s after the first %s", time.Since(signaledAt).Round(time.Millisecond), sig)
		return r
	case <-time.After(grace):
		cancel()
		if err := <-done; err != nil {
			t.Logf("killed: %v", err)
		}
		t.Fatalf("vigolium did not exit within %s of %s (killed)\n%s", grace, sig, p.result())
		return cliRun{}
	}
}

func exitCode(t *testing.T, err error, r cliRun) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			t.Fatalf("vigolium died from signal %s instead of exiting\n%s", ws.Signal(), r)
		}
		return ee.ExitCode()
	}
	t.Fatalf("run vigolium: %v\n%s", err, r)
	return -1
}

// doc decodes stdout as exactly one JSON document that matches the published
// schema of the command that printed it; anything else on stdout breaks the
// machine-output contract.
func (r cliRun) doc(t *testing.T) map[string]any {
	t.Helper()
	doc := r.rawDoc(t)
	if command := str(doc, "command"); command != "" {
		contracttest.Validate(t, command, []byte(r.stdout))
	}
	return doc
}

// rawDoc is doc without the schema check, for a document with a known
// contract defect that the caller checks itself.
func (r cliRun) rawDoc(t *testing.T) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(r.stdout))
	var doc map[string]any
	require.NoErrorf(t, dec.Decode(&doc), "stdout must be one JSON document\n%s", r)
	var extra any
	require.Errorf(t, dec.Decode(&extra), "stdout must hold exactly one JSON document\n%s", r)
	return doc
}

func num(doc map[string]any, key string) float64 {
	v, _ := doc[key].(float64)
	return v
}

func str(doc map[string]any, key string) string {
	v, _ := doc[key].(string)
	return v
}

func items(doc map[string]any) []map[string]any {
	raw, _ := doc["items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
