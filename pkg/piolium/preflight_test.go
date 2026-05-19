package piolium

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// withFakePi installs a shell script named `pi` in a fresh temp dir and
// prepends that dir to $PATH for the test's duration. The script body
// echoes the supplied JSONL lines, then exits with the supplied code.
//
// Skipped on platforms without a POSIX shell — the test is exercising
// our own argv/JSONL plumbing, not pi itself, so a shell-only fake is fine.
func withFakePi(t *testing.T, exitCode int, jsonl ...string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-pi shim requires a POSIX shell")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\ncat <<'PI_FAKE_EOF'\n" +
		strings.Join(jsonl, "\n") + "\nPI_FAKE_EOF\n" +
		"exit " + itoa(exitCode) + "\n"
	path := filepath.Join(dir, "pi")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake pi: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [12]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}

func TestPreflight_HappyPath(t *testing.T) {
	withFakePi(t, 0,
		`{"type":"session","id":"abc","cwd":"/tmp"}`,
		`{"type":"agent_start"}`,
		`{"type":"message_end","message":{"role":"assistant","provider":"openai-codex","model":"gpt-5.5","usage":{"input":4,"output":1,"cost":{"total":0.0001}},"stopReason":"stop"}}`,
		`{"type":"agent_end","messages":[]}`,
	)
	res, err := Preflight(context.Background(), PreflightOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if res.Model != "gpt-5.5" {
		t.Errorf("model = %q, want gpt-5.5", res.Model)
	}
	if res.Provider != "openai-codex" {
		t.Errorf("provider = %q, want openai-codex", res.Provider)
	}
	if res.Duration <= 0 {
		t.Errorf("duration should be positive, got %s", res.Duration)
	}
	if got := res.String(); !strings.Contains(got, "gpt-5.5") || !strings.Contains(got, "openai-codex") {
		t.Errorf("String() = %q, expected provider+model", got)
	}
}

func TestPreflight_SurfacesAuthError(t *testing.T) {
	withFakePi(t, 0,
		`{"type":"session","id":"abc","cwd":"/tmp"}`,
		`{"type":"message_end","message":{"role":"assistant","model":"gpt-5.5","stopReason":"error","errorMessage":"401 Incorrect API key provided"}}`,
		`{"type":"agent_end","messages":[]}`,
	)
	_, err := Preflight(context.Background(), PreflightOptions{Timeout: 5 * time.Second})
	if err == nil {
		t.Fatalf("expected error when message_end carries errorMessage")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should surface the upstream message, got: %v", err)
	}
}

func TestPreflight_NoAgentEnd(t *testing.T) {
	// pi exited cleanly but never emitted agent_end — treat as failure
	// rather than silently passing.
	withFakePi(t, 0,
		`{"type":"session","id":"abc","cwd":"/tmp"}`,
	)
	_, err := Preflight(context.Background(), PreflightOptions{Timeout: 5 * time.Second})
	if err == nil {
		t.Fatalf("expected error when no agent_end event is emitted")
	}
}

func TestPreflight_NonZeroExit(t *testing.T) {
	withFakePi(t, 7) // no JSONL, just a non-zero exit
	_, err := Preflight(context.Background(), PreflightOptions{Timeout: 5 * time.Second})
	if err == nil {
		t.Fatalf("expected error on non-zero pi exit")
	}
}

func TestPreflight_PiMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no pi anywhere
	_, err := Preflight(context.Background(), PreflightOptions{Timeout: time.Second})
	if err == nil {
		t.Fatalf("expected error when pi is not on PATH")
	}
	if !strings.Contains(err.Error(), "pi CLI not found") {
		t.Errorf("expected friendly missing-binary message, got: %v", err)
	}
}

func TestPreflightResult_StringFallback(t *testing.T) {
	cases := []struct {
		r      PreflightResult
		wantIn string
	}{
		{PreflightResult{Provider: "p", Model: "m", Duration: 1200 * time.Millisecond}, "provider=p model=m"},
		{PreflightResult{Model: "m", Duration: time.Second}, "model=m"},
		{PreflightResult{Duration: time.Second}, "ok in"},
	}
	for _, c := range cases {
		if got := c.r.String(); !strings.Contains(got, c.wantIn) {
			t.Errorf("String() = %q, want it to contain %q", got, c.wantIn)
		}
	}
}
