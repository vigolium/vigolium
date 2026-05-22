package piolium

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DefaultPreflightTimeout caps the preflight roundtrip. A successful Pi
// turn usually completes in under 5s; the upper bound covers slow cold
// starts and provider region failovers.
const DefaultPreflightTimeout = 30 * time.Second

// preflightPrompt is the cheapest prompt that still exercises auth + a
// real model call. The prompt is intentionally vague so any provider
// produces at least a token or two before stop.
const preflightPrompt = "Reply with one short word."

// PreflightOptions configures Preflight. Provider/Model are passed to pi
// as `--provider <name> --model <id>` so this preflight catches per-run
// overrides; leave empty to use pi's defaultProvider/defaultModel.
type PreflightOptions struct {
	Provider string
	Model    string
	Timeout  time.Duration
}

// PreflightResult summarizes a successful preflight call.
type PreflightResult struct {
	Provider string        // provider Pi reported on the assistant message
	Model    string        // model Pi reported on the assistant message
	Duration time.Duration // wall time of the pi invocation
}

// String renders a one-line summary suitable for a CLI banner.
func (r PreflightResult) String() string {
	switch {
	case r.Model != "" && r.Provider != "":
		return fmt.Sprintf("provider=%s model=%s in %s",
			r.Provider, r.Model, r.Duration.Round(100*time.Millisecond))
	case r.Model != "":
		return fmt.Sprintf("model=%s in %s",
			r.Model, r.Duration.Round(100*time.Millisecond))
	default:
		return fmt.Sprintf("ok in %s", r.Duration.Round(100*time.Millisecond))
	}
}

// Preflight runs `pi --mode json [--provider X] [--model Y] -p "<prompt>"`
// and waits for either an `agent_end` event (success) or an
// `errorMessage` field on an assistant `message_end` (failure).
//
// On success, returns the model+provider Pi reported, plus the wall time.
// On failure, returns an error wrapping the captured `errorMessage` so
// the caller can surface the underlying cause (401, quota, …) without
// having to parse pi's stderr themselves.
//
// Caller-provided ctx cancellation overrides Timeout. When both fire, the
// subprocess is killed and Preflight returns the more specific error.
func Preflight(ctx context.Context, opts PreflightOptions) (*PreflightResult, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultPreflightTimeout
	}

	binary, err := exec.LookPath(Binary)
	if err != nil {
		return nil, fmt.Errorf("pi CLI not found in PATH")
	}

	args := []string{}
	if opts.Provider != "" {
		args = append(args, "--provider", opts.Provider)
	}
	if opts.Model != "" {
		args = append(args, "--model", opts.Model)
	}
	args = append(args, "--mode", "json", "-p", preflightPrompt)

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(runCtx, binary, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("pi stdout pipe: %w", err)
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start pi: %w", err)
	}

	res, errText := scanPreflightStream(stdout)
	waitErr := cmd.Wait()
	res.Duration = time.Since(start)

	// stderr surfaces early-failure modes Pi can't express in the JSONL
	// stream (e.g. provider not configured, --provider unknown). Prefer
	// it when no errorMessage was emitted on stdout.
	stderr := strings.TrimSpace(stderrBuf.String())

	switch {
	case errText != "":
		return nil, fmt.Errorf("pi preflight rejected: %s", oneLine(errText, 200))
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("pi preflight timed out after %s", timeout)
	case waitErr != nil && stderr != "":
		return nil, fmt.Errorf("pi exited %w: %s", waitErr, oneLine(stderr, 200))
	case waitErr != nil:
		return nil, fmt.Errorf("pi exited %w", waitErr)
	case !res.endSeen && stderr != "":
		return nil, fmt.Errorf("pi exited cleanly but emitted no agent_end event: %s", oneLine(stderr, 200))
	case !res.endSeen:
		return nil, fmt.Errorf("pi exited cleanly but emitted no agent_end event")
	}

	return &PreflightResult{
		Provider: res.Provider,
		Model:    res.Model,
		Duration: res.Duration,
	}, nil
}

// preflightScan tracks the per-line decoder state.
type preflightScan struct {
	Provider string
	Model    string
	Duration time.Duration
	endSeen  bool
}

// scanPreflightStream consumes the JSONL output of `pi --mode json` and
// returns whatever provider/model the assistant message reported, plus
// the first errorMessage seen (when non-empty, it is the failure cause).
func scanPreflightStream(r interface{ Read(p []byte) (int, error) }) (preflightScan, string) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1<<20), 16<<20)

	var state preflightScan
	var errMsg string
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var env preflightLine
		if err := json.Unmarshal(line, &env); err != nil {
			continue
		}
		switch env.Type {
		case "message_end":
			if env.Message.ErrorMessage != "" && errMsg == "" {
				errMsg = env.Message.ErrorMessage
			}
			if env.Message.Model != "" {
				state.Model = env.Message.Model
			}
			if env.Message.Provider != "" {
				state.Provider = env.Message.Provider
			}
		case "agent_end":
			state.endSeen = true
		}
	}
	return state, errMsg
}

type preflightLine struct {
	Type    string `json:"type"`
	Message struct {
		Provider     string `json:"provider,omitempty"`
		Model        string `json:"model,omitempty"`
		ErrorMessage string `json:"errorMessage,omitempty"`
	} `json:"message,omitempty"`
}

// oneLine collapses newlines and truncates so a long error fits a banner.
func oneLine(s string, max int) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
