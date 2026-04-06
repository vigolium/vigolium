package opencodesdk

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	opencode "github.com/sst/opencode-sdk-go"
	"github.com/sst/opencode-sdk-go/option"
	"go.uber.org/zap"
)

// Client manages an OpenCode daemon subprocess and communicates via the official SDK.
type Client struct {
	opts    *Options
	daemon  *daemon
	sdk     *opencode.Client
	mu      sync.Mutex
	started bool
	closed  bool
}

// NewClient creates a new OpenCode client. The daemon is not started until Start() is called.
func NewClient(opts *Options) *Client {
	return &Client{opts: opts}
}

// Start spawns the OpenCode daemon and waits for it to become ready.
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return nil
	}
	if c.closed {
		return fmt.Errorf("client is closed")
	}

	d, err := startDaemon(ctx, c.opts)
	if err != nil {
		return err
	}
	c.daemon = d

	// Create SDK client pointing at the daemon's chosen port
	baseURL := fmt.Sprintf("http://localhost:%d", d.port)
	c.sdk = opencode.NewClient(option.WithBaseURL(baseURL))

	// Wait for daemon readiness
	if err := c.waitReady(ctx); err != nil {
		d.close()
		return fmt.Errorf("daemon failed to become ready: %w", err)
	}

	c.started = true
	return nil
}

// CreateSession creates a new OpenCode session.
func (c *Client) CreateSession(ctx context.Context) (string, error) {
	session, err := c.sdk.Session.New(ctx, opencode.SessionNewParams{
		Directory: opencode.F(c.opts.Cwd),
	})
	if err != nil {
		return "", fmt.Errorf("session creation failed: %w", err)
	}
	return session.ID, nil
}

// Prompt sends a text prompt to an existing session and collects the response.
// If streamWriter is non-nil, text deltas are streamed in real time.
// Permissions are auto-approved with "always".
func (c *Client) Prompt(ctx context.Context, sessionID, text string, streamWriter io.Writer) (string, error) {
	// Open SSE event stream before sending the prompt so we don't miss events.
	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()

	stream := c.sdk.Event.ListStreaming(streamCtx, opencode.EventListParams{
		Directory: opencode.F(c.opts.Cwd),
	})

	// Send the prompt (non-blocking from our perspective — response comes via SSE).
	promptParams := opencode.SessionPromptParams{
		Parts: opencode.F([]opencode.SessionPromptParamsPartUnion{
			opencode.TextPartInputParam{
				Text: opencode.F(text),
				Type: opencode.F(opencode.TextPartInputTypeText),
			},
		}),
		Directory: opencode.F(c.opts.Cwd),
	}
	if c.opts.SystemPrompt != "" {
		promptParams.System = opencode.F(c.opts.SystemPrompt)
	}

	if _, err := c.sdk.Session.Prompt(ctx, sessionID, promptParams); err != nil {
		streamCancel()
		return "", fmt.Errorf("prompt send failed: %w", err)
	}

	// Consume SSE events until the session becomes idle or errors.
	//
	// Different daemon versions send text in different ways:
	// - opencode sends "message.part.delta" with incremental text fragments
	// - some versions send "message.part.updated" with accumulated Part.Text
	//
	// We handle both: for "message.part.updated" we track per-part text length
	// and compute the delta. For "message.part.delta" we parse the raw JSON.
	var output strings.Builder
	partTextLen := make(map[string]int) // tracks seen text length per part ID
	for stream.Next() {
		event := stream.Current()

		zap.L().Debug("opencode SSE event received",
			zap.String("type", string(event.Type)),
			zap.String("sessionID", sessionID))

		switch event.Type {
		case opencode.EventListResponseTypeMessagePartUpdated:
			ev, ok := event.AsUnion().(opencode.EventListResponseEventMessagePartUpdated)
			if !ok || ev.Properties.Part.SessionID != sessionID {
				continue
			}
			// First try the Delta field (used by some daemon versions)
			if ev.Properties.Delta != "" {
				output.WriteString(ev.Properties.Delta)
				if streamWriter != nil {
					_, _ = io.WriteString(streamWriter, ev.Properties.Delta)
				}
				continue
			}
			// Fall back to computing delta from Part.Text:
			// Part.Text contains the full accumulated text; we emit only the new portion.
			part := ev.Properties.Part
			if part.Text != "" && part.Type == "text" {
				prev := partTextLen[part.ID]
				if len(part.Text) > prev {
					delta := part.Text[prev:]
					partTextLen[part.ID] = len(part.Text)
					output.WriteString(delta)
					if streamWriter != nil {
						_, _ = io.WriteString(streamWriter, delta)
					}
				}
			}

		case opencode.EventListResponseTypePermissionUpdated:
			ev, ok := event.AsUnion().(opencode.EventListResponseEventPermissionUpdated)
			if !ok {
				continue
			}
			perm := ev.Properties
			if perm.SessionID != sessionID {
				continue
			}
			// Auto-approve all permissions
			go func(sid, pid string) {
				_, err := c.sdk.Session.Permissions.Respond(ctx, sid, pid,
					opencode.SessionPermissionRespondParams{
						Response:  opencode.F(opencode.SessionPermissionRespondParamsResponseAlways),
						Directory: opencode.F(c.opts.Cwd),
					})
				if err != nil {
					zap.L().Debug("failed to auto-approve permission",
						zap.String("sessionID", sid),
						zap.String("permissionID", pid),
						zap.Error(err))
				}
			}(perm.SessionID, perm.ID)

		case opencode.EventListResponseTypeSessionIdle:
			ev, ok := event.AsUnion().(opencode.EventListResponseEventSessionIdle)
			if !ok {
				continue
			}
			if ev.Properties.SessionID == sessionID {
				return output.String(), nil
			}

		case opencode.EventListResponseTypeSessionError:
			ev, ok := event.AsUnion().(opencode.EventListResponseEventSessionError)
			if !ok {
				continue
			}
			if ev.Properties.SessionID == sessionID {
				return output.String(), fmt.Errorf("opencode session error: %s", ev.Properties.Error.Name)
			}

		default:
			// Handle "message.part.delta" — not yet in SDK types but sent by
			// newer daemon versions. Contains streaming text fragments.
			if event.Type == "message.part.delta" {
				delta := extractDelta(event)
				zap.L().Debug("message.part.delta extracted",
					zap.String("delta", delta),
					zap.Int("rawLen", len(event.JSON.RawJSON())))
				if delta != "" {
					output.WriteString(delta)
					if streamWriter != nil {
						_, _ = io.WriteString(streamWriter, delta)
					}
				}
			}
		}
	}

	if err := stream.Err(); err != nil {
		return output.String(), fmt.Errorf("SSE stream error: %w", err)
	}

	if output.Len() == 0 {
		return "", fmt.Errorf("opencode session ended without producing output")
	}

	return output.String(), nil
}

// extractDelta parses raw JSON from an SSE event to get the "properties.delta" field.
// Used for event types not yet defined in the SDK (e.g., "message.part.delta").
func extractDelta(event opencode.EventListResponse) string {
	var raw struct {
		Properties struct {
			Delta string `json:"delta"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(event.JSON.RawJSON()), &raw); err != nil {
		return ""
	}
	return raw.Properties.Delta
}

// Abort cancels a running session.
func (c *Client) Abort(ctx context.Context, sessionID string) error {
	_, err := c.sdk.Session.Abort(ctx, sessionID, opencode.SessionAbortParams{
		Directory: opencode.F(c.opts.Cwd),
	})
	return err
}

// Close shuts down the daemon subprocess.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	if c.daemon != nil {
		c.daemon.close()
	}
	return nil
}

// Alive returns true if the daemon is still running.
func (c *Client) Alive() bool {
	if c.daemon == nil {
		return false
	}
	return c.daemon.alive()
}

// waitReady polls the daemon until it responds or the context expires.
func (c *Client) waitReady(ctx context.Context) error {
	deadline := time.After(30 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timeout waiting for OpenCode daemon on port %d", c.daemon.port)
		case <-c.daemon.done:
			c.daemon.stderrMu.Lock()
			stderrStr := c.daemon.stderr.String()
			c.daemon.stderrMu.Unlock()
			return fmt.Errorf("daemon exited before becoming ready: %s", stderrStr)
		case <-ticker.C:
			// Try a lightweight API call to check readiness
			listCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
			_, err := c.sdk.Session.List(listCtx, opencode.SessionListParams{
				Directory: opencode.F(c.opts.Cwd),
			})
			cancel()
			if err == nil {
				return nil
			}
		}
	}
}

// --- Daemon subprocess management ---

// daemon manages an OpenCode server subprocess.
type daemon struct {
	cmd       *exec.Cmd
	stderrMu  sync.Mutex
	stderr    bytes.Buffer
	done      chan struct{}
	closeOnce sync.Once
	port      int
}

// startDaemon spawns the OpenCode daemon with the given options.
// It tries successive ports starting from opts.EffectivePort() until one is free.
func startDaemon(ctx context.Context, opts *Options) (*daemon, error) {
	executable := opts.Executable
	if executable == "" {
		executable = "opencode"
	}

	cmdPath, err := exec.LookPath(executable)
	if err != nil {
		return nil, fmt.Errorf("opencode executable %q not found in PATH: %w", executable, err)
	}

	// Find a free port
	basePort := opts.EffectivePort()
	port := basePort
	for i := 0; i < 10; i++ {
		if !isPortBusy(port) {
			break
		}
		zap.L().Debug("port busy, trying next",
			zap.Int("port", port),
			zap.Int("nextPort", port+1))
		port++
		if i == 9 {
			return nil, fmt.Errorf("no free port found in range %d-%d", basePort, port)
		}
	}

	args := []string{"serve", "--port", fmt.Sprintf("%d", port), "--print-logs"}

	// Log a readable command line for debugging
	var cmdLine strings.Builder
	cmdLine.WriteString(cmdPath)
	for _, a := range args {
		cmdLine.WriteByte(' ')
		if strings.ContainsAny(a, " \t\n'\"\\") {
			cmdLine.WriteString("'" + strings.ReplaceAll(a, "'", "'\\''") + "'")
		} else {
			cmdLine.WriteString(a)
		}
	}
	zap.L().Debug("starting opencode daemon subprocess",
		zap.String("command", cmdLine.String()),
		zap.Int("port", port),
		zap.String("cwd", opts.Cwd))

	// Use background context for the daemon lifetime — the session pool
	// manages process lifecycle via Kill(). The caller's ctx is only used for
	// bounding startup operations, not the daemon lifetime.
	cmd := exec.CommandContext(context.Background(), cmdPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if opts.Cwd != "" {
		cmd.Dir = opts.Cwd
	}

	// Pass through custom env vars if configured
	if len(opts.Env) > 0 {
		cmd.Env = cmd.Environ()
		for k, v := range opts.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start opencode daemon: %w", err)
	}

	d := &daemon{
		cmd:  cmd,
		done: make(chan struct{}),
		port: port,
	}

	// Drain stderr in background
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			d.stderrMu.Lock()
			d.stderr.WriteString(line)
			d.stderr.WriteByte('\n')
			d.stderrMu.Unlock()
			zap.L().Debug("opencode stderr", zap.String("line", line))
		}
	}()

	// Wait for process exit in background
	go func() {
		_ = cmd.Wait()
		close(d.done)
	}()

	return d, nil
}

// close gracefully shuts down the daemon process group: SIGTERM first, then SIGKILL after timeout.
func (d *daemon) close() {
	d.closeOnce.Do(func() {
		if d.cmd != nil && d.cmd.Process != nil {
			pid := d.cmd.Process.Pid

			// Graceful: send SIGTERM to entire process group first.
			if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
				zap.L().Debug("failed to SIGTERM opencode process group",
					zap.Int("pid", pid), zap.Error(err))
			}

			// Wait up to 5s for graceful exit, then escalate to SIGKILL.
			select {
			case <-d.done:
				return
			case <-time.After(5 * time.Second):
				zap.L().Debug("SIGTERM timeout, sending SIGKILL to opencode process group",
					zap.Int("pid", pid))
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			}
		}

		// Final wait with timeout to avoid hanging on stuck I/O.
		if d.cmd != nil {
			select {
			case <-d.done:
			case <-time.After(3 * time.Second):
				if d.cmd.Process != nil {
					_ = d.cmd.Process.Kill()
				}
			}
		}
	})
}

// alive returns true if the daemon is still running.
func (d *daemon) alive() bool {
	select {
	case <-d.done:
		return false
	default:
		return true
	}
}

// isPortBusy checks if a TCP port is already in use.
func isPortBusy(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 100*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
